"""
Testes do RBL Scan.

    cd backend
    pip install pytest
    pytest -q

Rodam sem rede: usam os exports de configuração em tests/ e relatórios
sintéticos. As partes que dependem de DNS ficam de fora de propósito — teste
que precisa de internet falha por motivo errado e some do hábito de rodar.

Os casos aqui vieram de defeitos reais encontrados em produção. Cada um está
comentado com o que aconteceu, para que uma refatoração futura não os
reintroduza em silêncio.
"""

from __future__ import annotations

import io
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.analyzers.rsc_analyzer import analyze  # noqa: E402
from app.core.security import scan_sensitive  # noqa: E402
from app.database.connection import MemoryRepository  # noqa: E402
from app.parsers.vrp_parser import parece_vrp, parse as parse_vrp  # noqa: E402
from app.services.rbl_service import (  # noqa: E402
    classify_ip,
    host_part,
    ptr_looks_generic,
)

AQUI = os.path.dirname(os.path.abspath(__file__))


def _ler(nome: str) -> str:
    with open(os.path.join(AQUI, nome), encoding="utf-8", errors="replace") as f:
        return f.read()


@pytest.fixture(scope="module")
def ne40() -> str:
    return _ler("exemplo-ne40.txt")


@pytest.fixture(scope="module")
def vrp_sintetico() -> str:
    return _ler("exemplo-vrp.cfg")


# --------------------------------------------------------------------------
# Heurística de rDNS
# --------------------------------------------------------------------------
@pytest.mark.parametrize("ip,ptr,esperado", [
    ("179.108.72.15", "179-108-72-15.dinamico.provedor.net.br", True),
    ("45.232.243.1", "45.232.243.1.forteinternet.net.br", True),
    ("179.108.72.60", "pppoe-4512.provedor.net.br", True),
    ("179.108.72.70", "cgnat-pool7.provedor.net.br", True),
    ("179.108.72.30", "", True),
    # Regressão: "cliente" no domínio registrável não é sinal de faixa
    # dinâmica. A primeira versão marcava mail.cliente.com.br como genérico.
    ("179.108.72.20", "mail.cliente.com.br", False),
    ("179.108.72.21", "smtp.pronetworks.com.br", False),
    ("179.108.72.50", "srv-financeiro.empresa.com.br", False),
])
def test_ptr_generico(ip, ptr, esperado):
    assert ptr_looks_generic(ip, ptr)[0] is esperado


def test_host_part_descarta_dominio_registravel():
    assert host_part("mail.cliente.com.br") == "mail"
    assert host_part("pppoe-1.pop.provedor.net.br") == "pppoe-1.pop"


# --------------------------------------------------------------------------
# Classificação política x comportamento
# --------------------------------------------------------------------------
def _hit(rbl, code, kind):
    return {"ip": "1.2.3.4", "rbl": rbl, "severity": 3,
            "entries": [{"code": code, "meaning": "x", "kind": kind}]}


def test_classificacao():
    assert classify_ip([]) == "clean"
    assert classify_ip([_hit("SPAMHAUS-ZEN", "127.0.0.11", "policy")]) == "policy"
    assert classify_ip([_hit("SPAMHAUS-ZEN", "127.0.0.4", "behavior")]) == "behavior"
    # Um comportamental entre vários de política domina: é ele que relista.
    assert classify_ip([_hit("SPAMHAUS-ZEN", "127.0.0.11", "policy"),
                        _hit("DRONEBL", "127.0.0.6", "behavior")]) == "behavior"


# --------------------------------------------------------------------------
# Parser VRP
# --------------------------------------------------------------------------
def test_detecta_vrp_e_nao_confunde_com_routeros(ne40):
    assert parece_vrp(ne40)
    assert not parece_vrp("/ip firewall raw\nadd chain=prerouting action=drop\n")


def test_hash_indentado_nao_encerra_secao(ne40):
    """Regressão do defeito mais grave do parser.

    O VRP usa '#' tanto como separador de seção (coluna 0) quanto como
    separador interno (indentado). Tratar os dois igual arrancava o
    'access-type' de dentro do bloco 'bas' e o promovia a seção raiz.
    """
    cfg = parse_vrp(ne40)
    assert not any(c.text.startswith("access-type") for c in cfg.root.children)
    intf = [b for b in cfg.sections("interface")
            if b.text.startswith("interface Eth-Trunk1.1002")]
    assert intf, "interface de teste não encontrada"
    dentro = [b.text for b in intf[0].walk()]
    assert any(t.startswith("access-type") for t in dentro)


def test_metadados_do_ne40(ne40):
    cfg = parse_vrp(ne40)
    assert cfg.sysname == "NAS-HUAWEI"
    assert cfg.version.startswith("V800R023")


def test_modelo_nao_captura_sysname():
    """O regex de modelo pegava 'NE8000-BORDA-TESTE' como se fosse o modelo."""
    cfg = parse_vrp("sysname NE8000-BORDA-TESTE\nbgp 1\n interface 10GE0/0/1\n")
    assert cfg.model == "NE8000"


# --------------------------------------------------------------------------
# Analisador VRP contra configuração real
# --------------------------------------------------------------------------
@pytest.fixture(scope="module")
def achados_ne40(ne40):
    d = analyze([("ne40.txt", ne40)])["devices"][0]
    return d, {f["id"]: f for f in d["findings"]}


def test_ne40_identificado_como_huawei(achados_ne40):
    d, _ = achados_ne40
    assert d["vendor"] == "Huawei"
    assert d["identity"] == "NAS-HUAWEI"
    assert "concentrador" in d["role"]


def test_ne40_acl_snmp_permissiva(achados_ne40):
    """A ACL restringe nas duas primeiras regras e libera na terceira."""
    _, ids = achados_ne40
    assert "snmp-acl-permissiva" in ids


def test_ne40_ftp_e_vty(achados_ne40):
    _, ids = achados_ne40
    assert "ftp-habilitado" in ids
    assert "vty-sem-acl" in ids


def test_ne40_sem_falso_positivo_de_telnet(achados_ne40):
    """O equipamento tem 'undo telnet server enable': não pode acusar."""
    _, ids = achados_ne40
    assert "telnet-aberto" not in ids


def test_ne40_urpf_reconhecido(achados_ne40):
    _, ids = achados_ne40
    assert "urpf-ok" in ids
    assert "urpf-ausente" not in ids


def test_ne40_policy_opaca_declarada(achados_ne40):
    """traffic-policy aplicada sem definição no export precisa ser declarada,
    não presumida: o bloqueio de porta 25 pode estar dentro dela."""
    _, ids = achados_ne40
    assert "policy-nao-visivel" in ids


def test_vrp_comandos_nao_usam_hash_como_comentario(vrp_sintetico, ne40):
    """No VRP '#' é separador de seção. Comando comentado com '#' colado no
    CLI gera erro em cada linha."""
    for texto in (vrp_sintetico, ne40):
        d = analyze([("x.cfg", texto)])["devices"][0]
        for f in d["findings"]:
            for c in f["commands"]:
                assert not c.strip().startswith("#"), f"{f['id']}: {c}"


def test_acl_nao_aplicada_e_ordem_de_regra(vrp_sintetico):
    """Dois casos que só existem em VRP e não têm equivalente no RouterOS."""
    sem_filtro = vrp_sintetico.replace(" traffic-filter inbound acl 3000\n", "")
    ids = {f["id"] for f in analyze([("a.cfg", sem_filtro)])["devices"][0]["findings"]}
    assert "acl-smtp-inerte" in ids

    permit_antes = vrp_sintetico.replace(
        " rule 5 deny tcp destination-port eq smtp",
        " rule 1 permit ip\n rule 5 deny tcp destination-port eq smtp")
    ids = {f["id"] for f in analyze([("b.cfg", permit_antes)])["devices"][0]["findings"]}
    assert "acl-smtp-inerte" in ids


# --------------------------------------------------------------------------
# Despacho por fabricante
# --------------------------------------------------------------------------
def test_lote_misto(ne40, vrp_sintetico):
    rsc = ("/ip firewall raw\n"
           "add chain=prerouting action=drop dst-port=25 protocol=tcp\n"
           "/system identity\nset name=BORDA-01\n")
    r = analyze([("a.rsc", rsc), ("b.cfg", vrp_sintetico), ("c.txt", ne40)])
    vendors = [d["vendor"] for d in r["devices"]]
    assert vendors == ["MikroTik", "Huawei", "Huawei"]
    # Com fabricantes diferentes o script precisa avisar, senão alguém aplica
    # sintaxe de um equipamento no outro.
    assert "FABRICANTES" in r["rsc"]


# --------------------------------------------------------------------------
# Política de dado sensível
# --------------------------------------------------------------------------
@pytest.mark.parametrize("texto", [
    "o assinante 100.64.32.1 está emitindo",
    "no equipamento CCR2116 da borda",
    "conforme o NE8000 do POP",
    "regra netmap da instância",
    "snmp-agent community read public",
    "rodando RouterOS 7.14.2",
])
def test_detecta_conteudo_que_nao_pode_sair(texto):
    assert scan_sensitive(texto), f"não detectou: {texto}"


@pytest.mark.parametrize("texto", [
    "o bloco 45.232.243.0/24 tem 199 endereços sem PTR",
    "a zona 243.232.45.in-addr.arpa está delegada",
    "45.232.243.1.forteinternet.net.br não resolve de volta",
])
def test_nao_marca_conteudo_publico(texto):
    assert not scan_sensitive(texto), f"falso positivo: {texto}"


# --------------------------------------------------------------------------
# Repositório
# --------------------------------------------------------------------------
def _relatorio(net="45.232.243.0/24", behavior=14):
    return {"network": net, "total": 256, "listed": 256, "elapsed": 51.2,
            "counts": {"behavior": behavior, "policy": 242, "clean": 0},
            "rdns": {"no_ptr": 199, "generic": 57, "with_ptr": 57,
                     "fcrdns_broken": 57, "audited": 256, "clean": 0},
            "rows": [], "plan": [], "lists": [], "delegation": []}


def test_repositorio_guarda_e_historia():
    repo = MemoryRepository(limite=2)
    repo.save_scan(_relatorio(behavior=14))
    repo.save_scan(_relatorio(behavior=3))
    assert repo.get_scan("45.232.243.0/24")["counts"]["behavior"] == 3
    hist = repo.scan_history("45.232.243.0/24")
    assert [h["behavior"] for h in hist] == [14, 3]


def test_repositorio_respeita_o_teto():
    """Sem teto, uma sessão longa acumula relatórios até o fim do processo."""
    repo = MemoryRepository(limite=2)
    for i in range(4):
        repo.save_scan(_relatorio(net=f"10.0.{i}.0/24"))
    assert len(repo.list_scans()) == 2
    assert repo.get_scan("10.0.0.0/24") is None
    assert repo.get_scan("10.0.3.0/24") is not None


# --------------------------------------------------------------------------
# Validação de configuração de servidor DNS
# --------------------------------------------------------------------------
from app.analyzers.dns_analyzer import analyze_dns  # noqa: E402
from app.parsers.zone_parser import (  # noqa: E402
    parse_zone,
    ptr_owner_to_ip,
    zone_to_cidr,
)

ZONA_REVERSA = """
$TTL 3600
@   IN  SOA ns1.provedor.net.br. hostmaster.provedor.net.br. (
        2026081901 3600 900 1209600 3600 )
@   IN  NS  ns1.provedor.net.br.
0   IN  PTR 92-191-181-0.provedor.net.br.
1   IN  PTR gw-pop01.provedor.net.br.
2   IN  PTR mail.provedor.net.br.
$GENERATE 64-67 $ IN PTR 92-191-181-$.provedor.net.br.
"""

ZONA_DIRETA = """
$TTL 3600
$ORIGIN provedor.net.br.
@        IN SOA ns1 hostmaster ( 1 3600 900 1209600 3600 )
@        IN NS  ns1
ns1      IN A   181.191.92.10
gw-pop01 IN A   181.191.92.1
mail     IN A   181.191.92.99
"""


def test_zone_to_cidr_e_ptr_owner():
    assert str(zone_to_cidr("92.191.181.in-addr.arpa")) == "181.191.92.0/24"
    assert ptr_owner_to_ip("15.92.191.181.in-addr.arpa") == "181.191.92.15"
    assert zone_to_cidr("provedor.net.br") is None


def test_generate_expande_e_herda_nome():
    z = parse_zone(ZONA_REVERSA, "db.92.191.181", "92.191.181.in-addr.arpa")
    gerados = [r for r in z.records if r.gerado]
    assert len(gerados) == 4
    assert gerados[0].name == "64.92.191.181.in-addr.arpa"
    assert not z.erros


def test_ptr_sem_registro_a_e_o_achado_critico():
    """O defeito real: o PTR publica um nome que ninguém criou na zona direta.
    Consultar só o reverso não revela isso."""
    r = analyze_dns([("db.92.191.181", ZONA_REVERSA),
                     ("db.provedor.net.br", ZONA_DIRETA)])
    ids = {f["id"]: f for f in r["findings"]}
    assert "ptr-sem-a" in ids
    # 0, 64, 65, 66, 67 apontam para nomes inexistentes
    assert ids["ptr-sem-a"]["count"] == 5
    assert r["resumo"]["ptr_ok"] == 1          # só gw-pop01 fecha os dois lados


def test_a_apontando_para_outro_endereco():
    r = analyze_dns([("db.92.191.181", ZONA_REVERSA),
                     ("db.provedor.net.br", ZONA_DIRETA)])
    ids = {f["id"]: f for f in r["findings"]}
    assert "a-divergente" in ids               # mail: PTR em .2, A em .99


def test_detecta_octetos_em_ordem_trocada():
    """O caso real usava 181.191.92.0 -> 92-191-181-0: comparar a sequência
    exata não pegaria."""
    r = analyze_dns([("db.92.191.181", ZONA_REVERSA),
                     ("db.provedor.net.br", ZONA_DIRETA)])
    ids = {f["id"]: f for f in r["findings"]}
    assert "nome-generico" in ids
    nomes = {s["nome"] for s in ids["nome-generico"]["samples"]}
    assert "92-191-181-0.provedor.net.br" in nomes
    assert "gw-pop01.provedor.net.br" not in nomes


def test_sem_zona_direta_nao_finge_que_verificou():
    """Só o reverso: a ferramenta precisa dizer que não pôde conferir, em vez
    de acusar tudo como quebrado."""
    r = analyze_dns([("db.92.191.181", ZONA_REVERSA)])
    ids = {f["id"] for f in r["findings"]}
    assert "zona-direta-ausente" in ids
    assert "ptr-sem-a" not in ids
    assert r["resumo"]["ptr_nao_verificavel"] == 7


# --------------------------------------------------------------------------
# Arquivo de coleta e remediação
# --------------------------------------------------------------------------
from app.parsers.zone_parser import parece_coleta, parse_coleta  # noqa: E402
from app.services.dns_collect import instrucoes  # noqa: E402

COLETA = f"""##### RBLSCAN-COLETA v1
##### HOST: debian-reverse
##### DATA: 2026-08-21 14:02:11 UTC
##### SERVIDOR: bind

===== ARQUIVO: /etc/bind/named.conf.local =====
zone "92.191.181.in-addr.arpa" {{ type master; file "/etc/bind/db.92.191.181"; }};
zone "provedor.net.br" {{ type master; file "/etc/bind/db.provedor.net.br"; }};
===== FIM =====

===== ZONA: 92.191.181.in-addr.arpa TIPO: master ARQUIVO: /etc/bind/db.92.191.181 ====={ZONA_REVERSA}
===== FIM =====

===== ZONA: provedor.net.br TIPO: master ARQUIVO: /etc/bind/db.provedor.net.br ====={ZONA_DIRETA}
===== FIM =====

##### FIM DA COLETA
"""


def test_parse_coleta_separa_as_partes():
    assert parece_coleta(COLETA)
    c = parse_coleta(COLETA)
    assert c.host == "debian-reverse"
    assert c.servidor == "bind"
    assert len(c.partes) == 3
    caminhos = [p[3] for p in c.partes]
    assert "/etc/bind/db.92.191.181" in caminhos


def test_coleta_produz_a_mesma_analise_que_arquivos_avulsos():
    a = analyze_dns([("coleta.txt", COLETA)])
    b = analyze_dns([("db.92.191.181", ZONA_REVERSA),
                     ("db.provedor.net.br", ZONA_DIRETA)])
    assert a["resumo"]["ptr_sem_a"] == b["resumo"]["ptr_sem_a"]
    assert a["coleta"]["servidor"] == "bind"


def test_remediacao_gera_generate_com_octeto_certo():
    """Regressão: o padrão saía como '92-191-1$-81' porque a substituição
    pegava o '81' de dentro de '181'."""
    r = analyze_dns([("coleta.txt", COLETA)])
    blocos = {b["id"]: b for b in r["remediacao"]["blocos"]}
    alvo = next(b for k, b in blocos.items() if k.startswith("a-faltando"))
    assert "$GENERATE 64-67 92-191-181-$ IN A 181.191.92.$" in alvo["conteudo"]
    assert "92-191-1$" not in alvo["conteudo"]


def test_remediacao_usa_o_caminho_real_do_arquivo():
    """O rótulo de exibição não pode vazar para os comandos do servidor."""
    r = analyze_dns([("coleta.txt", COLETA)])
    aplicar = next(b for b in r["remediacao"]["blocos"] if b["id"] == "aplicar")
    assert "/etc/bind/db.92.191.181" in aplicar["conteudo"]
    assert "(db." not in aplicar["conteudo"]
    assert "named-checkzone" in aplicar["conteudo"]


def test_coletor_e_leitor_na_mesma_versao():
    """Se o formato mudar sem o leitor acompanhar, a análise sairia errada em
    silêncio."""
    i = instrucoes()
    assert i["versao"] == "1"
    assert "RBLSCAN-COLETA v1" in i["script_legivel"]


def test_comando_de_coleta_cabe_em_uma_linha():
    """Regressão de campo: o heredoc quebrou no MobaXterm porque o cliente
    acrescentou um caractere no fim do terminador, e o shell ficou preso
    esperando. Base64 numa linha só elimina a classe de problema."""
    import base64
    import re

    cmd = instrucoes()["script"]
    assert "\n" not in cmd
    for ch in ("~", "`", '"', "'"):
        assert ch not in cmd, f"caractere que o terminal costuma alterar: {ch}"
    b64 = re.search(r"echo (\S+) \|", cmd).group(1)
    corpo = base64.b64decode(b64).decode("utf-8")
    assert "RBLSCAN-COLETA v1" in corpo
    assert corpo.rstrip().endswith('envie o arquivo na aba DNS do RBL Scan."')


def test_coletor_nao_altera_nada_no_servidor():
    script = instrucoes()["script_legivel"]
    for perigoso in ("rndc reload", "systemctl restart", "rm ", "> /etc/",
                     "pdnsutil add-record", "pdnsutil edit-zone"):
        assert perigoso not in script, f"comando que altera estado: {perigoso}"


# --------------------------------------------------------------------------
# Relatórios: remoção e configuração
# --------------------------------------------------------------------------
from app.services.removal_service import (  # noqa: E402
    CANAIS,
    build_removal_markdown,
    build_removal_plan,
    sugestoes_remediacao,
)

REPORT_LISTADO = {
    "network": "181.191.92.0/22",
    "rows": [
        {"ip": "181.191.92.18", "lists": ["SPAMHAUS-ZEN", "DRONEBL"],
         "reasons": ["XBL"]},
        {"ip": "181.191.92.27", "lists": ["SPAMHAUS-ZEN"], "reasons": ["PBL"]},
        {"ip": "181.191.92.70", "lists": ["UCEPROTECT-L1"], "reasons": ["L1"]},
    ],
    "counts": {"behavior": 224, "policy": 800, "clean": 0},
    "rdns": {"no_ptr": 1, "generic": 0, "fcrdns_broken": 1023,
             "with_ptr": 1023, "audited": 1024, "clean": 0},
}


def test_remocao_agrupa_por_lista():
    p = build_removal_plan(REPORT_LISTADO, provedor="X", asn="1", contato="a",
                           telefone="b")
    por = {g["lista"]: g for g in p["grupos"]}
    assert por["SPAMHAUS-ZEN"]["total"] == 2
    assert por["DRONEBL"]["total"] == 1
    assert p["total_listados"] == 3
    assert not p["faltando"]


def test_lista_que_expira_sozinha_nao_pede_remocao():
    """Insistir em lista auto-expirável atrasa em vez de acelerar."""
    p = build_removal_plan(REPORT_LISTADO)
    uce = next(g for g in p["grupos"] if g["lista"] == "UCEPROTECT-L1")
    assert uce["canal"] == "automatico"
    md = build_removal_markdown(p)
    assert "Texto do pedido" in md          # existe para as de formulário
    assert md.count("Texto do pedido") == len(
        [g for g in p["grupos"] if g["canal"] != "automatico"])


def test_nenhum_canal_inventa_email():
    """Quase nenhuma RBL aceita pedido por e-mail. Inventar endereço faria a
    equipe mandar pedido para o vazio."""
    for nome, meta in CANAIS.items():
        assert meta["canal"] in ("formulario", "automatico", "ticket"), nome
        assert "@" not in meta.get("nome_publico", ""), nome


def test_campos_vazios_viram_marcador_visivel():
    p = build_removal_plan(REPORT_LISTADO)
    assert set(p["faltando"]) == {"provedor", "ASN", "responsável técnico",
                                  "telefone"}
    texto = p["grupos"][0]["texto"]
    assert "<PROVEDOR>" in texto and "<ASN>" in texto


def test_sem_remediacao_marcada_o_pedido_avisa():
    p = build_removal_plan(REPORT_LISTADO, remediacoes=[])
    # Sem escolha explícita, entram as sugeridas; a flag só liga quando não
    # sobra nenhuma.
    assert p["remediacoes_aplicadas"]
    vazio = build_removal_plan(
        {"network": "1.2.3.0/24", "rows": [], "counts": {}, "rdns": {}},
        remediacoes=["inexistente"])
    assert vazio["sem_remediacao"]
    assert "<DESCREVA O QUE FOI CORRIGIDO" in (
        vazio["grupos"][0]["texto"] if vazio["grupos"] else
        "<DESCREVA O QUE FOI CORRIGIDO")


def test_sugestoes_derivam_do_que_a_varredura_achou():
    ids = {i["id"] for i in sugestoes_remediacao(REPORT_LISTADO)}
    assert {"contencao", "ptr", "fcrdns"} <= ids
    limpo = sugestoes_remediacao(
        {"counts": {"behavior": 0}, "rdns": {"no_ptr": 0, "fcrdns_broken": 0}})
    assert {i["id"] for i in limpo} == {"monitoramento"}


def test_relatorio_de_configuracao_nao_traz_comandos():
    """Comando transcrito de PDF gera erro de digitação, e em equipamento de
    borda isso derruba serviço. Eles vão no arquivo de correção."""
    from pypdf import PdfReader

    from app.services.report_service import build_config_pdf

    an = analyze([("ne40.txt", _ler("exemplo-ne40.txt"))])
    pdf = build_config_pdf(an, cliente="Teste", preparado_por="QA")
    texto = "".join(p.extract_text() for p in PdfReader(io.BytesIO(pdf)).pages)
    for comando in ("undo telnet server enable", "rule 5 deny",
                    "snmp-agent community read", "undo rule"):
        assert comando not in texto, f"comando vazou para o PDF: {comando}"


# --------------------------------------------------------------------------
# Cadeia de delegação
# --------------------------------------------------------------------------
from app.services.delegation_service import (  # noqa: E402
    _achados,
    _dominio_registravel,
    galho_comum,
)


def test_galho_comum_encontra_o_menor_pedaco_a_delegar():
    """Quando o domínio fica com terceiros, delegar só o galho resolve o bloco
    inteiro com dois registros NS, sem mexer em site nem em e-mail."""
    nomes = ["0.92.pop.prov.net.br", "5.92.pop.prov.net.br",
             "7.93.pop.prov.net.br", "200.95.pop.prov.net.br"]
    assert galho_comum(nomes, "prov.net.br") == "pop.prov.net.br"
    # Um /24 só: o galho é mais específico.
    assert galho_comum(["0.92.pop.x.net.br", "9.92.pop.x.net.br"],
                       "x.net.br") == "92.pop.x.net.br"
    # Padrão sem galho comum (nomes na raiz do domínio) não inventa um.
    assert galho_comum(["45-80-48-0.rem.net.br", "45-80-49-5.rem.net.br"],
                       "rem.net.br") == ""


def test_dominio_registravel_com_sufixo_br():
    assert _dominio_registravel("0.92.pop.prov.net.br") == "prov.net.br"
    assert _dominio_registravel("mail.empresa.com") == "empresa.com"


def test_dominio_em_terceiros_e_critico():
    """O caso real: registros A corretos num servidor para o qual o domínio
    não está delegado são registros invisíveis."""
    dominios = [{
        "dominio": "prov.net.br", "erro": "", "ns": ["ns1.hostgator.com.br"],
        "servidores": [], "hospedado_por_nos": False,
        "galho_sugerido": "pop.prov.net.br",
        "amostras": [], "nomes_no_ptr": 1023,
    }]
    achados = _achados(dominios, [])
    assert achados[0]["severidade"] == 3
    assert "terceiros" in achados[0]["titulo"]
    texto = "\n".join(achados[0]["correcao"])
    assert "pop.prov.net.br.   IN NS" in texto


def test_dominio_nosso_e_respondendo_nao_gera_achado():
    dominios = [{
        "dominio": "prov.net.br", "erro": "", "ns": ["ns1.prov.net.br"],
        "servidores": [], "hospedado_por_nos": True, "galho_sugerido": "",
        "amostras": [{"nome": "0.92.pop.prov.net.br", "ip_esperado": "1.2.3.0",
                      "por_servidor": [{"servidor": "ns1.prov.net.br",
                                        "respondeu": True,
                                        "valores": ["1.2.3.0"],
                                        "confere": True, "detalhe": ""}]}],
        "nomes_no_ptr": 1,
    }]
    assert _achados(dominios, []) == []


def test_reversa_sem_delegacao_e_critico():
    achados = _achados([], [{"zona": "92.191.181.in-addr.arpa",
                             "erro": "o domínio não existe na hierarquia do DNS",
                             "ns": [], "hospedado_por_nos": False}])
    assert achados[0]["severidade"] == 3
    assert "registro.br" in "\n".join(achados[0]["correcao"])
