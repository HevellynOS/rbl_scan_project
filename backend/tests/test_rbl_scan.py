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
    assert instrucoes()["versao"] == "1"
    assert "RBLSCAN-COLETA v1" in instrucoes()["script"]


def test_coletor_nao_altera_nada_no_servidor():
    script = instrucoes()["script"]
    for perigoso in ("rndc reload", "systemctl restart", "rm ", "> /etc/",
                     "pdnsutil add-record", "pdnsutil edit-zone"):
        assert perigoso not in script, f"comando que altera estado: {perigoso}"
