"""
app/analyzers/dns_analyzer.py — Validação da configuração do servidor de DNS.

A varredura enxerga o resultado das consultas; aqui a auditoria é sobre o
arquivo, o que permite apontar a linha exata onde o erro foi escrito e pegar o
problema antes de ele chegar na rede.

O defeito que motivou este módulo:

    181.191.92.0  ->  92-191-181-0.mundialnetfibras.com.br     (PTR existe)
    92-191-181-0.mundialnetfibras.com.br  ->  NXDOMAIN          (o A não existe)

O PTR publica um nome que ninguém criou na zona direta. Para o servidor de
destino a verificação de duas vias falha, e o resultado prático é o mesmo de
não haver reverso nenhum. Consultar só o reverso não revela isso: é preciso
consultar os dois lados, que é o que esta validação faz sobre o arquivo.
"""

from __future__ import annotations

import ipaddress
import re
from collections import defaultdict
from dataclasses import dataclass, field

from app.parsers.zone_parser import (
    NamedConf,
    Zone,
    parece_coleta,
    parece_named_conf,
    parece_zona,
    parse_coleta,
    parse_named_conf,
    parse_zone,
    ptr_owner_to_ip,
)

SEV_LABEL = {3: "crítico", 2: "importante", 1: "recomendado", 0: "informativo"}

# Palavras que marcam espaço de usuário final. Em faixa de assinante isso é
# correto e protege o bloco; em endereço de serviço, não.
GENERICO_RE = re.compile(
    r"dinamic|dynamic|dyn\d|dhcp|pppoe|ppp-?\d|dsl|adsl|gpon|cable|cabo|"
    r"wireless|wifi|client|cliente|customer|user|assinante|pool|cgnat|nat\d",
    re.I)


@dataclass
class DnsFinding:
    id: str
    severity: int
    title: str
    detail: str = ""
    why: str = ""
    fix: list[str] = field(default_factory=list)
    samples: list[dict] = field(default_factory=list)
    count: int = 0

    def to_dict(self) -> dict:
        return {"id": self.id, "severity": self.severity,
                "severity_label": SEV_LABEL[self.severity],
                "title": self.title, "detail": self.detail, "why": self.why,
                "fix": self.fix, "samples": self.samples[:25],
                "count": self.count}


def _octetos_no_nome(ip: str, nome: str) -> bool:
    """Detecta o nome que repete o endereço, em qualquer ordem de octetos.

    O caso real usava ordem trocada (181.191.92.0 virou 92-191-181-0), então
    comparar a sequência exata não bastaria: a comparação é por conjunto.
    """
    host = nome.split(".")[0].lower()
    nums = re.findall(r"\d+", host)
    if len(nums) < 3:
        return False
    return set(nums) >= set(ip.split(".")[:3])


def _generico(ip: str, nome: str) -> tuple[bool, str]:
    host = nome.split(".")[0].lower()
    if _octetos_no_nome(ip, nome):
        return True, "o nome repete os números do endereço"
    if GENERICO_RE.search(host):
        return True, "o nome tem palavra de faixa dinâmica"
    return False, ""


# --------------------------------------------------------------------------
def analyze_dns(files: list[tuple[str, str]]) -> dict:
    zonas: list[Zone] = []
    confs: list[NamedConf] = []
    ignorados: list[str] = []
    coleta_info: dict = {}
    avisos: list[str] = []

    # O arquivo de coleta traz tudo num só texto. Expandir aqui faz o resto da
    # análise não precisar saber de onde os arquivos vieram.
    expandidos: list[tuple[str, str, str, str]] = []
    for nome, texto in files:
        if parece_coleta(texto):
            c = parse_coleta(texto, nome)
            coleta_info = {"host": c.host, "data": c.data,
                           "servidor": c.servidor, "versao": c.versao,
                           "partes": len(c.partes)}
            avisos += c.avisos
            if c.versao not in ("1", "?"):
                avisos.append(
                    f"O arquivo foi gerado por um coletor versão {c.versao} e "
                    f"este sistema lê a versão 1. Copie o comando de coleta "
                    f"atualizado da tela e refaça.")
            expandidos += c.partes
        else:
            expandidos.append((nome, texto, "", nome))

    for rotulo, texto, origin_conhecido, caminho in expandidos:
        nome = rotulo
        if parece_named_conf(texto):
            confs.append(parse_named_conf(texto, nome))
        elif parece_zona(texto) or origin_conhecido:
            z = parse_zone(texto, caminho,
                           origin_conhecido or _origin_do_nome(nome))
            z.rotulo = rotulo
            zonas.append(z)
        else:
            ignorados.append(nome)

    # named.conf ajuda a nomear zona cujo arquivo não traz $ORIGIN.
    por_arquivo = {}
    for c in confs:
        for z in c.zonas:
            if z["file"]:
                por_arquivo[z["file"].split("/")[-1]] = z["name"]
    for z in zonas:
        if not z.origin:
            z.origin = por_arquivo.get(z.filename.split("/")[-1], "")

    # Índices
    ptrs: dict[str, list] = {}                 # ip -> [Record]
    a_por_nome: dict[str, list[str]] = defaultdict(list)
    cnames: dict[str, str] = {}
    for z in zonas:
        for r in z.records:
            if r.rtype == "PTR":
                ip = ptr_owner_to_ip(r.name)
                if ip:
                    ptrs.setdefault(ip, []).append((z, r))
            elif r.rtype == "A":
                a_por_nome[r.rdata.strip().rstrip(".").lower()].append(
                    r.name.rstrip("."))
                a_por_nome[r.name.rstrip(".").lower()].append(r.rdata.strip())
            elif r.rtype == "CNAME":
                cnames[r.name.rstrip(".").lower()] = \
                    r.rdata.strip().rstrip(".").lower()

    # a_por_nome ficou com as duas direções; separo o que interessa
    nome_para_ip: dict[str, list[str]] = defaultdict(list)
    for z in zonas:
        for r in z.by_type("A"):
            nome_para_ip[r.name.rstrip(".").lower()].append(r.rdata.strip())

    zonas_diretas = {z.origin for z in zonas if z.origin and not z.is_reverse}
    achados: list[DnsFinding] = []

    # --- 1. PTR sem o registro A correspondente ---
    sem_a, apontando_errado, fora_do_upload = [], [], []
    for ip, itens in ptrs.items():
        for z, r in itens:
            alvo = r.rdata.strip().rstrip(".").lower()
            if not alvo:
                continue
            dominio = _dominio_de(alvo)
            coberto = any(alvo == d or alvo.endswith("." + d)
                          for d in zonas_diretas)
            ips = nome_para_ip.get(alvo, [])
            if not ips and alvo in cnames:
                ips = nome_para_ip.get(cnames[alvo], [])
            item = {"ip": ip, "nome": alvo, "arquivo": z.filename,
                    "linha": r.line_no, "gerado": r.gerado,
                    "encontrado": ips[:3]}
            if not coberto:
                item["dominio"] = dominio
                fora_do_upload.append(item)
            elif not ips:
                sem_a.append(item)
            elif ip not in ips:
                apontando_errado.append(item)

    if sem_a:
        achados.append(DnsFinding(
            id="ptr-sem-a", severity=3, count=len(sem_a),
            title=f"{len(sem_a)} PTR apontam para nome que não existe na zona direta",
            detail="A zona direta correspondente está no material enviado, e o "
                   "nome publicado no PTR não aparece nela.",
            why="Servidores de destino consultam os dois sentidos: pegam o nome "
                "pelo PTR e conferem se aquele nome resolve de volta para o "
                "mesmo endereço. Com o registro A ausente, a verificação falha "
                "e o efeito prático é o mesmo de não haver reverso nenhum. "
                "Consultar apenas o reverso não revela o problema, e é por isso "
                "que a configuração parece correta em teste superficial.",
            fix=[
                "; Para cada nome publicado no PTR, criar o A na zona direta.",
                "; Exemplo, com os dados encontrados:",
                *[f";   {i['nome']}.  IN A  {i['ip']}" for i in sem_a[:3]],
                ";",
                "; Quando o reverso usa $GENERATE, a zona direta precisa de um",
                "; $GENERATE equivalente, senão a correspondência falha em toda",
                "; a faixa de uma vez.",
            ],
            samples=sem_a))

    if apontando_errado:
        achados.append(DnsFinding(
            id="a-divergente", severity=3, count=len(apontando_errado),
            title=f"{len(apontando_errado)} nomes resolvem para endereço diferente",
            detail="O registro A existe, mas aponta para outro endereço.",
            why="A verificação de duas vias exige que o nome volte para o MESMO "
                "endereço. Apontar para outro é tratado como reverso forjado, "
                "que costuma pesar mais contra a reputação do que a ausência.",
            fix=["; Corrigir o A para o endereço correspondente, ou o PTR para",
                 "; o nome correto. Os dois lados precisam fechar."],
            samples=apontando_errado))

    if fora_do_upload:
        dominios = sorted({i.get("dominio", "") for i in fora_do_upload if i.get("dominio")})
        achados.append(DnsFinding(
            id="zona-direta-ausente", severity=1, count=len(fora_do_upload),
            title=f"{len(fora_do_upload)} PTR apontam para domínio não enviado",
            detail="Domínios: " + ", ".join(dominios[:6]),
            why="A zona direta desses nomes não veio no material, então não há "
                "como verificar a correspondência de ida e volta por aqui. Se "
                "esse domínio é gerenciado por vocês, envie o arquivo dele "
                "junto. Se é gerenciado por terceiro, confirme com ele que os "
                "registros A existem.",
            fix=["; Envie também o arquivo de zona de:",
                 *[f";   {d}" for d in dominios[:6]]],
            samples=fora_do_upload))

    # --- 2. Nomenclatura ---
    genericos = []
    for ip, itens in ptrs.items():
        for z, r in itens:
            alvo = r.rdata.strip().rstrip(".")
            g, motivo = _generico(ip, alvo)
            if g:
                genericos.append({"ip": ip, "nome": alvo, "motivo": motivo,
                                  "arquivo": z.filename, "linha": r.line_no,
                                  "gerado": r.gerado})
    if genericos:
        achados.append(DnsFinding(
            id="nome-generico", severity=2, count=len(genericos),
            title=f"{len(genericos)} PTR com nome que repete o endereço",
            detail="Padrão característico de faixa residencial dinâmica.",
            why="Sistemas de reputação classificam como espaço de usuário final "
                "todo endereço cujo nome reverso repete os próprios números, "
                "mesmo havendo registro. Em faixa de assinante isso está "
                "CORRETO e protege o bloco: é o que impede um equipamento "
                "comprometido de entregar mensagem direta. Em endereço de "
                "infraestrutura ou de cliente com serviço publicado, precisa "
                "ser trocado por nome que descreva a função.",
            fix=[
                "; Endereço de serviço: nome pela função, sem os números.",
                ";   1   IN PTR gw-pop01.<dominio>.",
                ";   99  IN PTR mail.<dominio>.",
                ";",
                "; Faixa de assinante: pode manter nome padronizado, mas o A",
                "; correspondente continua obrigatório.",
                ";   $GENERATE 64-95 $ IN PTR cliente-$.pop01.<dominio>.",
                "; e na zona direta:",
                ";   $GENERATE 64-95 cliente-$.pop01 IN A <rede>.$",
            ],
            samples=genericos))

    # --- 3. Cobertura da zona reversa ---
    for z in zonas:
        if not z.is_reverse or not z.cidr:
            continue
        rede = z.cidr
        if rede.num_addresses > 4096:
            continue
        cobertos = {ptr_owner_to_ip(r.name) for r in z.by_type("PTR")}
        faltando = [str(ip) for ip in rede if str(ip) not in cobertos]
        if faltando:
            achados.append(DnsFinding(
                id=f"cobertura-{z.origin}", severity=2, count=len(faltando),
                title=f"{len(faltando)} de {rede.num_addresses} endereços sem "
                      f"PTR em {z.origin}",
                detail=f"Arquivo {z.filename}",
                why="Endereço sem nome reverso tem a mesma assinatura de "
                    "máquina residencial comprometida. O destinatário não "
                    "consegue diferenciar e trata os dois igual.",
                fix=[f"; Faixa descoberta em {rede}. Para o pool de assinante:",
                     f";   $GENERATE 0-255 $ IN PTR cliente-$.<pop>.<dominio>.",
                     "; e o $GENERATE equivalente na zona direta."],
                samples=[{"ip": ip} for ip in faltando[:25]]))

    # --- 4. Sanidade da zona ---
    for z in zonas:
        if z.erros:
            achados.append(DnsFinding(
                id=f"sintaxe-{z.filename}", severity=2, count=len(z.erros),
                title=f"{len(z.erros)} linha(s) não compreendidas em {z.filename}",
                detail="Podem ser diretivas fora do escopo desta leitura ou "
                       "erro de digitação que o servidor também recusaria.",
                why="Linha inválida em arquivo de zona faz o BIND recusar a "
                    "zona inteira no reload, e a zona anterior continua no ar "
                    "sem aviso. Confirme com: named-checkzone <zona> <arquivo>",
                fix=["; named-checkzone " + (z.origin or "<zona>") + " " + z.filename],
                samples=[{"linha": n, "erro": m} for n, m in z.erros[:25]]))

        if z.origin and not z.by_type("NS"):
            achados.append(DnsFinding(
                id=f"sem-ns-{z.origin}", severity=2, count=1,
                title=f"Zona {z.origin} sem registro NS",
                detail=f"Arquivo {z.filename}",
                why="Zona sem NS não declara quem responde por ela. O BIND "
                    "recusa a zona no carregamento.",
                fix=["; @  IN NS  ns1.<dominio>.", "; @  IN NS  ns2.<dominio>."]))

        soas = z.by_type("SOA")
        if z.origin and len(soas) != 1:
            achados.append(DnsFinding(
                id=f"soa-{z.origin}", severity=2, count=len(soas),
                title=(f"Zona {z.origin} sem SOA" if not soas
                       else f"Zona {z.origin} com {len(soas)} SOA"),
                detail=f"Arquivo {z.filename}",
                why="Toda zona precisa de exatamente um SOA, e ele deve ser o "
                    "primeiro registro.",
                fix=[]))

    # --- 5. Zonas declaradas no named.conf sem arquivo enviado ---
    enviadas = {z.origin for z in zonas if z.origin}
    declaradas = [z for c in confs for z in c.zonas
                  if z["type"] in ("master", "primary")]
    faltantes = [z for z in declaradas if z["name"] not in enviadas]
    if faltantes:
        achados.append(DnsFinding(
            id="zona-declarada-sem-arquivo", severity=1, count=len(faltantes),
            title=f"{len(faltantes)} zona(s) no named.conf sem o arquivo enviado",
            detail=", ".join(z["name"] for z in faltantes[:8]),
            why="A validação só enxerga o que foi enviado. Estas zonas existem "
                "no servidor e não foram verificadas.",
            fix=[f"; Envie: {z['file']}" for z in faltantes[:8]]))

    achados.sort(key=lambda f: (-f.severity, f.id))

    # --- Resumo ---
    total_ptr = sum(len(v) for v in ptrs.values())
    ok = total_ptr - len(sem_a) - len(apontando_errado) - len(fora_do_upload)
    remediacao = _remediacao(zonas, sem_a, apontando_errado, genericos,
                            coleta_info)

    return {
        "coleta": coleta_info,
        "avisos": avisos,
        "remediacao": remediacao,
        "arquivos": [{"nome": z.filename, "origin": z.origin,
                      "reversa": z.is_reverse,
                      "cidr": str(z.cidr) if z.cidr else "",
                      "registros": len(z.records),
                      "gerados": sum(1 for r in z.records if r.gerado)}
                     for z in zonas],
        "named_conf": [{"nome": c.filename, "zonas": c.zonas} for c in confs],
        "ignorados": ignorados,
        "resumo": {
            "zonas": len(zonas),
            "ptr_total": total_ptr,
            "ptr_sem_a": len(sem_a),
            "ptr_divergente": len(apontando_errado),
            "ptr_nao_verificavel": len(fora_do_upload),
            "ptr_ok": max(0, ok),
            "genericos": len(genericos),
        },
        "findings": [f.to_dict() for f in achados],
        "counts": {
            "critico": sum(1 for f in achados if f.severity == 3),
            "importante": sum(1 for f in achados if f.severity == 2),
            "recomendado": sum(1 for f in achados if f.severity == 1),
            "informativo": sum(1 for f in achados if f.severity == 0),
        },
    }


def _origin_do_nome(filename: str) -> str:
    """Deriva o $ORIGIN do nome do arquivo quando ele segue a convenção do
    BIND: db.92.191.181 ou 92.191.181.in-addr.arpa.zone."""
    base = filename.split("/")[-1].split("\\")[-1]
    base = re.sub(r"\.(zone|db|conf|txt|cfg)$", "", base, flags=re.I)
    base = re.sub(r"^(db|zone)[.\-_]", "", base, flags=re.I)
    if base.lower().endswith(".in-addr.arpa"):
        return base.lower()
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){0,3}", base):
        return f"{base}.in-addr.arpa"
    return ""


def _dominio_de(nome: str) -> str:
    partes = nome.rstrip(".").split(".")
    if len(partes) <= 2:
        return nome
    segundo = {"com", "net", "org", "gov", "edu", "co", "ne", "or"}
    corte = 3 if len(partes) >= 4 and partes[-2] in segundo else 2
    return ".".join(partes[-corte:])


# --------------------------------------------------------------------------
# Remediação: o que o técnico cola no servidor
# --------------------------------------------------------------------------
def _remediacao(zonas, sem_a, divergentes, genericos, coleta) -> dict:
    """Monta os blocos prontos para aplicar.

    O princípio é o mesmo do script de correção dos roteadores: nada que possa
    derrubar serviço sai pronto para colar sem revisão. Aqui, porém, o risco é
    menor e o volume é grande (centenas de registros), então os registros em si
    saem completos e o que exige decisão fica marcado.
    """
    blocos: list[dict] = []
    diretas = {z.origin: z for z in zonas if z.origin and not z.is_reverse}

    # --- 1. Registros A faltando, agrupados por zona direta ---
    if sem_a:
        por_zona: dict[str, list[dict]] = defaultdict(list)
        for i in sem_a:
            alvo = i["nome"]
            zona = next((d for d in diretas
                         if alvo == d or alvo.endswith("." + d)), "")
            por_zona[zona].append(i)

        for zona, itens in sorted(por_zona.items()):
            z = diretas.get(zona)
            arquivo = z.filename if z else "<arquivo da zona direta>"
            linhas = [
                f"; Acrescente ao final da zona direta {zona}",
                f"; Arquivo: {arquivo}",
                ";",
                "; Cada nome publicado no PTR precisa existir aqui, apontando",
                "; de volta para o MESMO endereço. É esta metade que falta.",
                "",
            ]
            faixas = _agrupa_sequencial(itens, zona)
            for f in faixas:
                if f["tipo"] == "generate":
                    linhas.append(
                        f"$GENERATE {f['ini']}-{f['fim']} {f['lhs']} IN A "
                        f"{f['rede']}.$")
                else:
                    rel = _relativo(f["nome"], zona)
                    linhas.append(f"{rel}\tIN A\t{f['ip']}")
            blocos.append({
                "id": f"a-faltando-{zona or 'sem-zona'}",
                "titulo": f"Criar {len(itens)} registro(s) A em {zona or 'zona direta'}",
                "arquivo": arquivo,
                "linguagem": "zona",
                "conteudo": "\n".join(linhas),
                "nota": (f"{len([f for f in faixas if f['tipo'] == 'generate'])} "
                         f"faixa(s) contígua(s) viraram $GENERATE, que é uma "
                         f"linha por faixa em vez de uma por endereço."
                         if any(f["tipo"] == "generate" for f in faixas) else ""),
            })

    # --- 2. A divergente ---
    if divergentes:
        linhas = [
            "; Estes nomes existem, mas apontam para outro endereço.",
            "; Decida qual lado está certo: o PTR ou o A. Os dois precisam",
            "; fechar no mesmo endereço.",
            "",
        ]
        for i in divergentes[:60]:
            linhas.append(f"; {i['nome']}")
            linhas.append(f";   PTR diz .... {i['ip']}   ({i['arquivo']}:{i['linha']})")
            linhas.append(f";   A resolve .. {', '.join(i['encontrado']) or '(nada)'}")
        blocos.append({
            "id": "a-divergente",
            "titulo": f"Resolver {len(divergentes)} divergência(s) entre PTR e A",
            "arquivo": "",
            "linguagem": "zona",
            "conteudo": "\n".join(linhas),
            "nota": "Exige decisão: não dá para saber qual lado está correto "
                    "sem conhecer a função do endereço.",
        })

    # --- 3. Renomear o que é infraestrutura ---
    if genericos:
        linhas = [
            "; Nome que repete os números do endereço marca o espaço como de",
            "; usuário final.",
            ";",
            "; EM FAIXA DE ASSINANTE ISSO ESTÁ CORRETO e protege o bloco: é o",
            "; que impede um equipamento comprometido de entregar mensagem",
            "; direta. Não renomeie o pool.",
            ";",
            "; Renomeie APENAS o que é infraestrutura ou cliente com serviço",
            "; publicado. Modelo:",
            ";",
            ";   reversa:  1   IN PTR gw-pop01.<dominio>.",
            ";   direta:   gw-pop01  IN A  <rede>.1",
            ";",
            f"; Endereços com nome genérico neste servidor: {len(genericos)}",
            "; Os primeiros, para conferência:",
        ]
        for g in genericos[:20]:
            linhas.append(f";   {g['ip']:<16} {g['nome']}   "
                          f"({g['arquivo']}:{g['linha']}"
                          f"{', $GENERATE' if g['gerado'] else ''})")
        blocos.append({
            "id": "renomear",
            "titulo": "Separar infraestrutura de faixa de assinante",
            "arquivo": "",
            "linguagem": "zona",
            "conteudo": "\n".join(linhas),
            "nota": "Exige decisão: só quem conhece o plano de endereçamento "
                    "sabe o que é serviço e o que é pool.",
        })

    # --- 4. Serial, validação e reload ---
    if blocos:
        arquivos_rev = sorted({z.filename for z in zonas if z.is_reverse})
        arquivos_dir = sorted({z.filename for z in zonas if not z.is_reverse})
        origens = {z.filename: z.origin for z in zonas}
        cmds = [
            "# 1. Suba o serial de CADA zona que voce editar.",
            "#    Sem isso o secundario nao recebe a alteracao e o cache do",
            "#    mundo continua com o dado antigo.",
            "#    Formato usual: AAAAMMDDNN",
            "",
        ]
        for f in arquivos_dir + arquivos_rev:
            cmds.append(f"sudo sed -i \"s/[0-9]\\{{10\\}}[[:space:]]*;[[:space:]]*serial/"
                        f"$(date +%Y%m%d)01 ; serial/\" {f}")
        cmds += [
            "",
            "# 2. Valide ANTES de recarregar. Zona invalida faz o BIND recusar",
            "#    a zona inteira, e a versao antiga continua no ar sem aviso.",
            "",
        ]
        for f in arquivos_dir + arquivos_rev:
            cmds.append(f"sudo named-checkzone {origens.get(f, '<zona>')} {f}")
        cmds += [
            "",
            "# 3. Recarregue.",
            "sudo named-checkconf",
            "sudo rndc reload",
            "",
            "# 4. Confirme os DOIS sentidos a partir de um resolver externo.",
            "#    Testar so o reverso e o que fez o problema passar batido.",
        ]
        exemplo = sem_a[0] if sem_a else None
        if exemplo:
            cmds += [
                f"dig +short -x {exemplo['ip']} @1.1.1.1",
                f"dig +short {exemplo['nome']} @1.1.1.1",
                "#    As duas respostas precisam fechar no mesmo endereco.",
            ]
        if coleta.get("servidor") == "powerdns":
            cmds = [
                "# Servidor identificado: PowerDNS. Os registros ficam no banco,",
                "# nao em arquivo. Para aplicar:",
                "#   sudo pdnsutil edit-zone <zona>",
                "# ou, registro a registro:",
                "#   sudo pdnsutil add-record <zona> <nome> A <ip>",
                "#",
                "# Depois:",
                "sudo pdnsutil increase-serial <zona>",
                "sudo pdnsutil check-zone <zona>",
                "sudo pdns_control rediscover",
            ]
        blocos.append({
            "id": "aplicar",
            "titulo": "Subir serial, validar e recarregar",
            "arquivo": "",
            "linguagem": "shell",
            "conteudo": "\n".join(cmds),
            "nota": "O passo 2 não é opcional: zona recusada no reload deixa a "
                    "versão anterior no ar sem nenhum aviso.",
        })

    return {"blocos": blocos, "total": len(blocos)}


def _relativo(nome: str, zona: str) -> str:
    n = nome.rstrip(".").lower()
    z = zona.rstrip(".").lower()
    if z and n.endswith("." + z):
        return n[: -(len(z) + 1)]
    return n + "."


def _agrupa_sequencial(itens: list[dict], zona: str) -> list[dict]:
    """Transforma endereços contíguos com nome de mesmo padrão em $GENERATE.

    Um /24 inteiro sem registro A geraria 256 linhas; quando os nomes seguem um
    padrão com o último octeto, uma linha resolve a faixa toda.
    """
    def chave(i):
        """Troca o ÚLTIMO octeto pelo marcador do $GENERATE.

        Substituir a primeira ocorrência não serve: em '92-191-181-81' o
        trecho '81' aparece antes, dentro de '181', e o padrão saía como
        '92-191-1$-81'. A troca precisa ser ancorada no fim do rótulo.
        """
        rel = _relativo(i["nome"], zona)
        ip = i["ip"]
        ult = ip.rsplit(".", 1)[-1]
        if not ult:
            return (None, None)
        m = re.search(rf"(?<!\d){re.escape(ult)}(?!\d)", rel[::-1][::-1])
        # ancorado no fim do primeiro rótulo, que é onde o octeto costuma estar
        primeiro, _, resto = rel.partition(".")
        if primeiro.endswith(ult):
            padrao = primeiro[: -len(ult)] + "$"
            if resto:
                padrao += "." + resto
            return (ip.rsplit(".", 1)[0], padrao)
        return (None, None)

    ordenados = sorted(itens, key=lambda i: ipaddress.ip_address(i["ip"]))
    saida: list[dict] = []
    corrente: list[dict] = []
    padrao = (None, None)

    def fecha():
        if not corrente:
            return
        if len(corrente) >= 4 and padrao[0]:
            saida.append({
                "tipo": "generate", "rede": padrao[0], "lhs": padrao[1],
                "ini": int(corrente[0]["ip"].rsplit(".", 1)[-1]),
                "fim": int(corrente[-1]["ip"].rsplit(".", 1)[-1]),
            })
        else:
            for c in corrente:
                saida.append({"tipo": "registro", "nome": c["nome"], "ip": c["ip"]})

    for i in ordenados:
        k = chave(i)
        contiguo = (corrente and k == padrao and
                    int(i["ip"].rsplit(".", 1)[-1]) ==
                    int(corrente[-1]["ip"].rsplit(".", 1)[-1]) + 1)
        if contiguo:
            corrente.append(i)
        else:
            fecha()
            corrente, padrao = [i], k
    fecha()
    return saida
