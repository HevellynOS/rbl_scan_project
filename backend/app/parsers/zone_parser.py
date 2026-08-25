"""
app/parsers/zone_parser.py — Leitor de arquivos de zona BIND e de named.conf.

Serve para validar a configuração do servidor de DNS antes de ela chegar na
rede. A auditoria por consulta (a que a varredura faz) só enxerga o resultado;
aqui dá para apontar a linha exata onde o erro foi escrito.

Cobre o que aparece em servidor de provedor:
  - $TTL, $ORIGIN, $INCLUDE (registrado, não seguido)
  - $GENERATE com $ e ${offset,largura,tipo}
  - nome de dono omitido (herda o anterior), '@', nomes relativos ao $ORIGIN
  - parênteses multilinha do SOA
  - comentários com ';'
  - named.conf: blocos zone com type, file e allow-transfer

Não cobre: DNSSEC, views, backends SQL do PowerDNS. Para PowerDNS com banco, a
saída de `pdnsutil list-zone <zona>` sai em formato de arquivo de zona e pode
ser enviada aqui.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

TIPOS = {"A", "AAAA", "PTR", "CNAME", "NS", "SOA", "MX", "TXT", "SRV",
         "CAA", "DNAME", "NAPTR", "SPF"}
CLASSES = {"IN", "CH", "HS"}


@dataclass
class Record:
    name: str            # nome absoluto, sem ponto final
    rtype: str
    rdata: str
    ttl: int | None = None
    line_no: int = 0
    gerado: bool = False   # veio de $GENERATE
    origem: str = ""       # arquivo


@dataclass
class Zone:
    filename: str
    origin: str = ""
    records: list[Record] = field(default_factory=list)
    erros: list[tuple[int, str]] = field(default_factory=list)
    includes: list[str] = field(default_factory=list)
    rotulo: str = ""     # como exibir; filename guarda o caminho real

    @property
    def is_reverse(self) -> bool:
        return self.origin.endswith((".in-addr.arpa", ".ip6.arpa"))

    def by_type(self, *tipos: str) -> list[Record]:
        alvo = {t.upper() for t in tipos}
        return [r for r in self.records if r.rtype in alvo]

    @property
    def cidr(self):
        """Prefixo coberto por uma zona reversa IPv4."""
        return zone_to_cidr(self.origin)


@dataclass
class NamedConf:
    filename: str
    zonas: list[dict] = field(default_factory=list)   # name, type, file, extras


# --------------------------------------------------------------------------
def zone_to_cidr(origin: str):
    """'92.191.181.in-addr.arpa' -> IPv4Network 181.191.92.0/24."""
    o = origin.rstrip(".").lower()
    if not o.endswith(".in-addr.arpa"):
        return None
    labels = o[: -len(".in-addr.arpa")].split(".")
    if not labels or len(labels) > 4:
        return None
    try:
        octetos = [int(x) for x in reversed(labels)]
    except ValueError:
        return None
    if any(n < 0 or n > 255 for n in octetos):
        return None
    prefixo = len(octetos) * 8
    octetos += [0] * (4 - len(octetos))
    try:
        return ipaddress.ip_network(
            f"{'.'.join(str(x) for x in octetos)}/{prefixo}", strict=False)
    except ValueError:
        return None


def ptr_owner_to_ip(name: str) -> str | None:
    """'15.92.191.181.in-addr.arpa' -> '181.191.92.15'."""
    n = name.rstrip(".").lower()
    if not n.endswith(".in-addr.arpa"):
        return None
    labels = n[: -len(".in-addr.arpa")].split(".")
    if len(labels) != 4:
        return None
    try:
        octetos = [int(x) for x in reversed(labels)]
    except ValueError:
        return None
    if any(x < 0 or x > 255 for x in octetos):
        return None
    return ".".join(str(x) for x in octetos)


def parece_zona(texto: str) -> bool:
    t = texto.lower()
    marcas = ("$ttl", "$origin", "$generate", " soa ", "\tsoa ", " ptr ",
              "\tptr ", " in a ", " in ptr ", "in-addr.arpa")
    return sum(1 for m in marcas if m in t) >= 2


def parece_named_conf(texto: str) -> bool:
    return bool(re.search(r"^\s*zone\s+\"", texto, re.M)) and "{" in texto


# --------------------------------------------------------------------------
def _absoluto(nome: str, origin: str) -> str:
    nome = nome.strip()
    if nome.endswith("."):
        return nome[:-1].lower()
    if nome == "@":
        return origin.lower()
    if not origin:
        return nome.lower()
    return f"{nome}.{origin}".lower()


_GEN_MOD = re.compile(r"\$(\{([-+]?\d+)(?:,(\d+))?(?:,([dxXon]))?\})?")


def _expande(padrao: str, i: int) -> str:
    """Substitui '$' e '${offset,largura,tipo}' pelo iterador do $GENERATE."""
    def sub(m: re.Match) -> str:
        if not m.group(1):
            return str(i)
        offset = int(m.group(2) or 0)
        largura = int(m.group(3) or 0)
        tipo = (m.group(4) or "d").lower()
        v = i + offset
        if tipo == "d":
            s = str(v)
        elif tipo == "x":
            s = format(v, "x")
        elif tipo == "o":
            s = format(v, "o")
        elif tipo == "n":            # nibble, usado em ip6.arpa
            s = ".".join(reversed(format(v, "x")))
        else:
            s = str(v)
        return s.rjust(largura, "0") if largura else s
    return _GEN_MOD.sub(sub, padrao)


MAX_GERADOS = 4096


def parse_zone(texto: str, filename: str = "zona", origin: str = "") -> Zone:
    texto = texto.replace("\r\n", "\n").replace("\r", "\n")
    z = Zone(filename=filename, origin=origin.rstrip(".").lower())
    ttl_padrao: int | None = None
    ultimo_nome = ""

    # Junta linhas de registro que abrem parênteses (SOA, tipicamente),
    # preservando a numeração original.
    linhas: list[tuple[int, str]] = []
    buf, inicio, abertos = "", 0, 0
    for n, bruta in enumerate(texto.split("\n"), 1):
        linha = bruta.split(";")[0] if ";" in _fora_de_aspas(bruta) else bruta
        linha = _corta_comentario(bruta)
        if not buf:
            inicio = n
        abertos += linha.count("(") - linha.count(")")
        buf += (" " if buf else "") + linha.strip()
        if abertos <= 0:
            if buf.strip():
                linhas.append((inicio, buf.replace("(", " ").replace(")", " ")))
            buf, abertos = "", 0

    for n, linha in linhas:
        s = linha.strip()
        if not s:
            continue

        if s.upper().startswith("$TTL"):
            ttl_padrao = _ttl(s.split()[1] if len(s.split()) > 1 else "")
            continue
        if s.upper().startswith("$ORIGIN"):
            partes = s.split()
            if len(partes) > 1:
                z.origin = partes[1].rstrip(".").lower()
            continue
        if s.upper().startswith("$INCLUDE"):
            partes = s.split()
            if len(partes) > 1:
                z.includes.append(partes[1])
            continue
        if s.upper().startswith("$GENERATE"):
            _gera(s, z, n, ttl_padrao)
            continue

        campos = s.split()
        if not campos:
            continue

        # Nome do dono: se a linha começa com espaço, herda o anterior.
        if linha[:1] in (" ", "\t"):
            nome = ultimo_nome
        else:
            nome = campos[0]
            campos = campos[1:]
            ultimo_nome = nome
        if not campos:
            continue

        ttl = ttl_padrao
        if campos and campos[0].upper() not in CLASSES and campos[0].upper() not in TIPOS:
            t = _ttl(campos[0])
            if t is not None:
                ttl = t
                campos = campos[1:]
        if campos and campos[0].upper() in CLASSES:
            campos = campos[1:]
        if not campos:
            z.erros.append((n, "registro sem tipo"))
            continue

        rtype = campos[0].upper()
        if rtype not in TIPOS:
            z.erros.append((n, f"tipo de registro não reconhecido: {campos[0]}"))
            continue

        rdata = " ".join(campos[1:]).strip()
        z.records.append(Record(name=_absoluto(nome, z.origin), rtype=rtype,
                                rdata=rdata, ttl=ttl, line_no=n,
                                origem=filename))
    return z


def _fora_de_aspas(linha: str) -> str:
    return linha


def _corta_comentario(linha: str) -> str:
    fora = True
    for i, c in enumerate(linha):
        if c == '"':
            fora = not fora
        elif c == ";" and fora:
            return linha[:i]
    return linha


def _ttl(v: str) -> int | None:
    v = v.strip().lower()
    if not v:
        return None
    if v.isdigit():
        return int(v)
    m = re.fullmatch(r"(\d+)([smhdw])", v)
    if not m:
        return None
    mult = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}[m.group(2)]
    return int(m.group(1)) * mult


def _gera(linha: str, z: Zone, n: int, ttl_padrao: int | None) -> None:
    campos = linha.split()
    if len(campos) < 4:
        z.erros.append((n, "$GENERATE incompleto"))
        return
    faixa = campos[1]
    m = re.fullmatch(r"(\d+)-(\d+)(?:/(\d+))?", faixa)
    if not m:
        z.erros.append((n, f"faixa inválida em $GENERATE: {faixa}"))
        return
    ini, fim = int(m.group(1)), int(m.group(2))
    passo = int(m.group(3) or 1) or 1
    if fim < ini:
        z.erros.append((n, f"faixa invertida em $GENERATE: {faixa}"))
        return

    resto = campos[2:]
    lhs = resto[0]
    resto = resto[1:]
    ttl = ttl_padrao
    if resto and resto[0].upper() not in CLASSES and resto[0].upper() not in TIPOS:
        t = _ttl(resto[0])
        if t is not None:
            ttl = t
            resto = resto[1:]
    if resto and resto[0].upper() in CLASSES:
        resto = resto[1:]
    if not resto:
        z.erros.append((n, "$GENERATE sem tipo de registro"))
        return
    rtype = resto[0].upper()
    rhs = " ".join(resto[1:])

    total = len(range(ini, fim + 1, passo))
    if total > MAX_GERADOS:
        z.erros.append((n, f"$GENERATE produziria {total} registros; "
                           f"limite de leitura é {MAX_GERADOS}"))
        return

    for i in range(ini, fim + 1, passo):
        z.records.append(Record(
            name=_absoluto(_expande(lhs, i), z.origin),
            rtype=rtype, rdata=_expande(rhs, i), ttl=ttl,
            line_no=n, gerado=True, origem=z.filename))


# --------------------------------------------------------------------------
def parse_named_conf(texto: str, filename: str = "named.conf") -> NamedConf:
    texto = texto.replace("\r\n", "\n")
    conf = NamedConf(filename=filename)
    for m in re.finditer(r'zone\s+"([^"]+)"\s*(?:(\w+)\s*)?\{([^}]*)\}',
                         texto, re.S):
        nome, corpo = m.group(1), m.group(3)
        tipo = re.search(r"\btype\s+(\w+)", corpo)
        arquivo = re.search(r'\bfile\s+"([^"]+)"', corpo)
        transfer = re.search(r"\ballow-transfer\s*\{([^}]*)\}", corpo)
        conf.zonas.append({
            "name": nome.rstrip(".").lower(),
            "type": tipo.group(1) if tipo else "",
            "file": arquivo.group(1) if arquivo else "",
            "allow_transfer": (transfer.group(1).strip() if transfer else ""),
        })
    return conf


# --------------------------------------------------------------------------
# Arquivo de coleta (ver app/services/dns_collect.py)
# --------------------------------------------------------------------------
@dataclass
class Coleta:
    """Um arquivo único produzido pelo comando de coleta, já separado em
    partes. Cada parte volta a ser tratada como se fosse um arquivo avulso."""
    host: str = ""
    data: str = ""
    servidor: str = ""
    versao: str = ""
    partes: list[tuple[str, str, str, str]] = field(default_factory=list)
    # (rotulo_exibido, conteudo, origin_conhecido, caminho_real)
    avisos: list[str] = field(default_factory=list)


_RE_CAB = re.compile(r"^#####\s*RBLSCAN-COLETA(?:\s+v(\S+))?", re.M)
_RE_META = re.compile(r"^#####\s*(HOST|DATA|SERVIDOR|AVISO):\s*(.+)$", re.M)
_RE_ARQ = re.compile(r"^=====\s*ARQUIVO:\s*(\S+)\s*=====\s*$", re.M)
_RE_ZONA = re.compile(
    r"^=====\s*ZONA:\s*(\S+)\s+TIPO:\s*(\S+)\s+ARQUIVO:\s*(.+?)\s*=====\s*$",
    re.M)
_RE_FIM = re.compile(r"^=====\s*FIM\s*=====\s*$", re.M)


def parece_coleta(texto: str) -> bool:
    return bool(_RE_CAB.search(texto))


def parse_coleta(texto: str, filename: str = "coleta.txt") -> Coleta:
    texto = texto.replace("\r\n", "\n").replace("\r", "\n")
    c = Coleta()

    if m := _RE_CAB.search(texto):
        c.versao = m.group(1) or "?"
    for m in _RE_META.finditer(texto):
        chave, valor = m.group(1), m.group(2).strip()
        if chave == "HOST":
            c.host = valor
        elif chave == "DATA":
            c.data = valor
        elif chave == "SERVIDOR":
            c.servidor = valor
        elif chave == "AVISO":
            c.avisos.append(valor)

    if c.servidor == "desconhecido":
        c.avisos.append(
            "O coletor não encontrou BIND nem PowerDNS neste servidor. "
            "Confirme se é ele quem responde pelas zonas reversas.")

    # Percorre os marcadores na ordem em que aparecem, para não depender de
    # os blocos de ARQUIVO virem antes dos de ZONA.
    marcas = sorted(
        [(m.start(), m.end(), "arquivo", m.group(1), "") for m in _RE_ARQ.finditer(texto)]
        + [(m.start(), m.end(), "zona", m.group(3), m.group(1))
           for m in _RE_ZONA.finditer(texto)],
        key=lambda x: x[0])

    fins = [m.start() for m in _RE_FIM.finditer(texto)]

    for inicio, fim_marca, tipo, caminho, origin in marcas:
        proximo = next((f for f in fins if f > fim_marca), len(texto))
        conteudo = texto[fim_marca:proximo].strip("\n")
        if not conteudo.strip():
            continue
        base = caminho.split("/")[-1] or caminho
        rotulo = f"{origin} ({base})" if tipo == "zona" and origin else base
        # O caminho real precisa sobreviver: é ele que entra nos comandos de
        # named-checkzone e de sed no servidor.
        c.partes.append((rotulo, conteudo, origin, caminho))

    return c
