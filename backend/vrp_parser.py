"""
vrp_parser.py — Leitor de configuração Huawei VRP (NE8000, NE40E, NE20E, CE).

O VRP e o RouterOS sao formatos opostos. O .rsc e uma lista plana de comandos
com parametros nomeados (chave=valor); o VRP e uma arvore hierarquica onde a
indentacao define o escopo e as secoes sao separadas por '#'.

    #
    interface GigabitEthernet0/0/1
     ip address 10.0.0.1 255.255.255.0
     traffic-filter inbound acl 3000
    #

Por isso o parser e separado. A saida, porem, alimenta as MESMAS verificacoes
do analisador: o que importa para uma listagem em RBL nao muda de fabricante.

Aceita 'display current-configuration', 'display saved-configuration' e
arquivos .cfg/.zip descompactados exportados do equipamento.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field


@dataclass
class Block:
    """Uma linha de configuracao e o que estiver aninhado sob ela."""
    text: str                      # linha sem indentacao
    words: list[str]
    children: list["Block"] = field(default_factory=list)
    line_no: int = 0
    depth: int = 0

    def head(self, n: int = 1) -> str:
        return " ".join(self.words[:n])

    def find(self, *prefixos: str) -> list["Block"]:
        """Filhos diretos cuja linha comeca por qualquer um dos prefixos."""
        out = []
        for c in self.children:
            for p in prefixos:
                if c.text.startswith(p):
                    out.append(c)
                    break
        return out

    def first(self, *prefixos: str) -> "Block | None":
        f = self.find(*prefixos)
        return f[0] if f else None

    def walk(self):
        yield self
        for c in self.children:
            yield from c.walk()


@dataclass
class VrpConfig:
    filename: str
    root: Block
    sysname: str = ""
    version: str = ""
    model: str = ""

    def sections(self, *prefixos: str) -> list[Block]:
        return self.root.find(*prefixos)

    def all_lines(self):
        for b in self.root.walk():
            if b is not self.root:
                yield b


# Marcadores que identificam um export VRP com boa confianca.
VRP_SINAIS = (
    "display current-configuration", "display saved-configuration",
    "sysname ", "interface GigabitEthernet", "interface Eth-Trunk",
    "undo info-center", " VRP ", "Huawei Versatile Routing Platform",
    "interface LoopBack", "bgp ", "acl number ", "nat instance",
    "interface 100GE", "interface 10GE", "interface Virtual-Template",
    "acl name ", "traffic-policy ", "pppoe-server", "ip pool ",
    "user-interface vty", "snmp-agent", "set neid",
)


def parece_vrp(texto: str) -> bool:
    """Distingue de um .rsc do RouterOS. Precisa de mais de um sinal para
    evitar falso positivo com arquivo de texto qualquer."""
    if "/ip firewall" in texto or "/interface " in texto:
        return False
    achados = sum(1 for s in VRP_SINAIS if s in texto)
    return achados >= 2


def _indent(linha: str) -> int:
    return len(linha) - len(linha.lstrip(" "))


def parse(texto: str, filename: str = "config.cfg") -> VrpConfig:
    texto = texto.replace("\r\n", "\n").replace("\r", "\n")
    root = Block(text="<root>", words=[], depth=-1)
    pilha: list[Block] = [root]

    for n, bruta in enumerate(texto.split("\n"), 1):
        linha = bruta.rstrip()
        s = linha.strip()
        # '#' separa secoes e nao carrega conteudo; '!' e comentario.
        # A COLUNA importa: '#' na coluna 0 encerra a secao inteira, mas '#'
        # indentado e apenas um separador interno. Confundir os dois arranca
        # blocos aninhados de dentro do pai — num BNG real o 'access-type' de
        # dentro do 'bas' acabava virando secao de primeiro nivel.
        if not s or s == "#" or s.startswith("!"):
            if s == "#" and _indent(linha) == 0:
                del pilha[1:]
            continue
        if s.startswith("<") and s.endswith(">"):   # prompt colado no arquivo
            continue

        prof = _indent(linha)
        bloco = Block(text=s, words=s.split(), line_no=n, depth=prof)

        while len(pilha) > 1 and pilha[-1].depth >= prof:
            pilha.pop()
        pilha[-1].children.append(bloco)
        pilha.append(bloco)

    cfg = VrpConfig(filename=filename, root=root)

    if m := re.search(r"^\s*sysname\s+(\S+)", texto, re.M):
        cfg.sysname = m.group(1)
    if m := re.search(r"VRP.*?Version\s+([\d.]+\s*\(?[^)\n]*\)?)", texto):
        cfg.version = m.group(1).strip()
    elif m := re.search(r"!Software Version\s+(\S+)", texto):
        cfg.version = m.group(1)
    # O sufixo precisa parecer código de modelo (X8, M14, F1A), senão o
    # regex captura o sysname: "NE8000-BORDA-TESTE" viraria o modelo.
    SUF = r"(?:[- ]?(?:X\d+[A-Z]?|M\d+[A-Z]?|F\d+[A-Z]?|E\d*|S\d+))?"
    for familia in ("NE8000", "NE40E", "NE20E", "NE5000E", "ATN"):
        if m := re.search(rf"\b({familia}{SUF})\b", texto):
            cfg.model = m.group(1)
            break
    else:
        if m := re.search(r"\b(CE\d{4}[A-Z]*)\b", texto):
            cfg.model = m.group(1)

    return cfg


# --------------------------------------------------------------------------
def mask_to_prefix(mask: str) -> int | None:
    """255.255.255.0 -> 24. O VRP usa mascara pontilhada em quase todo lugar."""
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
    except ValueError:
        try:
            n = int(mask)
            return n if 0 <= n <= 32 else None
        except ValueError:
            return None


def as_network(ip: str, mask: str | None = None):
    try:
        if mask:
            p = mask_to_prefix(mask)
            if p is None:
                return None
            return ipaddress.ip_network(f"{ip}/{p}", strict=False)
        return ipaddress.ip_network(ip, strict=False)
    except ValueError:
        return None


def is_private(net) -> bool:
    if net is None:
        return False
    cgnat = ipaddress.ip_network("100.64.0.0/10")
    return net.is_private or net.subnet_of(cgnat)


# Nomes de porta que o VRP aceita no lugar do numero.
PORTAS_NOMEADAS = {
    "smtp": 25, "telnet": 23, "ssh": 22, "ftp": 21, "ftp-data": 20,
    "domain": 53, "dns": 53, "http": 80, "www": 80, "https": 443,
    "pop3": 110, "snmp": 161, "snmptrap": 162, "ntp": 123,
    "chargen": 19, "netbios-ns": 137, "bootps": 67, "bootpc": 68,
}


def portas_da_regra(texto: str, lado: str = "destination") -> set[int]:
    """Extrai portas de uma linha 'rule ... destination-port eq smtp' ou
    'destination-port range 20 25'. Cobre eq, range, lt e gt."""
    out: set[int] = set()

    def num(tok: str) -> int | None:
        if tok.isdigit():
            return int(tok)
        return PORTAS_NOMEADAS.get(tok.lower())

    for m in re.finditer(rf"{lado}-port\s+(eq|range|lt|gt)\s+(\S+)(?:\s+(\S+))?",
                         texto):
        op, a, b = m.group(1), m.group(2), m.group(3)
        na = num(a)
        if op == "eq" and na is not None:
            out.add(na)
        elif op == "range" and na is not None:
            nb = num(b) if b else None
            if nb is not None and 0 <= na <= nb <= 65535 and nb - na <= 20000:
                out.update(range(na, nb + 1))
        elif op == "lt" and na is not None and na <= 20000:
            out.update(range(0, na))
        elif op == "gt" and na is not None and 65535 - na <= 20000:
            out.update(range(na + 1, 65536))
    return out
