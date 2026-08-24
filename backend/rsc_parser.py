"""
rsc_parser.py — Leitor de arquivos .rsc exportados do RouterOS.

Transforma o export em estrutura consultavel. Nao e um parser completo da
linguagem do RouterOS: e o suficiente para auditoria de configuracao, que e
o que a analise precisa.

Detalhes que quebram parsers ingenuos e estao tratados aqui:
  - continuacao de linha com "\\" no fim
  - valores entre aspas contendo espacos e virgulas
  - comentarios que atravessam varias linhas
  - o mesmo caminho aparecendo varias vezes no arquivo
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field


@dataclass
class Item:
    """Uma linha de configuracao: 'add'/'set' dentro de um caminho."""
    path: str                 # ex: "/ip firewall raw"
    verb: str                 # add | set | outro
    params: dict[str, str]
    raw: str
    line_no: int

    def get(self, key: str, default: str = "") -> str:
        return self.params.get(key, default)

    @property
    def disabled(self) -> bool:
        return self.params.get("disabled", "no") == "yes"

    @property
    def comment(self) -> str:
        return self.params.get("comment", "")

    def ports(self, key: str) -> set[int]:
        """Expande '19,25,1900' e '16460-16480' em portas individuais."""
        out: set[int] = set()
        for part in self.get(key, "").split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                a, _, b = part.partition("-")
                try:
                    lo, hi = int(a), int(b)
                except ValueError:
                    continue
                if hi - lo > 20000:          # faixa absurda, provavelmente erro
                    continue
                out.update(range(lo, hi + 1))
            else:
                try:
                    out.add(int(part))
                except ValueError:
                    pass
        return out


@dataclass
class Config:
    filename: str
    items: list[Item] = field(default_factory=list)
    identity: str = ""
    model: str = ""
    version: str = ""

    def by_path(self, path: str) -> list[Item]:
        return [i for i in self.items if i.path == path]

    def paths(self) -> set[str]:
        return {i.path for i in self.items}

    def has_path(self, path: str) -> bool:
        return any(i.path == path for i in self.items)


PARAM_RE = re.compile(r'([a-zA-Z0-9_.-]+)=("(?:[^"\\]|\\.)*"|\S+)')


def parse(text: str, filename: str = "config.rsc") -> Config:
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    cfg = Config(filename=filename)

    # Cabecalho do export
    if m := re.search(r"#\s*(\d{4}-\d{2}-\d{2}.*?)by RouterOS ([\d.]+)", text):
        cfg.version = m.group(2)
    if m := re.search(r"#\s*model\s*=\s*(\S+)", text):
        cfg.model = m.group(1)

    # Junta continuacoes de linha, preservando a numeracao original
    lines: list[tuple[int, str]] = []
    buf, start = "", 0
    for n, line in enumerate(text.split("\n"), 1):
        stripped = line.rstrip()
        if not buf:
            start = n
        if stripped.endswith("\\"):
            buf += stripped[:-1].rstrip() + " "
            continue
        buf += stripped
        lines.append((start, buf))
        buf = ""
    if buf:
        lines.append((start, buf))

    current_path = ""
    for line_no, line in lines:
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if s.startswith("/"):
            # Pode ser só o caminho, ou caminho + comando na mesma linha
            m = re.match(r"^(/[^\s]+(?:\s+[a-z0-9-]+)*)\s*(add|set|remove)?\s*(.*)$", s)
            if not m:
                continue
            head, verb, rest = m.group(1), m.group(2), m.group(3)
            current_path = head.strip()
            if verb:
                cfg.items.append(_item(current_path, verb, rest, s, line_no))
            continue

        m = re.match(r"^(add|set|remove)\s*(.*)$", s)
        if m and current_path:
            cfg.items.append(_item(current_path, m.group(1), m.group(2), s, line_no))

    if ident := [i for i in cfg.items if i.path == "/system identity"]:
        cfg.identity = ident[0].get("name").strip('"')

    return cfg


def _item(path: str, verb: str, rest: str, raw: str, line_no: int) -> Item:
    params: dict[str, str] = {}
    for key, val in PARAM_RE.findall(rest):
        if val.startswith('"') and val.endswith('"'):
            val = val[1:-1]
        params[key] = val
    return Item(path=path, verb=verb, params=params, raw=raw, line_no=line_no)


# --------------------------------------------------------------------------
def as_network(value: str):
    """Aceita 'a.b.c.d', 'a.b.c.d/n', '!a.b.c.d'. Retorna None se nao for IP."""
    value = value.strip().lstrip("!")
    if not value:
        return None
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None


def is_private(net) -> bool:
    """RFC1918 + CGNAT (100.64/10). O 100.64/10 nao e 'private' para o modulo
    ipaddress, mas para efeito de auditoria de ISP e espaco interno."""
    if net is None:
        return False
    cgnat = ipaddress.ip_network("100.64.0.0/10")
    return net.is_private or net.subnet_of(cgnat)
