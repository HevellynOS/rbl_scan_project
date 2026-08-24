"""
app/database/models.py — Formato dos registros persistidos.

Dataclasses puras, sem ORM. Servem como contrato entre o repositório e o
restante da aplicação: quando o banco real entrar, o mapeamento acontece aqui
e nenhuma rota precisa mudar.

Os campos foram escolhidos pensando no que a ferramenta não consegue responder
hoje: se a remediação funcionou. Sem série histórica por bloco, não há como
provar melhora num pedido de remoção, que é justamente o que as listas pedem.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone


def _agora() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class ScanRecord:
    """Uma varredura de bloco. `payload` guarda o relatório completo."""
    network: str
    created_at: str = field(default_factory=_agora)
    total: int = 0
    listed: int = 0
    behavior: int = 0
    policy: int = 0
    no_ptr: int = 0
    generic_ptr: int = 0
    fcrdns_broken: int = 0
    elapsed: float = 0.0
    payload: dict = field(default_factory=dict)

    @classmethod
    def from_report(cls, report: dict) -> "ScanRecord":
        r = report.get("rdns", {})
        c = report.get("counts", {})
        return cls(
            network=report.get("network", ""),
            total=report.get("total", 0),
            listed=report.get("listed", 0),
            behavior=c.get("behavior", 0),
            policy=c.get("policy", 0),
            no_ptr=r.get("no_ptr", 0),
            generic_ptr=r.get("generic", 0),
            fcrdns_broken=r.get("fcrdns_broken", 0),
            elapsed=report.get("elapsed", 0.0),
            payload=report,
        )

    def resumo(self) -> dict:
        d = asdict(self)
        d.pop("payload", None)
        return d


@dataclass
class AnalysisRecord:
    """Uma análise de configuração, com um ou mais equipamentos."""
    created_at: str = field(default_factory=_agora)
    devices: int = 0
    identities: list[str] = field(default_factory=list)
    vendors: list[str] = field(default_factory=list)
    critico: int = 0
    importante: int = 0
    payload: dict = field(default_factory=dict)

    @classmethod
    def from_analysis(cls, analysis: dict) -> "AnalysisRecord":
        devs = analysis.get("devices", [])
        t = analysis.get("totals", {})
        return cls(
            devices=len(devs),
            identities=[d.get("identity", "") for d in devs],
            vendors=sorted({d.get("vendor", "?") for d in devs}),
            critico=t.get("critico", 0),
            importante=t.get("importante", 0),
            payload=analysis,
        )

    def resumo(self) -> dict:
        d = asdict(self)
        d.pop("payload", None)
        return d
