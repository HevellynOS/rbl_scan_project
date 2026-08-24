"""
app/database/connection.py — Repositório de varreduras e análises.

Hoje a implementação é em memória, que é exatamente o que o banco vai
substituir. As rotas conversam apenas com a interface `Repository`, então
trocar a implementação não muda nenhuma rota.

Para ligar um banco de verdade:
  1. defina RBLSCAN_DATABASE_URL no .env
  2. implemente SqlRepository abaixo, respeitando a mesma interface
  3. faça get_repository() devolver a nova implementação

Limitação atual, e o motivo de o banco fazer falta: reiniciar o processo apaga
tudo. Sem histórico não há como comparar antes e depois de uma remediação, que
é a evidência que as listas de reputação pedem num pedido de remoção.
"""

from __future__ import annotations

from collections import OrderedDict
from typing import Protocol

from app.core.config import settings
from app.database.models import AnalysisRecord, ScanRecord

MAX_EM_MEMORIA = 50


class Repository(Protocol):
    def save_scan(self, report: dict) -> ScanRecord: ...
    def get_scan(self, network: str) -> dict | None: ...
    def scan_history(self, network: str) -> list[dict]: ...
    def list_scans(self) -> list[dict]: ...
    def save_analysis(self, analysis: dict) -> AnalysisRecord: ...
    def get_analysis(self) -> dict | None: ...
    def clear(self) -> None: ...


class MemoryRepository:
    """Guarda o relatório mais recente por bloco, mais um histórico curto.

    OrderedDict com teto: uma varredura de /20 gera relatório grande, e sem
    limite o processo cresce até o fim da sessão.
    """

    def __init__(self, limite: int = MAX_EM_MEMORIA):
        self._scans: OrderedDict[str, ScanRecord] = OrderedDict()
        self._historico: dict[str, list[ScanRecord]] = {}
        self._analysis: AnalysisRecord | None = None
        self._limite = limite

    def save_scan(self, report: dict) -> ScanRecord:
        rec = ScanRecord.from_report(report)
        if not rec.network:
            return rec
        self._scans[rec.network] = rec
        self._scans.move_to_end(rec.network)
        hist = self._historico.setdefault(rec.network, [])
        hist.append(rec)
        del hist[:-10]
        while len(self._scans) > self._limite:
            antigo, _ = self._scans.popitem(last=False)
            self._historico.pop(antigo, None)
        return rec

    def get_scan(self, network: str) -> dict | None:
        rec = self._scans.get(network.strip())
        return rec.payload if rec else None

    def scan_history(self, network: str) -> list[dict]:
        return [r.resumo() for r in self._historico.get(network.strip(), [])]

    def list_scans(self) -> list[dict]:
        return [r.resumo() for r in reversed(self._scans.values())]

    def save_analysis(self, analysis: dict) -> AnalysisRecord:
        self._analysis = AnalysisRecord.from_analysis(analysis)
        return self._analysis

    def get_analysis(self) -> dict | None:
        return self._analysis.payload if self._analysis else None

    def clear(self) -> None:
        self._scans.clear()
        self._historico.clear()
        self._analysis = None


_repo: Repository = MemoryRepository()


def get_repository() -> Repository:
    """Ponto único de troca. Quando houver banco, decida aqui."""
    if settings.has_database:
        # Ainda não implementado: cair no silêncio e usar memória sem avisar
        # daria a falsa impressão de que os dados estão sendo persistidos.
        raise NotImplementedError(
            "RBLSCAN_DATABASE_URL está definida, mas não há implementação de "
            "banco. Implemente SqlRepository em app/database/connection.py ou "
            "remova a variável para usar o repositório em memória.")
    return _repo
