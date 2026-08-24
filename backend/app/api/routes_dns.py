"""
app/api/routes_dns.py — Geração de zona reversa.

A auditoria de rDNS em si acontece dentro da varredura, porque depende de
consultar cada endereço do bloco. Aqui fica o que é exclusivo de DNS e não
depende de varrer: montar a zona a partir do bloco, do domínio e da separação
entre faixa de assinante e endereço de serviço.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.database.connection import get_repository
from app.services.dns_service import build_zone

router = APIRouter(prefix="/api", tags=["dns"])


class ZoneRequest(BaseModel):
    cidr: str
    domain: str
    ns: list[str] = Field(default_factory=list)
    email: str = ""
    prefixo_pool: str = "cliente"


@router.post("/zone")
async def make_zone(req: ZoneRequest):
    if not req.domain.strip():
        raise HTTPException(400, "Informe o domínio usado nos nomes reversos.")
    repo = get_repository()
    try:
        return build_zone(
            req.cidr, req.domain, req.ns, req.email,
            report=repo.get_scan(req.cidr),
            analysis=repo.get_analysis(),
            prefixo_pool=req.prefixo_pool or "cliente",
        )
    except ValueError as e:
        raise HTTPException(400, str(e))
