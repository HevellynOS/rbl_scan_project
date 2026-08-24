"""
app/api/routes_rbl.py — Varredura de blocos e cruzamento com a configuração.

Tudo que gira em torno do bloco IP e das listas de reputação. A varredura é
WebSocket porque um /23 leva minutos: sem streaming a interface ficaria muda
até o fim.
"""

from __future__ import annotations

import csv
import io
import json

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from app.core.config import settings
from app.core.security import validate_cidr
from app.database.connection import get_repository
from app.services.dns_service import correlate
from app.services.rbl_service import RBLS, ScanConfig, Scanner

router = APIRouter(prefix="/api", tags=["rbl"])


class ScanRequest(BaseModel):
    cidr: str
    profile: str = Field(default="core", pattern="^(core|full)$")
    lists: list[str] | None = None
    resolver: str | None = None
    concurrency: int = Field(default=40, ge=1, le=200)
    per_zone: int = Field(default=8, ge=1, le=50)
    timeout: float = Field(default=3.0, ge=0.5, le=15)
    check_rdns: bool = True


def build_config(req: ScanRequest) -> ScanConfig:
    return ScanConfig(
        cidr=req.cidr, profile=req.profile, lists=req.lists,
        dqs_key=settings.dqs_key,
        resolver=req.resolver or settings.resolver,
        concurrency=req.concurrency, per_zone=req.per_zone,
        timeout=req.timeout, check_rdns=req.check_rdns,
    )


@router.get("/rbls")
async def list_rbls():
    return [{"name": r.name, "zone": r.zone, "severity": r.severity,
             "profile": r.profile, "note": r.note, "delist": r.delist,
             "needs_key": r.needs_key, "needs_registration": r.needs_registration}
            for r in RBLS]


@router.post("/verify-zones")
async def verify_zones(req: ScanRequest):
    """Consulta a entrada de teste 127.0.0.2 em cada lista.

    Rode antes do primeiro scan: lista bloqueada responde NXDOMAIN, e o bloco
    inteiro sairia pintado de 'limpo'.
    """
    cfg = build_config(req)
    cfg.cidr = "127.0.0.2/32"
    scanner = Scanner(cfg)
    return {"zones": await scanner.verify_zones(), "warnings": scanner.warnings}


@router.get("/report/{cidr:path}")
async def get_report(cidr: str):
    report = get_repository().get_scan(cidr)
    if not report:
        raise HTTPException(404, "Nenhuma varredura em memória para esse bloco. "
                                 "Rode a varredura primeiro.")
    return report


@router.get("/scans")
async def list_scans():
    """Varreduras guardadas, mais recentes primeiro."""
    return get_repository().list_scans()


@router.get("/history/{cidr:path}")
async def scan_history(cidr: str):
    """Série de varreduras do mesmo bloco.

    É o que permite provar remediação: sem antes e depois, um pedido de
    remoção não tem evidência de que a causa foi corrigida.
    """
    return get_repository().scan_history(cidr)


@router.get("/correlate/{cidr:path}")
async def get_correlation(cidr: str):
    """Junta as duas metades: quais IPs estão listados e quem está atrás deles."""
    repo = get_repository()
    report = repo.get_scan(cidr)
    if not report:
        raise HTTPException(404, "Nenhuma varredura em memória para esse bloco.")
    analysis = repo.get_analysis()
    if not analysis:
        raise HTTPException(
            409, "Nenhuma análise de configuração em memória. Envie os arquivos "
                 "de configuração na aba de análise para cruzar os emissores "
                 "com as faixas de CGNAT.")
    return correlate(report, analysis)


@router.get("/export/{fmt}/{cidr:path}")
async def export(fmt: str, cidr: str):
    report = get_repository().get_scan(cidr)
    if not report:
        raise HTTPException(404, "Nenhuma varredura em memória para esse bloco.")
    slug = cidr.replace("/", "_")

    if fmt == "json":
        return StreamingResponse(
            io.BytesIO(json.dumps(report, indent=2, ensure_ascii=False).encode()),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="rbl_{slug}.json"'})

    if fmt == "csv":
        buf = io.StringIO()
        w = csv.writer(buf)
        # Colunas separadas: "sem PTR" e "PTR genérico" têm correções opostas
        # e precisam ser filtráveis uma sem a outra.
        w.writerow(["ip", "classificacao", "listas", "motivos", "ptr",
                    "ptr_status", "ptr_ausente", "ptr_generico", "fcrdns"])
        for r in report["rows"]:
            st = r.get("ptr_status", "")
            w.writerow([r["ip"], r["classification"], ";".join(r["lists"]),
                        ";".join(r["reasons"]), r["ptr"], st,
                        "sim" if st == "ausente" else "nao",
                        "sim" if st == "generico" else "nao",
                        "" if r["fcrdns"] is None else
                        ("sim" if r["fcrdns"] else "nao")])
        return StreamingResponse(
            io.BytesIO(buf.getvalue().encode("utf-8-sig")),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="rbl_{slug}.csv"'})

    raise HTTPException(400, "Formato deve ser json ou csv.")


async def ws_scan(ws: WebSocket) -> None:
    """Varredura com streaming. Registrada em main.py, fora do prefixo /api."""
    await ws.accept()
    try:
        payload = await ws.receive_json()
        req = ScanRequest(**payload)
        validate_cidr(req.cidr)
    except HTTPException as e:
        await ws.send_json({"type": "error", "message": e.detail})
        await ws.close()
        return
    except Exception as e:
        await ws.send_json({"type": "error", "message": f"Requisição inválida: {e}"})
        await ws.close()
        return

    scanner = Scanner(build_config(req))
    try:
        async for event in scanner.run():
            await ws.send_json(event)
            if event["type"] == "done":
                get_repository().save_scan(event["report"])
    except WebSocketDisconnect:
        scanner.cancelled = True
    except Exception as e:
        try:
            await ws.send_json({"type": "error", "message": str(e)})
        except Exception:
            pass
    finally:
        try:
            await ws.close()
        except Exception:
            pass
