"""
app/api/routes_reports.py — Análise de configuração e relatórios.

Reúne o que produz documento: a auditoria dos arquivos de configuração, o
script de correção, a explicação em markdown e o relatório executivo em PDF.
"""

from __future__ import annotations

import io
import json
import time

from fastapi import APIRouter, File, HTTPException, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from app.analyzers.rsc_analyzer import analyze as analyze_configs
from app.core.config import settings
from app.core.security import assert_safe_for_external, validate_config_file
from app.database.connection import get_repository
from app.services.report_service import build_pdf

router = APIRouter(prefix="/api", tags=["reports"])


@router.post("/analyze")
async def analyze(files: list[UploadFile] = File(...)):
    """Recebe exports de configuração e devolve achados, script e explicação.

    Reconhece MikroTik RouterOS e Huawei VRP pelo conteúdo, não pela extensão.
    """
    if not files:
        raise HTTPException(400, "Envie ao menos um arquivo de configuração.")
    if len(files) > settings.max_files:
        raise HTTPException(
            400, f"Máximo de {settings.max_files} arquivos por análise.")

    parsed: list[tuple[str, str]] = []
    for f in files:
        raw = await f.read()
        text = validate_config_file(f.filename or "config", raw)
        parsed.append((f.filename or "config", text))

    result = analyze_configs(parsed)
    get_repository().save_analysis(result)
    return result


@router.get("/analysis/export/{fmt}")
async def export_analysis(fmt: str):
    analysis = get_repository().get_analysis()
    if not analysis:
        raise HTTPException(404, "Nenhuma análise em memória. Envie os arquivos "
                                 "primeiro.")
    stamp = time.strftime("%Y%m%d")

    if fmt == "rsc":
        # Extensão .rsc só faz sentido quando tudo é RouterOS. Com Huawei no
        # lote, .txt evita que alguém importe o arquivo no equipamento errado.
        fabricantes = {d.get("vendor") for d in analysis.get("devices", [])}
        ext = "rsc" if fabricantes == {"MikroTik"} else "txt"
        return StreamingResponse(
            io.BytesIO(analysis["rsc"].encode("utf-8")),
            media_type="text/plain",
            headers={"Content-Disposition":
                     f'attachment; filename="correcao-rbl-{stamp}.{ext}"'})

    if fmt == "md":
        return StreamingResponse(
            io.BytesIO(analysis["report"].encode("utf-8")),
            media_type="text/markdown",
            headers={"Content-Disposition":
                     f'attachment; filename="analise-rbl-{stamp}.md"'})

    if fmt == "json":
        return StreamingResponse(
            io.BytesIO(json.dumps(analysis, indent=2,
                                  ensure_ascii=False).encode("utf-8")),
            media_type="application/json",
            headers={"Content-Disposition":
                     f'attachment; filename="analise-rbl-{stamp}.json"'})

    raise HTTPException(400, "Formato deve ser rsc, md ou json.")


class DnsReportRequest(BaseModel):
    cidr: str
    cliente: str = ""
    preparado_por: str = ""
    observacoes: str = ""
    dominio_exemplo: str = ""


@router.post("/dns-report")
async def dns_report(req: DnsReportRequest):
    """Relatório executivo de DNS reverso, em PDF, para terceiros.

    Recebe só o CIDR: o conteúdo sai do relatório já guardado, para que o PDF
    nunca possa ser montado com dados que o operador não viu na tela.
    """
    report = get_repository().get_scan(req.cidr)
    if not report:
        raise HTTPException(404, "Nenhuma varredura em memória para esse bloco. "
                                 "Rode a varredura antes de gerar o relatório.")
    if not report.get("rdns", {}).get("audited"):
        raise HTTPException(
            409, "A varredura foi feita sem auditoria de rDNS. Marque "
                 "'Auditar rDNS junto' em Mais opções e varra novamente.")

    # O texto do usuário é o único caminho por onde dado interno pode entrar
    # num documento que sai da empresa. O resto do PDF vem de campos
    # controlados.
    assert_safe_for_external(
        " ".join([req.cliente, req.preparado_por, req.observacoes,
                  req.dominio_exemplo]),
        "relatório")

    try:
        pdf = build_pdf(report, cliente=req.cliente,
                        preparado_por=req.preparado_por,
                        observacoes=req.observacoes,
                        dominio_exemplo=req.dominio_exemplo)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Falha ao gerar o PDF: {e}")

    slug = req.cidr.strip().replace("/", "_").replace(".", "-")
    stamp = time.strftime("%Y%m%d")
    return StreamingResponse(
        io.BytesIO(pdf), media_type="application/pdf",
        headers={"Content-Disposition":
                 f'attachment; filename="dns-{slug}-{stamp}.pdf"'})
