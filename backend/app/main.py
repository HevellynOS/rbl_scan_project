"""
app/main.py — Aplicação FastAPI.

Monta as rotas, o WebSocket e, quando existe build do frontend, a interface
embutida. As regras de negócio ficam em app/services e app/analyzers; aqui só
há composição.

    cd backend
    cp .env.example .env        # e preencha a chave DQS
    uvicorn app.main:app --host 0.0.0.0 --port 8000

O scan roda no backend e não no navegador por um motivo simples: navegador não
faz consulta DNS arbitrária. E mesmo que fizesse, as RBLs precisam ver o seu
resolver recursivo — resolver público é recusado e responde NXDOMAIN, o que
faria o bloco parecer limpo.
"""

from __future__ import annotations

import os

from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.api import routes_dns, routes_rbl, routes_reports
from app.core.config import bundle_dir, settings

app = FastAPI(title="RBL Scan", version=__version__)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.origins,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(routes_rbl.router)
app.include_router(routes_dns.router)
app.include_router(routes_reports.router)


@app.websocket("/ws/scan")
async def ws_scan(ws: WebSocket):
    await routes_rbl.ws_scan(ws)


@app.get("/api/health")
async def health():
    return {
        "ok": True,
        "version": __version__,
        "dqs_key": bool(settings.dqs_key),
        "resolver": settings.resolver,
        "max_addresses": settings.max_addresses,
        "database": "configurado" if settings.has_database else "memória",
    }


# ---------------------------------------------------------------------------
# Interface embutida
# ---------------------------------------------------------------------------
# Montada por último de propósito: as rotas /api e /ws acima têm precedência e
# este mount só atende o que sobrar. Só existe quando o frontend foi compilado
# para backend/webui; em desenvolvimento, use o servidor do Vite.
_WEBUI = os.path.join(bundle_dir(), "webui")

if os.path.isdir(_WEBUI):
    from fastapi.staticfiles import StaticFiles

    app.mount("/", StaticFiles(directory=_WEBUI, html=True), name="webui")
