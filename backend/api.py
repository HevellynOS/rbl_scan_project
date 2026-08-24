"""
api.py — Backend do RBL Scan.

O scan roda aqui e nao no navegador por um motivo simples: navegador nao faz
consulta DNS arbitraria. Alem disso as RBLs precisam ver SEU resolver
recursivo, nao um resolver publico — senao respondem NXDOMAIN e o bloco
parece limpo.

    pip install -r requirements.txt
    cp .env.example .env      # e preencha a chave DQS
    uvicorn api:app --host 0.0.0.0 --port 8000
"""

from __future__ import annotations

import asyncio
import csv
import io
import ipaddress
import json
import os
import sys
import time

from fastapi import FastAPI, File, HTTPException, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from rbl_core import RBLS, ScanConfig, Scanner
from correlate import build_zone, correlate
from dns_report import build_pdf
from rsc_analyzer import analyze as analyze_rsc


def app_dir() -> str:
    """Pasta onde o usuário mexe: a do .exe quando empacotado, a do código
    quando rodando do fonte. É aqui que o .env é procurado — dentro do onefile
    o __file__ aponta para um temporário que some ao fechar."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def bundle_dir() -> str:
    """Pasta dos recursos embutidos (o frontend compilado)."""
    return getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))


# Carrega o .env antes de qualquer os.environ.get() abaixo.
# Variáveis já exportadas no shell têm precedência sobre o arquivo.
try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(app_dir(), ".env"))
except ImportError:
    pass

app = FastAPI(title="RBL Scan", version="1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get("RBLSCAN_ORIGINS", "http://localhost:5173").split(","),
    allow_methods=["*"],
    allow_headers=["*"],
)

MAX_ADDRESSES = int(os.environ.get("RBLSCAN_MAX", "4096"))
DQS_KEY = os.environ.get("SPAMHAUS_DQS_KEY")
DEFAULT_RESOLVER = os.environ.get("RBLSCAN_RESOLVER")

# Guarda o ultimo relatorio por rede, para exportar sem revarrer.
_reports: dict[str, dict] = {}


class ScanRequest(BaseModel):
    cidr: str
    profile: str = Field(default="core", pattern="^(core|full)$")
    lists: list[str] | None = None
    resolver: str | None = None
    concurrency: int = Field(default=40, ge=1, le=200)
    per_zone: int = Field(default=8, ge=1, le=50)
    timeout: float = Field(default=3.0, ge=0.5, le=15)
    check_rdns: bool = True


def validate_cidr(cidr: str) -> ipaddress.IPv4Network:
    try:
        net = ipaddress.ip_network(cidr.strip(), strict=False)
    except ValueError as e:
        raise HTTPException(400, f"CIDR inválido: {e}")
    if net.version != 4:
        raise HTTPException(400, "Só IPv4 — enumerar IPv6 é inviável. "
                                 "Consulte apenas os /128 em uso.")
    if net.num_addresses > MAX_ADDRESSES:
        raise HTTPException(
            400, f"{net} tem {net.num_addresses} endereços (limite {MAX_ADDRESSES}). "
                 f"Varra em pedaços menores: multi-RBL nesse volume viola o uso "
                 f"justo das listas públicas.")
    return net


def build_config(req: ScanRequest) -> ScanConfig:
    return ScanConfig(
        cidr=req.cidr, profile=req.profile, lists=req.lists,
        dqs_key=DQS_KEY, resolver=req.resolver or DEFAULT_RESOLVER,
        concurrency=req.concurrency, per_zone=req.per_zone,
        timeout=req.timeout, check_rdns=req.check_rdns,
    )


@app.get("/api/health")
async def health():
    return {"ok": True, "dqs_key": bool(DQS_KEY),
            "resolver": DEFAULT_RESOLVER, "max_addresses": MAX_ADDRESSES}


@app.get("/api/rbls")
async def list_rbls():
    return [{"name": r.name, "zone": r.zone, "severity": r.severity,
             "profile": r.profile, "note": r.note, "delist": r.delist,
             "needs_key": r.needs_key, "needs_registration": r.needs_registration}
            for r in RBLS]


@app.post("/api/verify-zones")
async def verify_zones(req: ScanRequest):
    """Testa 127.0.0.2 em cada lista. Rode isto antes do primeiro scan:
    lista bloqueada responde NXDOMAIN e o bloco parece limpo."""
    cfg = build_config(req)
    cfg.cidr = "127.0.0.2/32"
    scanner = Scanner(cfg)
    return {"zones": await scanner.verify_zones(), "warnings": scanner.warnings}


@app.websocket("/ws/scan")
async def ws_scan(ws: WebSocket):
    await ws.accept()
    try:
        payload = await ws.receive_json()
        req = ScanRequest(**payload)
        net = validate_cidr(req.cidr)
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
                _reports[str(net)] = event["report"]
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


@app.get("/api/report/{cidr:path}")
async def get_report(cidr: str):
    report = _reports.get(cidr)
    if not report:
        raise HTTPException(404, "Nenhum relatório em memória para esse bloco. "
                                 "Rode a varredura primeiro.")
    return report


@app.get("/api/export/{fmt}/{cidr:path}")
async def export(fmt: str, cidr: str):
    report = _reports.get(cidr)
    if not report:
        raise HTTPException(404, "Nenhum relatório em memória para esse bloco.")
    slug = cidr.replace("/", "_")

    if fmt == "json":
        return StreamingResponse(
            io.BytesIO(json.dumps(report, indent=2, ensure_ascii=False).encode()),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="rbl_{slug}.json"'})

    if fmt == "csv":
        buf = io.StringIO()
        w = csv.writer(buf)
        # Colunas separadas: "sem PTR" e "PTR generico" tem correcoes opostas
        # e precisam ser filtraveis uma sem a outra.
        w.writerow(["ip", "classificacao", "listas", "motivos", "ptr",
                    "ptr_status", "ptr_ausente", "ptr_generico", "fcrdns"])
        for r in report["rows"]:
            st = r.get("ptr_status", "")
            w.writerow([r["ip"], r["classification"], ";".join(r["lists"]),
                        ";".join(r["reasons"]), r["ptr"], st,
                        "sim" if st == "ausente" else "nao",
                        "sim" if st == "generico" else "nao",
                        "" if r["fcrdns"] is None else ("sim" if r["fcrdns"] else "nao")])
        return StreamingResponse(
            io.BytesIO(buf.getvalue().encode("utf-8-sig")),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="rbl_{slug}.csv"'})

    raise HTTPException(400, "Formato deve ser json ou csv.")




# ---------------------------------------------------------------------------
# Análise de configuração (.rsc)
# ---------------------------------------------------------------------------
MAX_RSC_BYTES = int(os.environ.get("RBLSCAN_MAX_RSC", str(8 * 1024 * 1024)))

# Último relatório de análise, para exportar sem reenviar os arquivos.
_analysis: dict = {}


@app.post("/api/analyze")
async def analyze_configs(files: list[UploadFile] = File(...)):
    """Recebe um ou mais exports .rsc e devolve achados + script + relatório."""
    if not files:
        raise HTTPException(400, "Envie ao menos um arquivo .rsc")
    if len(files) > 10:
        raise HTTPException(400, "Máximo de 10 arquivos por análise.")

    parsed: list[tuple[str, str]] = []
    for f in files:
        raw = await f.read()
        if len(raw) > MAX_RSC_BYTES:
            raise HTTPException(
                400, f"{f.filename} tem {len(raw)//1024} KB (limite "
                     f"{MAX_RSC_BYTES//1024} KB).")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = raw.decode("latin-1", errors="replace")
        from vrp_parser import parece_vrp
        rsc = "/ip " in text or "/interface" in text
        if not rsc and not parece_vrp(text):
            raise HTTPException(
                400, f"{f.filename} não parece um export de configuração "
                     f"reconhecido. RouterOS: /export file=nome. "
                     f"Huawei VRP: display current-configuration.")
        parsed.append((f.filename or "config.rsc", text))

    result = analyze_rsc(parsed)
    _analysis.clear()
    _analysis.update(result)
    return result


@app.get("/api/analysis/export/{fmt}")
async def export_analysis(fmt: str):
    if not _analysis:
        raise HTTPException(404, "Nenhuma análise em memória. Envie os arquivos "
                                 "primeiro.")
    stamp = time.strftime("%Y%m%d")
    if fmt == "rsc":
        # Extensao .rsc so faz sentido quando tudo e RouterOS. Com Huawei no
        # lote, .txt evita que alguem importe o arquivo no equipamento errado.
        fabricantes = {d.get("vendor") for d in _analysis.get("devices", [])}
        ext = "rsc" if fabricantes == {"MikroTik"} else "txt"
        return StreamingResponse(
            io.BytesIO(_analysis["rsc"].encode("utf-8")),
            media_type="text/plain",
            headers={"Content-Disposition":
                     f'attachment; filename="correcao-rbl-{stamp}.{ext}"'})
    if fmt == "md":
        return StreamingResponse(
            io.BytesIO(_analysis["report"].encode("utf-8")),
            media_type="text/markdown",
            headers={"Content-Disposition":
                     f'attachment; filename="analise-rbl-{stamp}.md"'})
    if fmt == "json":
        return StreamingResponse(
            io.BytesIO(json.dumps(_analysis, indent=2,
                                  ensure_ascii=False).encode("utf-8")),
            media_type="application/json",
            headers={"Content-Disposition":
                     f'attachment; filename="analise-rbl-{stamp}.json"'})
    raise HTTPException(400, "Formato deve ser rsc, md ou json.")


# ---------------------------------------------------------------------------
# Cruzamento varredura x configuração, e geração de zona reversa
# ---------------------------------------------------------------------------
class ZoneRequest(BaseModel):
    cidr: str
    domain: str
    ns: list[str] = Field(default_factory=list)
    email: str = ""
    prefixo_pool: str = "cliente"


@app.get("/api/correlate/{cidr:path}")
async def get_correlation(cidr: str):
    """Junta as duas metades: quais IPs estão listados e quem está atrás deles."""
    report = _reports.get(cidr.strip())
    if not report:
        raise HTTPException(404, "Nenhuma varredura em memória para esse bloco.")
    if not _analysis:
        raise HTTPException(
            409, "Nenhuma análise de configuração em memória. Envie os arquivos "
                 ".rsc na aba de análise para cruzar os emissores com as faixas "
                 "de CGNAT.")
    return correlate(report, _analysis)


@app.post("/api/zone")
async def make_zone(req: ZoneRequest):
    if not req.domain.strip():
        raise HTTPException(400, "Informe o domínio usado nos nomes reversos.")
    try:
        return build_zone(
            req.cidr, req.domain, req.ns, req.email,
            report=_reports.get(req.cidr.strip()),
            analysis=_analysis or None,
            prefixo_pool=req.prefixo_pool or "cliente",
        )
    except ValueError as e:
        raise HTTPException(400, str(e))



class DnsReportRequest(BaseModel):
    cidr: str
    cliente: str = ""
    preparado_por: str = ""
    observacoes: str = ""
    dominio_exemplo: str = ""


@app.post("/api/dns-report")
async def dns_report(req: DnsReportRequest):
    """Relatório executivo de DNS reverso, em PDF, para terceiros.

    Recebe só o CIDR: o conteúdo sai do relatório já em memória, para que o
    PDF nunca possa ser montado com dados que o operador não viu na tela.
    """
    report = _reports.get(req.cidr.strip())
    if not report:
        raise HTTPException(404, "Nenhuma varredura em memória para esse bloco. "
                                 "Rode a varredura antes de gerar o relatório.")
    if not report.get("rdns", {}).get("audited"):
        raise HTTPException(
            409, "A varredura foi feita sem auditoria de rDNS. Marque "
                 "'Auditar rDNS junto' em Mais opções e varra novamente.")
    try:
        pdf = build_pdf(report, cliente=req.cliente,
                        preparado_por=req.preparado_por,
                        observacoes=req.observacoes,
                        dominio_exemplo=req.dominio_exemplo)
    except Exception as e:
        raise HTTPException(500, f"Falha ao gerar o PDF: {e}")

    slug = req.cidr.strip().replace("/", "_").replace(".", "-")
    stamp = time.strftime("%Y%m%d")
    return StreamingResponse(
        io.BytesIO(pdf), media_type="application/pdf",
        headers={"Content-Disposition":
                 f'attachment; filename="dns-{slug}-{stamp}.pdf"'})



# ---------------------------------------------------------------------------
# Interface embutida
# ---------------------------------------------------------------------------
# Registrado por último de propósito: as rotas /api e /ws acima têm precedência,
# e este mount só atende o que sobrar. Só existe quando o frontend foi compilado
# para backend/webui — rodando em desenvolvimento, use o servidor do Vite.
_WEBUI = os.path.join(bundle_dir(), "webui")

if os.path.isdir(_WEBUI):
    from fastapi.staticfiles import StaticFiles

    app.mount("/", StaticFiles(directory=_WEBUI, html=True), name="webui")
