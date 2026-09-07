"""
app/api/routes_dns.py — Geração de zona reversa.

A auditoria de rDNS em si acontece dentro da varredura, porque depende de
consultar cada endereço do bloco. Aqui fica o que é exclusivo de DNS e não
depende de varrer: montar a zona a partir do bloco, do domínio e da separação
entre faixa de assinante e endereço de serviço.
"""

from __future__ import annotations

from fastapi import APIRouter, File, HTTPException, UploadFile
from pydantic import BaseModel, Field

from app.analyzers.dns_analyzer import analyze_dns
from app.core.config import settings
from app.database.connection import get_repository
from app.services.delegation_service import (
    ChainConfig,
    check_chain,
    extrai_dominios,
)
from app.services.dns_collect import instrucoes
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


@router.get("/dns/collect-help")
async def collect_help():
    """Instruções e o comando de coleta para colar no servidor por SSH."""
    return instrucoes()


@router.post("/dns/validate")
async def validate_dns(files: list[UploadFile] = File(...)):
    """Valida a configuração do servidor de DNS a partir dos arquivos de zona.

    A varredura enxerga o resultado das consultas; aqui a auditoria é sobre o
    arquivo, o que permite apontar a linha onde o erro foi escrito e pegá-lo
    antes de chegar na rede.

    Envie junto a zona reversa E a direta: sem as duas não há como verificar a
    correspondência de ida e volta, que é onde o problema costuma estar.
    """
    if not files:
        raise HTTPException(400, "Envie ao menos um arquivo de zona.")
    if len(files) > 30:
        raise HTTPException(400, "Máximo de 30 arquivos por validação.")

    parsed: list[tuple[str, str]] = []
    for f in files:
        raw = await f.read()
        if len(raw) > settings.max_rsc_bytes:
            raise HTTPException(
                400, f"{f.filename} tem {len(raw) // 1024} KB (limite "
                     f"{settings.max_rsc_bytes // 1024} KB).")
        try:
            texto = raw.decode("utf-8")
        except UnicodeDecodeError:
            texto = raw.decode("latin-1", errors="replace")
        parsed.append((f.filename or "zona", texto))

    resultado = analyze_dns(parsed)
    if not resultado["arquivos"] and not resultado["named_conf"]:
        raise HTTPException(
            400, "Nenhum arquivo reconhecido como zona DNS ou named.conf. "
                 "Envie os arquivos de /etc/bind ou a saída de "
                 "'pdnsutil list-zone <zona>'.")
    return resultado


class ChainRequest(BaseModel):
    """Domínios e zonas a seguir. Vem preenchido a partir da validação de
    arquivos, mas pode ser editado: um provedor costuma ter mais de um
    domínio em uso nos PTR, e nem todos aparecem nos arquivos enviados."""
    dominios: list[str] = Field(default_factory=list)
    zonas_reversas: list[str] = Field(default_factory=list)
    servidores_locais: list[str] = Field(default_factory=list)
    amostras: dict[str, list[dict]] = Field(default_factory=dict)
    resolver: str | None = None


@router.post("/dns/chain")
async def dns_chain(req: ChainRequest):
    """Segue a cadeia de delegação ao vivo, incluindo DNS de terceiros.

    A validação por arquivo enxerga só o servidor de quem enviou. Aqui a
    consulta é feita contra a hierarquia real: para onde o domínio está
    delegado, e se os servidores do provedor estão nessa lista.

    É a peça que faltava: registro A correto num servidor para o qual o
    domínio não está delegado é registro invisível.
    """
    if not req.dominios and not req.zonas_reversas:
        raise HTTPException(
            400, "Informe ao menos um domínio ou uma zona reversa.")
    if len(req.dominios) + len(req.zonas_reversas) > 40:
        raise HTTPException(400, "Máximo de 40 nomes por verificação.")

    dominios = {d: req.amostras.get(d, []) for d in req.dominios}
    cfg = ChainConfig(resolver=req.resolver or settings.resolver)
    try:
        return await check_chain(dominios, req.zonas_reversas,
                                 req.servidores_locais, cfg)
    except Exception as e:
        raise HTTPException(502, f"Falha ao consultar a hierarquia: {e}")


@router.post("/dns/chain-from-analysis")
async def chain_from_analysis(files: list[UploadFile] = File(...)):
    """Atalho: valida os arquivos e já segue a cadeia dos domínios achados."""
    from app.analyzers.dns_analyzer import analyze_dns

    parsed: list[tuple[str, str]] = []
    for f in files:
        raw = await f.read()
        try:
            texto = raw.decode("utf-8")
        except UnicodeDecodeError:
            texto = raw.decode("latin-1", errors="replace")
        parsed.append((f.filename or "zona", texto))

    analise = analyze_dns(parsed)
    dominios = extrai_dominios(analise)
    reversas = [a["origin"] for a in analise["arquivos"]
                if a["reversa"] and a["origin"]]
    locais = []
    for c in analise.get("named_conf", []):
        for z in c.get("zonas", []):
            locais.append(z.get("name", ""))
    cfg = ChainConfig(resolver=settings.resolver)
    cadeia = await check_chain(dominios, reversas, [], cfg)
    return {"analise": analise, "cadeia": cadeia}
