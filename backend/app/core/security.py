"""
app/core/security.py — Validação de entrada e política de dado sensível.

Duas responsabilidades, ambas de segurança e ambas antes concentradas na
camada de rotas:

1. VALIDAR O QUE ENTRA. Bloco CIDR dentro do teto, arquivo de configuração
   plausível e dentro do tamanho. Recusar cedo evita que uma varredura de /8
   consuma a cota de todas as RBLs do NOC.

2. CONTROLAR O QUE SAI. O relatório em PDF é feito para deixar a empresa, e
   por isso existe uma lista explícita do que nunca pode entrar nele. A regra
   está aqui, num só lugar, para que uma alteração futura em qualquer módulo
   tenha de passar por esta revisão.
"""

from __future__ import annotations

import ipaddress
import re

from fastapi import HTTPException

from app.core.config import settings

# --------------------------------------------------------------------------
# 1. Entrada
# --------------------------------------------------------------------------
def validate_cidr(cidr: str) -> ipaddress.IPv4Network:
    try:
        net = ipaddress.ip_network(cidr.strip(), strict=False)
    except ValueError as e:
        raise HTTPException(400, f"CIDR inválido: {e}")
    if net.version != 4:
        raise HTTPException(
            400, "Só IPv4. Enumerar IPv6 é inviável: consulte apenas os /128 "
                 "efetivamente em uso.")
    if net.num_addresses > settings.max_addresses:
        raise HTTPException(
            400, f"{net} tem {net.num_addresses} endereços (limite "
                 f"{settings.max_addresses}). Varra em pedaços menores: "
                 f"multi-RBL nesse volume viola o uso justo das listas.")
    return net


SINAIS_ROUTEROS = ("/ip ", "/interface", "/system ", "/routing ")


def validate_config_file(filename: str, raw: bytes) -> str:
    """Decodifica e confirma que o conteúdo parece um export de configuração."""
    if len(raw) > settings.max_rsc_bytes:
        raise HTTPException(
            400, f"{filename} tem {len(raw) // 1024} KB (limite "
                 f"{settings.max_rsc_bytes // 1024} KB).")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        # Export do VRP às vezes chega em latin-1 dependendo do terminal.
        text = raw.decode("latin-1", errors="replace")

    from app.parsers.vrp_parser import parece_vrp
    if not any(s in text for s in SINAIS_ROUTEROS) and not parece_vrp(text):
        raise HTTPException(
            400, f"{filename} não parece um export de configuração reconhecido. "
                 f"RouterOS: /export file=nome. "
                 f"Huawei VRP: display current-configuration.")
    return text


# --------------------------------------------------------------------------
# 2. Saída — o que nunca pode ir para um documento externo
# --------------------------------------------------------------------------
# Cada padrão descreve algo que, num relatório entregue a parceiro, provedor de
# DNS ou órgão, expõe a rede auditada ou o cliente final.
PADROES_SENSIVEIS: list[tuple[str, str]] = [
    (r"\b(?:10|127)\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "endereço privado (RFC1918)"),
    (r"\b192\.168\.\d{1,3}\.\d{1,3}\b", "endereço privado (RFC1918)"),
    (r"\b172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b", "endereço privado"),
    (r"\b100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3}\b",
     "faixa de CGNAT (RFC6598)"),
    (r"\bCCR\d{4}\b|\bRB\d{3,4}\b", "modelo de equipamento MikroTik"),
    (r"\bNE\d{2,4}[A-Z]?\b|\bATN\d+\b", "modelo de equipamento Huawei"),
    (r"\bRouterOS\s+\d|\bV\d{3}R\d{3}C\d{2}", "versão de sistema do equipamento"),
    (r"\bnetmap\b|\bnat instance\b|\bsrc-nat\b", "regra de tradução interna"),
    (r"\bsnmp-agent community\b|\bcommunity\s+(?:read|write)\b",
     "comunidade SNMP"),
    (r"\bcipher\s+\S{8,}", "credencial cifrada"),
    (r"\bssh-rsa\s+[A-Za-z0-9+/]{40,}", "chave pública"),
    (r"[a-z0-9]{20,}\.(?:zen|dq)\.spamhaus\.net", "chave DQS da Spamhaus"),
]


def scan_sensitive(texto: str) -> list[tuple[str, str]]:
    """Retorna (trecho, motivo) para cada ocorrência encontrada.

    Usado como rede de segurança na geração do PDF: se um campo novo trouxer
    dado interno por descuido, isso aparece antes de o documento sair.
    """
    achados: list[tuple[str, str]] = []
    vistos: set[str] = set()
    for padrao, motivo in PADROES_SENSIVEIS:
        for m in re.finditer(padrao, texto, re.I):
            t = m.group(0)
            if t not in vistos:
                vistos.add(t)
                achados.append((t, motivo))
    return achados


def assert_safe_for_external(texto: str, contexto: str = "documento") -> None:
    """Levanta erro se houver dado que não deve sair da empresa.

    Falhar é preferível a entregar: um PDF com faixa de CGNAT ou modelo de
    equipamento vira mapa de rede na mão de terceiro.
    """
    achados = scan_sensitive(texto)
    if achados:
        amostra = "; ".join(f"{t} ({m})" for t, m in achados[:5])
        raise HTTPException(
            500, f"Geração de {contexto} interrompida: foi detectado conteúdo "
                 f"sensível que não deve sair da empresa ({amostra}). "
                 f"Isto é uma trava de segurança — reporte para correção.")
