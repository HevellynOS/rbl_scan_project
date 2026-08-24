"""
app/core/config.py — Configuração central.

Único ponto do backend que lê variáveis de ambiente. Qualquer módulo que
precise de um ajuste importa `settings` daqui, para que não haja
os.environ.get() espalhado e para que o .env seja carregado uma vez só.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from functools import lru_cache


def app_dir() -> str:
    """Pasta onde o usuário mexe: a do .exe quando empacotado, a do backend
    quando rodando do fonte. É aqui que o .env é procurado — dentro do onefile
    o __file__ aponta para um temporário que some ao fechar."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    # .../backend/app/core/config.py -> .../backend
    return os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))))


def bundle_dir() -> str:
    """Pasta dos recursos embutidos (frontend compilado, logo)."""
    if getattr(sys, "frozen", False):
        return getattr(sys, "_MEIPASS", app_dir())
    return app_dir()


def assets_dir() -> str:
    return os.path.join(bundle_dir(), "assets")


def _load_env() -> None:
    try:
        from dotenv import load_dotenv
        load_dotenv(os.path.join(app_dir(), ".env"))
    except ImportError:
        # Sem python-dotenv a aplicação sobe lendo só o ambiente do sistema,
        # que é o caso normal em container.
        pass


@dataclass(frozen=True)
class Settings:
    # Spamhaus DQS. Sem ela a zona ZEN é pulada, e é a lista mais relevante.
    dqs_key: str | None = None
    # Resolver recursivo próprio. Resolver público é recusado pelas DNSBLs.
    resolver: str | None = None
    # Teto de endereços por varredura: um /24 no perfil core já são ~2.000
    # consultas DNS, e listas públicas bloqueiam resolver abusivo.
    max_addresses: int = 4096
    max_rsc_bytes: int = 8 * 1024 * 1024
    max_files: int = 10
    origins: list[str] = field(default_factory=lambda: ["http://localhost:5173"])
    # URL do banco. Vazio mantém o repositório em memória.
    database_url: str = ""

    @property
    def has_database(self) -> bool:
        return bool(self.database_url.strip())


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    _load_env()
    origins = [o.strip() for o in
               os.environ.get("RBLSCAN_ORIGINS", "http://localhost:5173").split(",")
               if o.strip()]
    return Settings(
        dqs_key=os.environ.get("SPAMHAUS_DQS_KEY") or None,
        resolver=os.environ.get("RBLSCAN_RESOLVER") or None,
        max_addresses=int(os.environ.get("RBLSCAN_MAX", "4096")),
        max_rsc_bytes=int(os.environ.get("RBLSCAN_MAX_RSC", str(8 * 1024 * 1024))),
        max_files=int(os.environ.get("RBLSCAN_MAX_FILES", "10")),
        origins=origins,
        database_url=os.environ.get("RBLSCAN_DATABASE_URL", ""),
    )


settings = get_settings()
