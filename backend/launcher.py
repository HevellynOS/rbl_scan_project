"""
launcher.py — Ponto de entrada do RBL Scan empacotado.

Sobe o servidor em 127.0.0.1 e abre o navegador. O executável e o servidor são
a mesma coisa: fechar a janela do console encerra o scan em andamento.

    python launcher.py                 # roda do fonte
    python launcher.py --port 8123
    python launcher.py --no-browser    # útil para rodar como serviço
"""

from __future__ import annotations

import argparse
import os
import socket
import sys
import threading
import time
import webbrowser

import uvicorn

from app.core.config import app_dir, settings
from app.main import app


def free_port(preferred: int) -> int:
    """Usa a porta pedida se estiver livre; senão pega uma qualquer.
    Sem isso, abrir o programa duas vezes daria 'address already in use'
    e uma janela que fecha antes de dar para ler o erro."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(("127.0.0.1", preferred))
            return preferred
        except OSError:
            pass
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def banner(port: int) -> None:
    env_path = os.path.join(app_dir(), ".env")
    print()
    print("  RBL SCAN")
    print(f"  Interface .... http://127.0.0.1:{port}")
    print(f"  Configuração . {env_path}")
    if settings.dqs_key:
        print("  Chave DQS .... carregada")
    else:
        print("  Chave DQS .... AUSENTE — a zona ZEN da Spamhaus será pulada.")
        print("                 É a lista que separa 'sem reverso' de 'spam saindo'.")
        print(f"                 Preencha SPAMHAUS_DQS_KEY em {env_path}")
    print()
    print("  Feche esta janela para encerrar. Ctrl+C também serve.")
    print()


def open_later(port: int, delay: float = 1.2) -> None:
    def go():
        time.sleep(delay)
        webbrowser.open(f"http://127.0.0.1:{port}")

    threading.Thread(target=go, daemon=True).start()


def main() -> int:
    ap = argparse.ArgumentParser(description="RBL Scan")
    ap.add_argument("--port", type=int,
                    default=int(os.environ.get("RBLSCAN_PORT", "8000")))
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--no-browser", action="store_true")
    args = ap.parse_args()

    port = free_port(args.port) if args.host == "127.0.0.1" else args.port
    banner(port)

    if not args.no_browser:
        open_later(port)

    try:
        uvicorn.run(app, host=args.host, port=port, log_level="warning")
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"\n  Falhou ao subir o servidor: {e}\n")
        if getattr(sys, "frozen", False):
            input("  Pressione Enter para fechar.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
