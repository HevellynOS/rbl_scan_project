# -*- mode: python ; coding: utf-8 -*-
"""
Spec do PyInstaller para o RBL Scan.

    pyinstaller rblscan.spec --noconfirm

Gera dist/RBLScan.exe — arquivo único, com a interface web embutida.
Rode isto NO WINDOWS: o PyInstaller não faz compilação cruzada, ele empacota
para o sistema onde está rodando.
"""

from PyInstaller.utils.hooks import collect_submodules, collect_data_files

# O uvicorn carrega loops, protocolos e o lifespan por import dinâmico.
# O PyInstaller não enxerga isso na análise estática — sem os hiddenimports
# abaixo o .exe compila e quebra só na hora de subir o servidor.
hidden = (
    collect_submodules("uvicorn")
    + collect_submodules("dns")
    + collect_submodules("reportlab")
    + collect_submodules("app")
    + [
        "uvicorn.logging",
        "uvicorn.loops.auto",
        "uvicorn.loops.asyncio",
        "uvicorn.protocols.http.auto",
        "uvicorn.protocols.http.h11_impl",
        "uvicorn.protocols.websockets.auto",
        "uvicorn.protocols.websockets.websockets_impl",
        "uvicorn.lifespan.on",
        "uvicorn.lifespan.off",
        "websockets.legacy",
        "websockets.legacy.server",
        "anyio._backends._asyncio",
        "email.mime.text",
        "app",
        "app.main",
        "app.api.routes_rbl",
        "app.api.routes_dns",
        "app.api.routes_reports",
        "app.core.config",
        "app.core.security",
        "app.database.connection",
        "app.database.models",
        "app.parsers.rsc_parser",
        "app.parsers.vrp_parser",
        "app.parsers.zone_parser",
        "app.analyzers.dns_analyzer",
        "app.analyzers.rsc_analyzer",
        "app.analyzers.vrp_analyzer",
        "app.services.rbl_service",
        "app.services.dns_service",
        "app.services.dns_collect",
        "app.services.report_service",
    ]
)

datas = [("webui", "webui"), ("assets", "assets")] + collect_data_files("dns")

a = Analysis(
    ["launcher.py"],
    pathex=["."],
    binaries=[],
    datas=datas,
    hiddenimports=hidden,
    hookspath=[],
    runtime_hooks=[],
    excludes=["tkinter", "matplotlib", "numpy", "PIL", "pytest"],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="RBLScan",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,           # UPX aumenta muito o falso positivo de antivírus
    runtime_tmpdir=None,
    console=True,        # console à vista: erros de DNS e de chave precisam ser lidos
    disable_windowed_traceback=False,
    icon=None,
)
