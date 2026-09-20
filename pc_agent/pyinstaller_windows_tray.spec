# Unprivileged Windows notification-area companion.
# Build: python -m PyInstaller --noconfirm pc_agent/pyinstaller_windows_tray.spec
import sys
from pathlib import Path

pc_agent_root = Path(SPECPATH)
project_root = pc_agent_root.parent
sys.path.insert(0, str(project_root))

a = Analysis(
    [str(pc_agent_root / "platform" / "windows" / "tray.py")],
    pathex=[str(project_root), str(pc_agent_root)],
    hiddenimports=["pc_agent.platform.windows.tray_status"],
    datas=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "aiohttp",
        "win32service",
        "pc_agent.endpoint_gateway",
        "pc_agent.gateway_update_runtime",
        "pc_agent.ui_gui",
        "pc_agent.ui_bridge",
        "pc_agent.ws_agent",
    ],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="EndpointAgentTray",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    target_arch=None,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="EndpointAgentTray",
)
