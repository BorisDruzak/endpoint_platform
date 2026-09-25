# Credential-free Native Messaging host; console=True preserves binary stdin/stdout.
# Build: python -m PyInstaller --noconfirm pc_agent/pyinstaller_windows_browser_bridge.spec
import sys
from pathlib import Path

pc_agent_root = Path(SPECPATH)
project_root = pc_agent_root.parent
sys.path.insert(0, str(project_root))

a = Analysis(
    [str(pc_agent_root / "platform" / "windows" / "browser_bridge_entry.py")],
    pathex=[str(project_root), str(pc_agent_root)],
    hiddenimports=[
        "pc_agent.browser_protocol",
        "pc_agent.platform.windows.browser_bridge",
        "pc_agent.platform.windows.local_ipc",
        "pc_agent.platform.windows.local_sensor_protocol",
    ],
    datas=[(str(project_root / "browser_sensor" / "extension-id.txt"), "browser_sensor")],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "aiohttp",
        "requests",
        "pc_agent.device_credential",
        "pc_agent.endpoint_gateway",
        "pc_agent.gateway_update_runtime",
        "pc_agent.runtime",
        "pc_agent.transport",
        "pc_agent.ui_gui",
        "pc_agent.ui_bridge",
        "pc_agent.ws_agent",
        "endpoint_server",
    ],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    exclude_binaries=False,
    name="EndpointBrowserBridge",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
    target_arch=None,
)
