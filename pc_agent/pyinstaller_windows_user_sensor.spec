# Credential-free, per-session Windows observation companion.
# Build: python -m PyInstaller --noconfirm pc_agent/pyinstaller_windows_user_sensor.spec
import sys
from pathlib import Path

pc_agent_root = Path(SPECPATH)
project_root = pc_agent_root.parent
sys.path.insert(0, str(project_root))
from tools.canary.tzdata_payload import configure_tzdata_archive

a = Analysis(
    [str(pc_agent_root / "platform" / "windows" / "user_sensor_entry.py")],
    pathex=[str(project_root), str(pc_agent_root)],
    hiddenimports=[
        "pc_agent.platform.windows.local_ipc",
        "pc_agent.platform.windows.local_sensor_protocol",
        "pc_agent.platform.windows.user_sensor",
    ],
    datas=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[str(pc_agent_root / "runtime_hook_tzdata_zip.py")],
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
    ],
    noarchive=False,
    optimize=0,
)
configure_tzdata_archive(a, Path(workpath))
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    exclude_binaries=True,
    contents_directory="_foundation-runtime",
    name="EndpointUserSensor",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    target_arch=None,
)

coll = COLLECT(exe, a.binaries, a.datas, strip=False, upx=False, name="EndpointUserSensor")
