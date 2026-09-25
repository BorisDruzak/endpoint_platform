# Fixed MSI-owned LocalSystem Browser Sensor policy helper.
import sys
from pathlib import Path

pc_agent_root = Path(SPECPATH)
project_root = pc_agent_root.parent
sys.path.insert(0, str(project_root))

a = Analysis(
    [str(pc_agent_root / "platform" / "windows" / "browser_policy_service_entry.py")],
    pathex=[str(project_root), str(pc_agent_root)],
    hiddenimports=[
        "servicemanager",
        "win32service",
        "win32serviceutil",
        "win32security",
        "win32pipe",
        "win32file",
        "win32api",
        "pc_agent.platform.windows.browser_policy",
        "pc_agent.platform.windows.browser_policy_helper",
        "pc_agent.platform.windows.sensor_pipe_listener",
    ],
    datas=[
        (str(project_root / "browser_sensor" / "extension-id.txt"), "browser_sensor"),
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["PySide6", "qasync", "pc_agent.ui_gui", "pc_agent.ui_bridge"],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    name="EndpointBrowserPolicy",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
)
