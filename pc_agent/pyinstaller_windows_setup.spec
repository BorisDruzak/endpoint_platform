# Universal Windows Setup bootstrapper. It has no embedded enrollment authority.
import sys
from pathlib import Path

pc_agent_root = Path(SPECPATH)
project_root = pc_agent_root.parent
sys.path.insert(0, str(project_root))

a = Analysis(
    [str(pc_agent_root / "platform" / "windows" / "setup_entry.py")],
    pathex=[str(project_root), str(pc_agent_root)],
    hiddenimports=[],
    datas=[],
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
    name="EndpointAgentSetup",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
)
