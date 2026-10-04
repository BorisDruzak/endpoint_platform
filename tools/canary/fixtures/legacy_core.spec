# Nonproduction core83/86/87 ONLY. Canonical core spec remains unchanged.
import sys
from pathlib import Path

fixture_root = Path(SPECPATH)
project_root = fixture_root.parents[2]
pc_agent_root = project_root / "pc_agent"
sys.path.insert(0, str(project_root))

from pc_agent.version import AGENT_VERSION
from tools.canary.fixtures.fixture_binding import require_binding

# Refuse the implementation commit (82/unbound) before invoking PyInstaller.
require_binding(AGENT_VERSION)

a = Analysis(
    [str(fixture_root / "legacy_entry.py")],
    pathex=[str(project_root), str(pc_agent_root)],
    hiddenimports=[
        "pc_agent.version", "pc_agent.core.runtime_paths", "pc_agent.endpoint_gateway",
        "pc_agent.gateway_update_runtime", "pc_agent.update_adapter",
        "pc_agent.context_profiles.command_execution", "pc_agent.context_profiles.probe",
        "pc_agent.context_profiles.registry",
    ],
    datas=[(str(project_root / "browser_sensor" / "extension-id.txt"), "browser_sensor")],
    hookspath=[], hooksconfig={}, runtime_hooks=[],
    excludes=["PySide6", "qasync", "aiortc", "aioice", "av", "pylibsrtp", "mss", "PIL",
        "Pillow", "pynput", "imageio_ffmpeg", "pc_agent.ui_gui", "pc_agent.ui_bridge",
        "pc_agent.remote_assist", "pc_agent.ws_agent", "pc_agent.auth", "pc_agent.core.database",
        "pc_agent.core.job_manager", "pc_agent.core.orchestrator", "pc_agent.core.sender"],
    noarchive=False, optimize=0,
)
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, [], exclude_binaries=True, name="endpoint_agent_core", debug=False,
    bootloader_ignore_signals=False, strip=False, upx=True, console=True,
    disable_windowed_traceback=False, target_arch=None)
coll = COLLECT(exe, a.binaries, a.datas, strip=False, upx=True, upx_exclude=[], name="endpoint_agent_core")
