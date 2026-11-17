# Neutral Endpoint Agent core artifact for Linux.
# Build: python -m PyInstaller --noconfirm pc_agent/pyinstaller_endpoint_core_linux.spec
# This spec intentionally excludes Qt, Helpdesk UI, and Remote Assist.
import json
import re
import subprocess
import sys
from importlib.metadata import version
from pathlib import Path

pc_agent_root = Path(SPECPATH)
project_root = pc_agent_root.parent
sys.path.insert(0, str(project_root))

revision = subprocess.check_output(
    ["git", "rev-parse", "HEAD"], cwd=project_root, text=True,
).strip()
status = subprocess.check_output(
    ["git", "status", "--porcelain", "--untracked-files=normal", "--",
     "pc_agent", "endpoint_contracts", "browser_sensor", "requirements"],
    cwd=project_root, text=True,
)
if status.strip() or not re.fullmatch(r"[0-9a-f]{40}", revision):
    raise ValueError("Linux Core freeze requires clean committed source")
source_identity = Path(workpath) / "endpoint-core-build.json"
source_identity.parent.mkdir(parents=True, exist_ok=True)
source_identity.write_text(json.dumps({
    "source_revision": revision,
    "pyinstaller_version": version("PyInstaller"),
}), encoding="ascii")

_excluded_optional_runtime = [
    "PySide6",
    "qasync",
    "aiortc",
    "aioice",
    "av",
    "pylibsrtp",
    "mss",
    "PIL",
    "Pillow",
    "pynput",
    "imageio_ffmpeg",
    "pc_agent.ui_gui",
    "pc_agent.ui_bridge",
    "pc_agent.remote_assist",
    "pc_agent.ws_agent",
    "pc_agent.auth",
    "pc_agent.core.database",
    "pc_agent.core.job_manager",
    "pc_agent.core.orchestrator",
    "pc_agent.core.sender",
]

a = Analysis(
    [str(pc_agent_root / "runtime" / "main.py")],
    pathex=[str(project_root), str(pc_agent_root)],
    hiddenimports=[
        "pc_agent.version",
        "pc_agent.core.runtime_paths",
        "pc_agent.endpoint_gateway",
        "pc_agent.gateway_update_runtime",
        "pc_agent.update_adapter",
        "pc_agent.context_profiles.command_execution",
        "pc_agent.context_profiles.probe",
        "pc_agent.context_profiles.registry",
    ],
    datas=[
        (str(project_root / "browser_sensor" / "extension-id.txt"), "browser_sensor"),
        (str(source_identity), "."),
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=_excluded_optional_runtime,
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="endpoint-agent",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
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
    name="endpoint-agent",
)
