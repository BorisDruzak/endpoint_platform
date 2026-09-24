"""Package the self-contained Windows Setup from explicit public release inputs."""

import os
import sys
from pathlib import Path

pc_agent_root = Path(SPECPATH)
project_root = pc_agent_root.parent
sys.path.insert(0, str(project_root))


def _public_payload(name: str, expected_filename: str) -> Path:
    value = os.environ.get(name)
    if not value:
        raise SystemExit(f"{name} is required for a Windows Setup build")
    path = Path(value).resolve()
    if not path.is_file() or path.name != expected_filename:
        raise SystemExit(f"{name} must name {expected_filename}")
    return path


setup_msi = _public_payload("ENDPOINT_SETUP_MSI", "EndpointAgent.msi")
setup_ca = _public_payload("ENDPOINT_SETUP_CA_FILE", "endpoint-ca.crt")
setup_config = _public_payload("ENDPOINT_SETUP_CONFIG", "setup-config.json")
setup_msi_release_manifest = _public_payload(
    "ENDPOINT_SETUP_MSI_RELEASE_MANIFEST", "EndpointAgent.release.json"
)
setup_installer_wrapper = project_root / "packaging" / "windows" / "Install-EndpointAgentCanary.ps1"
if not setup_installer_wrapper.is_file():
    raise SystemExit("Install-EndpointAgentCanary.ps1 is required for a Windows Setup build")

a = Analysis(
    [str(pc_agent_root / "platform" / "windows" / "setup_entry.py")],
    pathex=[str(project_root), str(pc_agent_root)],
    hiddenimports=[],
    datas=[
        (str(setup_msi), "payload"),
        (str(setup_ca), "payload"),
        (str(setup_config), "payload"),
        (str(setup_msi_release_manifest), "payload"),
        (str(setup_installer_wrapper), "payload"),
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
    name="EndpointAgentSetup",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    uac_admin=True,
)
