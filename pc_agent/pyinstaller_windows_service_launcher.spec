# Fixed machine-wide service host. It selects versions/<current>/pc_agent.exe.
import sys
from pathlib import Path

pc_agent_root = Path(SPECPATH)
project_root = pc_agent_root.parent
sys.path.insert(0, str(project_root))
from tools.canary.tzdata_payload import configure_tzdata_archive
from tools.canary.ssl_payload import configure_ssl_resources
from tools.canary.privileged_bootstrap_contract import assert_no_build_modules

a = Analysis(
    [str(pc_agent_root / "platform" / "windows" / "service_launcher.py")],
    pathex=[str(project_root), str(pc_agent_root)],
    hiddenimports=[
        "pc_agent.platform.windows.staged_update_state",
        "pc_agent.platform.windows.staged_trial_proof",
        "pc_agent.platform.windows.staged_foundation_rollback",
        "pc_agent.platform.windows.staged_recovery",
        "pc_agent.platform.windows.retained_storage",
        "servicemanager",
        "win32service",
        "win32serviceutil",
        "win32security",
        "ntsecuritycon",
        "pc_agent.platform.windows.updater_service",
        "pc_agent.platform.windows.selector_migration",
    ],
    datas=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[str(pc_agent_root / "runtime_hook_tzdata_zip.py")],
    excludes=["PySide6", "qasync", "pc_agent.ui_gui", "pc_agent.ui_bridge",
              "setuptools", "pkg_resources", "_distutils_hack"],
    noarchive=False,
    optimize=0,
)
assert_no_build_modules(name for name, *_ in [*a.pure, *a.binaries, *a.scripts])
configure_tzdata_archive(a, Path(workpath))
configure_ssl_resources(a)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    [('pyi-enable-onefile-parent-verification', None, 'OPTION')],
    exclude_binaries=True,
    contents_directory="_foundation-runtime",
    name="endpoint-agent-service",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
)

coll = COLLECT(exe, a.binaries, a.datas, strip=False, upx=False, name="endpoint-agent-service")
