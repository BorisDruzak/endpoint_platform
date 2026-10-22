"""Privileged updater release root: no agent launcher or network capability."""
import sys
from pathlib import Path

pc_agent_root = Path(SPECPATH)
project_root = pc_agent_root.parent
sys.path.insert(0, str(project_root))
from tools.canary.tzdata_payload import configure_tzdata_archive
from tools.canary.offline_updater_contract import FORBIDDEN_MODULES, assert_offline_modules
from tools.canary.privileged_bootstrap_contract import assert_no_build_modules

a = Analysis(
    [str(pc_agent_root / 'platform' / 'windows' / 'updater_entry.py')],
    pathex=[str(project_root), str(pc_agent_root)],
    hiddenimports=['pc_agent.platform.windows.staged_update_state',
        'servicemanager', 'win32service', 'win32serviceutil',
                   'win32security', 'win32file', 'ntsecuritycon'],
    datas=[], hookspath=[], hooksconfig={}, runtime_hooks=[str(pc_agent_root / "runtime_hook_tzdata_zip.py")],
    excludes=[*FORBIDDEN_MODULES, 'PySide6', 'qasync', 'pc_agent.ui_gui',
              'pc_agent.ui_bridge', 'pc_agent.runtime',
              'pc_agent.platform.windows.service_launcher',
              'setuptools', 'pkg_resources', '_distutils_hack'],
    noarchive=False, optimize=0,
)
assert_offline_modules(name for name, *_ in [*a.pure, *a.binaries, *a.scripts])
assert_no_build_modules(name for name, *_ in [*a.pure, *a.binaries, *a.scripts])
configure_tzdata_archive(a, Path(workpath))
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, a.binaries, a.datas,
          [('pyi-enable-onefile-parent-verification', None, 'OPTION')], name='endpoint-agent-updater',
          debug=False, bootloader_ignore_signals=False, strip=False,
          upx=True, console=True, disable_windowed_traceback=False)
