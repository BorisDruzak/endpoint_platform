"""Independent signed SYSTEM support service; patched verification bootloader."""
import sys
from pathlib import Path

pc_agent_root = Path(SPECPATH)
project_root = pc_agent_root.parent
sys.path.insert(0, str(project_root))
from tools.canary.ssl_payload import configure_ssl_resources
from tools.canary.privileged_bootstrap_contract import assert_no_build_modules

if sys.version_info[:2] != (3, 12):
    raise RuntimeError('Support service requires the qualified Python 3.12 runtime')

a = Analysis(
    [str(pc_agent_root/'platform'/'windows'/'support_access_service.py')],
    pathex=[str(project_root),str(pc_agent_root)],
    hiddenimports=['servicemanager','win32service','win32serviceutil','win32security',
                   'win32api','win32net','win32job','win32process','win32con','ntsecuritycon'],
    datas=[],hookspath=[],hooksconfig={},runtime_hooks=[],
    excludes=['PySide6','qasync','pc_agent.ui_gui','pc_agent.ui_bridge','pc_agent.runtime',
              'pc_agent.core','pc_agent.ws_agent','pc_agent.endpoint_gateway',
              'pc_agent.platform.windows.updater_service','pc_agent.platform.windows.native_setup_observer',
              'setuptools','pkg_resources','_distutils_hack'],
    noarchive=False,optimize=0,
)
assert_no_build_modules(name for name,*_ in [*a.pure,*a.binaries,*a.scripts])
configure_ssl_resources(a)
pyz = PYZ(a.pure)
exe = EXE(pyz,a.scripts,a.binaries,a.datas,
          [('pyi-enable-onefile-parent-verification',None,'OPTION')],
          name='EndpointSupportAccess',debug=False,bootloader_ignore_signals=False,
          strip=False,upx=False,console=True,disable_windowed_traceback=False)
