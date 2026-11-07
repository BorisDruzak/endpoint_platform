"""Linux Support1.0.0 onedir payload, independent of Core/updater and Qt."""
import sys
from pathlib import Path

pc_agent_root = Path(SPECPATH)
project_root = pc_agent_root.parent
sys.path.insert(0,str(project_root))
from tools.release.freeze_linux_native_identity import freeze_identity
identity = freeze_identity(project_root, 'support')
if sys.version_info[:2] != (3,12):
    raise RuntimeError('Linux Support requires qualified Python3.12')

a = Analysis([str(pc_agent_root/'platform/linux/support_access_service.py')],
    pathex=[str(project_root)], hiddenimports=['pwd','spwd','fcntl'],
    datas=[(identity,'.')],hookspath=[],hooksconfig={},runtime_hooks=[],
    excludes=['PySide6','qasync','pc_agent.core','pc_agent.runtime','pc_agent.ws_agent',
        'pc_agent.endpoint_gateway','pc_agent.gateway_update_runtime','pc_agent.ui_gui',
        'pc_agent.ui_bridge','pc_agent.platform.linux.updater','aiohttp','pydantic',
        'setuptools','pkg_resources','_distutils_hack'],noarchive=False,optimize=0)
for name,*_ in a.pure:
    if name.startswith(('pc_agent.core','pc_agent.runtime','pc_agent.ws_agent','pc_agent.gateway_update_runtime')):
        raise RuntimeError('Support import boundary violated')
pyz = PYZ(a.pure)
exe = EXE(pyz,a.scripts,[],exclude_binaries=True,name='endpoint-support-access',
    debug=False,bootloader_ignore_signals=False,strip=False,upx=False,console=True)
coll = COLLECT(exe,a.binaries,a.datas,strip=False,upx=False,name='endpoint-support-access')
