"""Root-only onefile native coordinator; survives removal of its owning RPM."""
import sys
from pathlib import Path

root = Path(SPECPATH).parent
sys.path.insert(0,str(root))
from tools.release.freeze_linux_native_identity import freeze_identity
identity = freeze_identity(root, 'setup')
if sys.version_info[:2] != (3, 12):
    raise RuntimeError('Linux Setup requires Python3.12')
a = Analysis([str(root/'pc_agent/platform/linux/installation_coordinator.py')],
    pathex=[str(root)], hiddenimports=['pwd','fcntl','spwd',
        'pc_agent.platform.linux.installation_notification','pc_agent.platform.linux.installation_user_sessions'],
    datas=[(identity,'.')], hookspath=[], hooksconfig={}, runtime_hooks=[],
    excludes=['PySide6','qasync','pc_agent.runtime','pc_agent.ws_agent','pc_agent.endpoint_gateway',
        'pc_agent.gateway_update_runtime','pc_agent.ui_gui','pc_agent.ui_bridge','setuptools','pkg_resources'],
    noarchive=False, optimize=0)
pyz = PYZ(a.pure)
exe = EXE(pyz,a.scripts,a.binaries,a.datas,[],name='endpoint-agent-setup',debug=False,
    bootloader_ignore_signals=False,strip=False,upx=False,console=True)
