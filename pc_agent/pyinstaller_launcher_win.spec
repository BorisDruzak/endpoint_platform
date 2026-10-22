# PyInstaller spec for launcher (Windows). Build: pyinstaller pyinstaller_launcher_win.spec
# Output: dist/launcher.exe
import sys
from pathlib import Path

# SPECPATH = directory containing this .spec file (pc_agent/)
pc_agent_root = Path(SPECPATH)
project_root = pc_agent_root.parent
sys.path.insert(0, str(project_root))
from tools.canary.tzdata_payload import configure_tzdata_archive
from tools.canary.privileged_bootstrap_contract import assert_no_build_modules

a = Analysis(
    [str(pc_agent_root / "launcher" / "launcher_main.py")],
    pathex=[str(project_root)],
    hiddenimports=["pc_agent.core.runtime_paths", "pc_agent.launcher.installer", "pc_agent.version"],
    datas=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[str(pc_agent_root / "runtime_hook_tzdata_zip.py")],
    excludes=["setuptools", "pkg_resources", "_distutils_hack"],
    noarchive=False,
    optimize=0,
)
assert_no_build_modules(name for name, *_ in [*a.pure, *a.binaries, *a.scripts])
configure_tzdata_archive(a, Path(workpath))
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [('pyi-enable-onefile-parent-verification', None, 'OPTION')],
    name="launcher",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
