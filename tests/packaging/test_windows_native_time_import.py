"""Exercise pywin32's native metadata dependency inside a frozen executable."""
import ctypes
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest


@pytest.mark.skipif(os.name != "nt", reason="native frozen Windows process identity")
def test_frozen_process_identity_reads_file_metadata(tmp_path):
    if importlib.util.find_spec("PyInstaller") is None:
        pytest.skip("Windows build toolchain is unavailable")
    if not ctypes.windll.shell32.IsUserAnAdmin():
        pytest.skip("native identity policy requires an elevated operator")
    repo = Path(__file__).resolve().parents[2]
    script = tmp_path / "native_identity_probe.py"
    script.write_text(
        "import json, os\n"
        "from pc_agent.platform.windows.installer_transaction_bridge import NativeIdentity\n"
        "identity = NativeIdentity(os.getpid())\n"
        "try: print(json.dumps({'native_identity_valid': True, 'elevated': identity.value['elevated']}))\n"
        "finally: identity.close()\n",
        encoding="utf-8",
    )
    built = subprocess.run(
        [sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--onefile",
         "--console", "--paths", str(repo), "--distpath", str(tmp_path / "dist"),
         "--workpath", str(tmp_path / "work"), "--specpath", str(tmp_path), str(script)],
        capture_output=True, text=True, timeout=120, check=False,
    )
    assert built.returncode == 0, built.stderr[-4000:]
    observed = subprocess.run(
        [str(tmp_path / "dist/native_identity_probe.exe")],
        capture_output=True, text=True, timeout=20, check=False,
    )
    assert observed.returncode == 0, observed.stderr[-2000:]
    assert json.loads(observed.stdout) == {"native_identity_valid": True, "elevated": True}
