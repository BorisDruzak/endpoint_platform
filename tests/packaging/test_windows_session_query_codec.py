"""Ensure native OEM decoding remains available in the shipped frozen runtime."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest


@pytest.mark.skipif(os.name != "nt", reason="native frozen Windows OEM codec")
def test_frozen_query_user_ignores_localized_header_and_decodes_oem(tmp_path):
    if importlib.util.find_spec("PyInstaller") is None:
        pytest.skip("Windows build toolchain is unavailable")
    repo = Path(__file__).resolve().parents[2]
    script = tmp_path / "native_session_codec_probe.py"
    script.write_text(
        "import json\n"
        "from pc_agent.context_profiles import probe\n"
        "for login in ('тестовый', 'müller', 'テスト', '테스트', 'operator'):\n"
        "    try: login.encode('oem')\n"
        "    except UnicodeError: continue\n"
        "    break\n"
        "raw = ('ИМЯ ПОЛЬЗОВАТЕЛЯ SESSIONNAME ID STATE\\n>' + login + ' console 1 Active none 10/14/2026 03:17\\n').encode('oem', errors='replace')\n"
        "probe.shutil.which = lambda _: 'query.exe'\n"
        "probe._execute_bounded_command = lambda *args, **kwargs: raw\n"
        "result = probe.SystemProbe().session_info()\n"
        "print(json.dumps({'native_oem_login_matches': result.get('current_user_login') == login, 'session_present': result.get('interactive_session_present')}))\n",
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
        [str(tmp_path / "dist/native_session_codec_probe.exe")],
        capture_output=True, text=True, timeout=20, check=False,
    )
    assert observed.returncode == 0, observed.stderr[-2000:]
    assert json.loads(observed.stdout) == {
        "native_oem_login_matches": True, "session_present": True,
    }
