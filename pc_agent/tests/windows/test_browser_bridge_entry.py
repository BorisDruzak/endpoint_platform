"""The packaged native-host entrypoint has binary stdio and a pinned origin."""

import json
from pathlib import Path
import struct
import subprocess
import sys


REPO_ROOT = Path(__file__).resolve().parents[3]
EXTENSION_ID = (
    (REPO_ROOT / "browser_sensor" / "extension-id.txt")
    .read_text(encoding="ascii")
    .strip()
)
ENTRYPOINT = "pc_agent.platform.windows.browser_bridge_entry"


def test_entrypoint_rejects_other_origin_without_stdout() -> None:
    result = subprocess.run(
        [sys.executable, "-m", ENTRYPOINT, "chrome-extension://" + "a" * 32 + "/"],
        input=b"",
        capture_output=True,
        cwd=REPO_ROOT,
        check=False,
    )
    assert result.returncode == 2
    assert result.stdout == b""


def test_entrypoint_writes_one_binary_ack_for_oversized_frame() -> None:
    result = subprocess.run(
        [sys.executable, "-m", ENTRYPOINT, f"chrome-extension://{EXTENSION_ID}/"],
        input=struct.pack("<I", 16385),
        capture_output=True,
        cwd=REPO_ROOT,
        check=False,
    )
    assert result.returncode == 0
    length = struct.unpack("<I", result.stdout[:4])[0]
    assert len(result.stdout) == length + 4
    assert json.loads(result.stdout[4:]) == {
        "schema_version": "browser_bridge_ack_v1",
        "accepted": False,
        "error_code": "OVERSIZE",
    }


def test_agent_core_bundle_contains_pinned_browser_identity() -> None:
    spec = (REPO_ROOT / "pc_agent" / "pyinstaller_endpoint_core_windows.spec").read_text(
        encoding="utf-8"
    )
    assert 'browser_sensor" / "extension-id.txt"' in spec
