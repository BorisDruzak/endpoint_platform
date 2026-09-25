"""The frozen Native Messaging host accepts only its pinned extension origin."""

from __future__ import annotations

import json
from pathlib import Path
import struct
import subprocess
import sys

import pytest
from PyInstaller.archive.readers import CArchiveReader


REPO_ROOT = Path(__file__).resolve().parents[2]
SPEC = REPO_ROOT / "pc_agent" / "pyinstaller_windows_browser_bridge.spec"
EXTENSION_ID = (
    (REPO_ROOT / "browser_sensor" / "extension-id.txt")
    .read_text(encoding="ascii")
    .strip()
)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows executable")
def test_frozen_bridge_has_pinned_binary_host_without_agent_credentials(
    tmp_path: Path,
) -> None:
    build = subprocess.run(
        [
            sys.executable,
            "-m",
            "PyInstaller",
            "--noconfirm",
            "--clean",
            "--log-level=WARN",
            "--distpath",
            str(tmp_path / "dist"),
            "--workpath",
            str(tmp_path / "work"),
            str(SPEC),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        timeout=180,
        check=False,
    )
    assert build.returncode == 0, build.stderr.decode("utf-8", errors="replace")[-3000:]
    executable = tmp_path / "dist" / "EndpointBrowserBridge.exe"
    assert executable.is_file()

    refused = subprocess.run(
        [executable, "chrome-extension://" + "a" * 32 + "/"],
        input=b"",
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert refused.returncode == 2
    assert refused.stdout == b""
    accepted = subprocess.run(
        [executable, f"chrome-extension://{EXTENSION_ID}/"],
        input=struct.pack("<I", 16385),
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert accepted.returncode == 0
    size = struct.unpack("<I", accepted.stdout[:4])[0]
    assert len(accepted.stdout) == size + 4
    assert json.loads(accepted.stdout[4:])["error_code"] == "OVERSIZE"

    archive = CArchiveReader(str(executable))
    modules = set(archive.open_embedded_archive("PYZ.pyz").toc)
    assert not any(
        name == prefix or name.startswith(prefix + ".")
        for name in modules
        for prefix in (
            "pc_agent.device_credential",
            "pc_agent.endpoint_gateway",
            "pc_agent.gateway_update_runtime",
            "pc_agent.transport",
            "pc_agent.runtime",
            "endpoint_server",
        )
    )
