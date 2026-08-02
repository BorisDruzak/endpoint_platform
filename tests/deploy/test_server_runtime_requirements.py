from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def test_server_runtime_requirements_resolve_websocket_implementation(
    tmp_path: Path,
) -> None:
    """The production ASGI runtime must support Gateway WebSocket upgrades."""
    report_path = tmp_path / "server-requirements-report.json"

    subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--dry-run",
            "--ignore-installed",
            "--report",
            str(report_path),
            "-r",
            "requirements-server.txt",
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    report = json.loads(report_path.read_text(encoding="utf-8"))
    resolved_packages = {
        item["metadata"]["name"].lower() for item in report["install"]
    }

    assert "websockets" in resolved_packages
