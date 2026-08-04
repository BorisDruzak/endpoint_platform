#!/usr/bin/python3
"""Validate systemd-loaded credentials, then replace this process with the agent."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys


CHECKER = Path("/usr/lib/endpoint-agent/check-start-prerequisites")
LAUNCHER = Path("/opt/endpoint-agent/launcher")
NO_RESTART_STATUS = 78


def main() -> int:
    credential_root_value = os.environ.get("CREDENTIALS_DIRECTORY")
    if not credential_root_value:
        return NO_RESTART_STATUS
    credential_root = Path(credential_root_value)
    if not credential_root.is_absolute():
        return NO_RESTART_STATUS
    result = subprocess.run(
        [
            str(CHECKER),
            "--credential-representation",
            "loaded",
            "--config",
            str(credential_root / "endpoint-agent-config"),
            "--ca",
            str(credential_root / "endpoint-agent-ca"),
            "--claim",
            str(credential_root / "endpoint-enrollment-claim"),
        ],
        check=False,
    )
    if result.returncode != 0:
        return NO_RESTART_STATUS
    os.execv(
        LAUNCHER,
        [
            str(LAUNCHER),
            "--no-gui",
            "--transport-mode",
            "gateway_wss",
            "--no-migration-http-pull-fallback",
            "--data-dir",
            "/var/lib/endpoint-agent",
            "--install-root",
            "/opt/endpoint-agent",
        ],
    )
    return NO_RESTART_STATUS


if __name__ == "__main__":
    sys.exit(main())
