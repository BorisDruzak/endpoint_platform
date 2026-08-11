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
    config_value = os.environ.get("ENDPOINT_AGENT_CONFIG")
    ca_value = os.environ.get("ENDPOINT_AGENT_CA_FILE")
    claim_value = os.environ.get("ENDPOINT_AGENT_PROVISIONING_HANDOFF_FILE")
    if not config_value or not ca_value or not claim_value:
        return NO_RESTART_STATUS
    config_path = Path(config_value)
    ca_path = Path(ca_value)
    claim_path = Path(claim_value)
    if not all(path.is_absolute() for path in (config_path, ca_path, claim_path)):
        return NO_RESTART_STATUS
    result = subprocess.run(
        [
            str(CHECKER),
            "--credential-representation",
            "delegated",
            "--config",
            str(config_path),
            "--ca",
            str(ca_path),
            "--claim",
            str(claim_path),
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
