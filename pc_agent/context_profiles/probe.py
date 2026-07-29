"""Small local-only boundary around OS files and a fixed command allowlist."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
import shutil
import subprocess


MAX_PROBE_BYTES = 65_536

LSBLK_COMMAND = ("lsblk", "--bytes", "--json", "--output", "NAME,MODEL,SIZE,WWN,SERIAL,TYPE")
IP_LINK_COMMAND = ("ip", "-json", "link", "show")
IP_DEFAULT_ROUTE_COMMAND = ("ip", "-json", "route", "show", "default")
IP_ADDRESS_COMMAND = ("ip", "-json", "address", "show")
SSHD_STATUS_COMMAND = ("systemctl", "is-active", "sshd")
NETWORK_MANAGER_STATUS_COMMAND = ("systemctl", "is-active", "NetworkManager")
PROCESS_COMMAND = ("ps", "-eo", "comm=,stat=")
JOURNAL_COMMAND = ("journalctl", "-n", "100", "--no-pager", "-o", "cat")

_ALLOWED_COMMANDS = frozenset(
    {
        LSBLK_COMMAND,
        IP_LINK_COMMAND,
        IP_DEFAULT_ROUTE_COMMAND,
        IP_ADDRESS_COMMAND,
        SSHD_STATUS_COMMAND,
        NETWORK_MANAGER_STATUS_COMMAND,
        PROCESS_COMMAND,
        JOURNAL_COMMAND,
    }
)


class SystemProbe:
    """Permit only bounded reads and explicitly enumerated local commands."""

    def read_text(self, path: str, max_bytes: int) -> str:
        limit = _bounded_limit(max_bytes)
        return Path(path).read_bytes()[:limit].decode("utf-8", errors="replace")

    def run(self, argv: Sequence[str], timeout_seconds: float, max_bytes: int) -> str:
        command = tuple(str(item) for item in argv)
        if command not in _ALLOWED_COMMANDS:
            raise ValueError("context probe command is not allowlisted")
        if timeout_seconds <= 0 or timeout_seconds > 10:
            raise ValueError("context probe timeout must be between 0 and 10 seconds")
        limit = _bounded_limit(max_bytes)
        executable = shutil.which(command[0])
        if not executable:
            raise FileNotFoundError(command[0])
        completed = subprocess.run(
            (executable, *command[1:]),
            check=False,
            capture_output=True,
            timeout=timeout_seconds,
        )
        output = (completed.stdout or b"") + (completed.stderr or b"")
        return output[:limit].decode("utf-8", errors="replace")


def _bounded_limit(max_bytes: int) -> int:
    if not isinstance(max_bytes, int) or max_bytes < 1:
        raise ValueError("context probe max_bytes must be a positive integer")
    return min(max_bytes, MAX_PROBE_BYTES)
