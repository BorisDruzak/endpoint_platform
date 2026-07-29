"""Small local-only boundary around OS files and a fixed command allowlist."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
import shutil
import subprocess
import threading
import time


MAX_PROBE_BYTES = 65_536
TERMINATION_GRACE_SECONDS = 0.2
_DRAIN_JOIN_GRACE_SECONDS = 0.2

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
        with Path(path).open("rb") as source:
            return source.read(limit).decode("utf-8", errors="replace")

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
        try:
            output = _execute_bounded_command((executable, *command[1:]), timeout_seconds, limit)
        except subprocess.TimeoutExpired as exc:
            raise TimeoutError("context probe command timed out") from exc
        return output.decode("utf-8", errors="replace")


def _bounded_limit(max_bytes: int) -> int:
    if not isinstance(max_bytes, int) or max_bytes < 1:
        raise ValueError("context probe max_bytes must be a positive integer")
    return min(max_bytes, MAX_PROBE_BYTES)


def _execute_bounded_command(command: tuple[str, ...], timeout_seconds: float, limit: int) -> bytes:
    """Capture local command output without materializing unbounded pipe streams."""
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdout is not None
    assert process.stderr is not None
    stdout = _BoundedDrain(process.stdout, limit)
    stderr = _BoundedDrain(process.stderr, limit)
    stdout.start()
    stderr.start()

    deadline = time.monotonic() + timeout_seconds
    timed_out = False
    cleanup_failed = False
    cleanup_attempted = False
    try:
        while process.poll() is None:
            if stdout.full.is_set() or stderr.full.is_set() or time.monotonic() >= deadline:
                timed_out = time.monotonic() >= deadline
                cleanup_attempted = True
                cleanup_failed = not _terminate_and_reap(process)
                break
            time.sleep(0.01)
    finally:
        if not cleanup_attempted and process.poll() is None:
            cleanup_failed = not _terminate_and_reap(process) or cleanup_failed
        elif not cleanup_attempted and not _wait_for_exit(process):
            cleanup_failed = True
        process.stdout.close()
        process.stderr.close()
        stdout.join(_DRAIN_JOIN_GRACE_SECONDS)
        stderr.join(_DRAIN_JOIN_GRACE_SECONDS)

    if timed_out or cleanup_failed:
        raise subprocess.TimeoutExpired(command, timeout_seconds)
    return (bytes(stdout.output) + bytes(stderr.output))[:limit]


def _terminate_and_reap(process: subprocess.Popen[bytes]) -> bool:
    """Stop a child without letting a hung exit path block a collector."""
    if process.poll() is not None:
        return _wait_for_exit(process)
    try:
        process.terminate()
    except ProcessLookupError:
        return _wait_for_exit(process)
    if _wait_for_exit(process):
        return True
    try:
        process.kill()
    except ProcessLookupError:
        return _wait_for_exit(process)
    return _wait_for_exit(process)


def _wait_for_exit(process: subprocess.Popen[bytes]) -> bool:
    try:
        process.wait(timeout=TERMINATION_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        return False
    return True


class _BoundedDrain:
    def __init__(self, stream: object, limit: int) -> None:
        self._stream = stream
        self._limit = limit
        self.output = bytearray()
        self.full = threading.Event()
        self._thread = threading.Thread(target=self._drain, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def join(self, timeout_seconds: float) -> None:
        self._thread.join(timeout=timeout_seconds)

    def _drain(self) -> None:
        try:
            while len(self.output) < self._limit:
                chunk = self._stream.read(min(8192, self._limit - len(self.output)))
                if not chunk:
                    return
                self.output.extend(chunk)
            self.full.set()
        except (OSError, ValueError):
            return
