"""Small local-only boundary around OS files and a fixed command allowlist."""

from __future__ import annotations

from collections.abc import Sequence
import os
from pathlib import Path
import shutil
import signal
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
WINDOWS_TASKLIST_COMMAND = ("tasklist", "/FO", "CSV", "/NH")

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
        WINDOWS_TASKLIST_COMMAND,
    }
)


class SystemProbe:
    """Permit only bounded reads and explicitly enumerated local commands."""

    @property
    def platform_name(self) -> str:
        return "windows" if os.name == "nt" else "linux"

    def windows_system(self) -> dict[str, object]:
        from pc_agent.platform.windows.identity import native_system

        return native_system()

    def windows_hardware(self) -> dict[str, object]:
        from pc_agent.platform.windows.identity import native_hardware

        return native_hardware()

    def windows_health(self) -> dict[str, int]:
        from pc_agent.platform.windows.identity import native_health

        return native_health()

    def windows_storage(self) -> list[dict[str, object]]:
        from pc_agent.platform.windows.storage import native_storage

        return native_storage()

    def windows_interfaces(self) -> list[dict[str, object]]:
        from pc_agent.platform.windows.network import native_interfaces

        return native_interfaces()

    def windows_default_route(self) -> dict[str, str | None]:
        from pc_agent.platform.windows.network import native_default_route

        return native_default_route()

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
    popen_options: dict[str, object] = {
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
    }
    if os.name == "posix":
        popen_options["start_new_session"] = True
    process = subprocess.Popen(command, **popen_options)
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
        stdout.join(_DRAIN_JOIN_GRACE_SECONDS)
        stderr.join(_DRAIN_JOIN_GRACE_SECONDS)
        if stdout.is_alive() or stderr.is_alive():
            timed_out = True
            cleanup_failed = not _terminate_pipe_holding_group(process, stdout, stderr) or cleanup_failed

    if timed_out or cleanup_failed:
        raise subprocess.TimeoutExpired(command, timeout_seconds)
    return (bytes(stdout.output) + bytes(stderr.output))[:limit]


def _terminate_and_reap(process: subprocess.Popen[bytes]) -> bool:
    """Stop a child without letting a hung exit path block a collector."""
    if process.poll() is not None:
        return _wait_for_exit(process)
    if not _signal_process(process, terminate=True):
        return _wait_for_exit(process)
    if _wait_for_exit(process):
        return True
    if not _signal_process(process, terminate=False):
        return _wait_for_exit(process)
    return _wait_for_exit(process)


def _signal_process(process: subprocess.Popen[bytes], *, terminate: bool) -> bool:
    """Signal a process group where supported, without leaking OS cleanup errors."""
    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGTERM if terminate else signal.SIGKILL)
        except AttributeError:
            pass
        except ProcessLookupError:
            return False
        except OSError:
            return False
        else:
            return True

    try:
        if terminate:
            process.terminate()
        else:
            process.kill()
    except (OSError, ProcessLookupError):
        return False
    return True


def _wait_for_exit(process: subprocess.Popen[bytes]) -> bool:
    try:
        process.wait(timeout=TERMINATION_GRACE_SECONDS)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return True


def _terminate_pipe_holding_group(
    process: subprocess.Popen[bytes], stdout: _BoundedDrain, stderr: _BoundedDrain
) -> bool:
    """Stop POSIX descendants that retain probe pipes after their parent exits."""
    if os.name != "posix":
        return False
    if not _signal_process(process, terminate=True):
        return False
    _wait_for_exit(process)
    stdout.join(_DRAIN_JOIN_GRACE_SECONDS)
    stderr.join(_DRAIN_JOIN_GRACE_SECONDS)
    if not stdout.is_alive() and not stderr.is_alive():
        return True
    if not _signal_process(process, terminate=False):
        return False
    _wait_for_exit(process)
    stdout.join(_DRAIN_JOIN_GRACE_SECONDS)
    stderr.join(_DRAIN_JOIN_GRACE_SECONDS)
    return not stdout.is_alive() and not stderr.is_alive()


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

    def is_alive(self) -> bool:
        return self._thread.is_alive()

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
        finally:
            try:
                self._stream.close()
            except (OSError, ValueError):
                pass
