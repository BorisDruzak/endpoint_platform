from __future__ import annotations

from io import BytesIO
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

import pytest

from pc_agent.context_profiles import probe as probe_module
from pc_agent.context_profiles.probe import MAX_PROBE_BYTES, SystemProbe


def test_system_probe_converts_subprocess_timeout_to_collector_timeout(monkeypatch) -> None:
    """A process timeout becomes the timeout type all collectors handle."""

    def raises_timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="lsblk", timeout=0.1)

    monkeypatch.setattr(probe_module.shutil, "which", lambda command: "/usr/bin/lsblk")
    monkeypatch.setattr(probe_module, "_execute_bounded_command", raises_timeout, raising=False)

    with pytest.raises(TimeoutError):
        SystemProbe().run(probe_module.LSBLK_COMMAND, 0.1, 128)


def test_system_probe_reads_only_the_requested_file_prefix(monkeypatch) -> None:
    """A capped context file read must not materialize the trailing source bytes."""
    requested: list[int] = []

    class RecordingFile(BytesIO):
        def read(self, size: int = -1) -> bytes:
            requested.append(size)
            return super().read(size)

    def open_recording(self, mode="r", *args, **kwargs):
        assert mode == "rb"
        return RecordingFile(b"first" + b"x" * (MAX_PROBE_BYTES * 2))

    monkeypatch.setattr(Path, "open", open_recording)
    monkeypatch.setattr(Path, "read_bytes", lambda self: pytest.fail("unbounded read_bytes used"))

    assert SystemProbe().read_text("/proc/example", 5) == "first"
    assert requested == [5]


def test_system_probe_stops_command_stream_at_requested_limit(monkeypatch) -> None:
    """An oversized command stream is terminated after bounded acquisition."""
    read_sizes: list[int] = []

    class RecordingStream(BytesIO):
        def read(self, size: int = -1) -> bytes:
            read_sizes.append(size)
            return super().read(size)

    class RecordingProcess:
        def __init__(self) -> None:
            self.stdout = RecordingStream(b"a" * (MAX_PROBE_BYTES * 2))
            self.stderr = RecordingStream(b"b" * (MAX_PROBE_BYTES * 2))
            self.terminated = False

        def poll(self):
            return 0 if self.terminated else None

        def terminate(self) -> None:
            self.terminated = True

        def kill(self) -> None:
            self.terminated = True

        def wait(self, timeout: float | None = None) -> int:
            self.terminated = True
            return 0

    process = RecordingProcess()
    monkeypatch.setattr(probe_module.shutil, "which", lambda command: "/usr/bin/lsblk")
    monkeypatch.setattr(probe_module.subprocess, "Popen", lambda *args, **kwargs: process)

    assert SystemProbe().run(probe_module.LSBLK_COMMAND, 1.0, 128) == "a" * 128
    assert process.terminated is True
    assert read_sizes == [128, 128]


def test_bounded_command_uses_bounded_waits_when_terminate_grace_expires(monkeypatch) -> None:
    """A child that survives terminate is killed and reaped through bounded waits only."""

    class RequiresBoundedWaitProcess:
        def __init__(self) -> None:
            self.stdout = BytesIO()
            self.stderr = BytesIO()
            self.killed = False
            self.wait_timeouts: list[float | None] = []

        def poll(self):
            return 0 if self.killed else None

        def terminate(self) -> None:
            pass

        def kill(self) -> None:
            self.killed = True

        def wait(self, timeout: float | None = None) -> int:
            self.wait_timeouts.append(timeout)
            if timeout is None:
                raise AssertionError("unbounded wait used")
            if not self.killed:
                raise subprocess.TimeoutExpired(cmd="probe", timeout=timeout)
            return 0

    process = RequiresBoundedWaitProcess()
    monkeypatch.setattr(probe_module.subprocess, "Popen", lambda *args, **kwargs: process)

    with pytest.raises(subprocess.TimeoutExpired):
        probe_module._execute_bounded_command(("probe",), 0.01, 128)

    assert process.killed is True
    assert process.wait_timeouts == [
        probe_module.TERMINATION_GRACE_SECONDS,
        probe_module.TERMINATION_GRACE_SECONDS,
    ]


@pytest.mark.skipif(os.name == "nt", reason="SIGTERM can only be ignored by this child on POSIX")
def test_bounded_command_kills_a_child_that_ignores_sigterm_within_grace_period() -> None:
    """Timeout cleanup must not wait for an uncooperative POSIX child to exit naturally."""
    script = (
        "import signal, time; "
        "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
        "time.sleep(0.75)"
    )
    started = time.monotonic()

    with pytest.raises(subprocess.TimeoutExpired):
        probe_module._execute_bounded_command((sys.executable, "-c", script), 0.05, 128)

    assert time.monotonic() - started < 0.6


@pytest.mark.skipif(os.name == "nt", reason="process-group cleanup is exercised on POSIX")
def test_bounded_command_times_out_without_waiting_for_descendant_holding_pipes() -> None:
    """A descendant retaining inherited pipes must not extend the caller deadline."""
    script = (
        "import subprocess, sys, time; "
        "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(3)']); "
        "time.sleep(3)"
    )
    started = time.monotonic()

    with pytest.raises(subprocess.TimeoutExpired):
        probe_module._execute_bounded_command((sys.executable, "-c", script), 0.05, 128)

    assert time.monotonic() - started < 1.0


@pytest.mark.skipif(os.name == "nt", reason="process-group cleanup is exercised on POSIX")
def test_system_probe_times_out_and_cleans_parent_exited_pipe_holding_descendant(
    monkeypatch, tmp_path
) -> None:
    """A completed parent must not make a live pipe-holding group look successful."""
    child_pid_path = tmp_path / "child-pid"
    child_cleanup_path = tmp_path / "child-cleanup"
    probe_executable = tmp_path / "lsblk"
    probe_executable.write_text(
        "#!/usr/bin/env python3\n"
        "import os\n"
        "from pathlib import Path\n"
        "import subprocess\n"
        "import sys\n"
        f"child_pid_path = Path({str(child_pid_path)!r})\n"
        f"child_cleanup_path = Path({str(child_cleanup_path)!r})\n"
        "child_code = (\n"
        "    'import signal, sys, time; from pathlib import Path; '\n"
        "    'signal.signal(signal.SIGTERM, lambda *_: (Path(sys.argv[1]).write_text(\\\"done\\\"), sys.exit())); '\n"
        "    'time.sleep(30)'\n"
        ")\n"
        "child = subprocess.Popen([sys.executable, '-c', child_code, str(child_cleanup_path)])\n"
        "child_pid_path.write_text(f'{child.pid}:{os.getpgrp()}')\n"
    )
    probe_executable.chmod(0o755)
    monkeypatch.setattr(probe_module.shutil, "which", lambda command: str(probe_executable))

    started = time.monotonic()
    try:
        with pytest.raises(TimeoutError, match="context probe command timed out"):
            SystemProbe().run(
                probe_module.LSBLK_COMMAND,
                1.0,
                128,
            )
        assert time.monotonic() - started < 1.0
        assert child_cleanup_path.read_text() == "done"
    finally:
        if child_pid_path.exists():
            _child_pid, process_group = child_pid_path.read_text().split(":")
            try:
                os.killpg(int(process_group), signal.SIGKILL)
            except ProcessLookupError:
                pass


@pytest.mark.parametrize("failure_stage", ("terminate", "kill"))
def test_bounded_command_normalizes_cleanup_oserrors(failure_stage: str, monkeypatch) -> None:
    """OS cleanup failures surface as the probe timeout result, never raw errors."""

    class CleanupFailureProcess:
        def __init__(self) -> None:
            self.stdout = BytesIO()
            self.stderr = BytesIO()

        def poll(self):
            return None

        def terminate(self) -> None:
            if failure_stage == "terminate":
                raise PermissionError("terminate denied")

        def kill(self) -> None:
            if failure_stage == "kill":
                raise PermissionError("kill denied")

        def wait(self, timeout: float | None = None) -> int:
            raise subprocess.TimeoutExpired(cmd="probe", timeout=timeout)

    monkeypatch.setattr(probe_module.subprocess, "Popen", lambda *args, **kwargs: CleanupFailureProcess())

    with pytest.raises(subprocess.TimeoutExpired):
        probe_module._execute_bounded_command(("probe",), 0.01, 128)
