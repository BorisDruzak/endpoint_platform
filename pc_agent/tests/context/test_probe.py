from __future__ import annotations

from io import BytesIO
import os
from pathlib import Path
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
