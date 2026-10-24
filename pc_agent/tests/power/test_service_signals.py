"""SCM shutdown and ordinary service stop remain distinguishable and compatible."""

import asyncio
import io
import subprocess
import sys

import pytest

from pc_agent.platform.windows.service_launcher import ChildProcessCoordinator
from pc_agent.runtime import main


def test_service_host_shutdown_sends_fixed_byte_then_eof_and_stop_only_eof():
    class Pipe(io.BytesIO):
        def close(self):
            self.saved = self.getvalue()
            super().close()

    class Process:
        stdin = None

    for shutdown, expected in [(True, b"S"), (False, b"")]:
        process = Process()
        process.stdin = Pipe()
        child = ChildProcessCoordinator()
        child._process = process
        child.stop(shutdown=shutdown)
        assert process.stdin.saved == expected and process.stdin.closed


async def test_child_persists_shutdown_before_cancel_but_stop_has_no_power_fact(
    monkeypatch,
):
    recorded = []

    async def runtime(_settings):
        try:
            await asyncio.Event().wait()
        finally:
            recorded.append("cancelled")

    async def record(_settings):
        recorded.append("shutdown")

    async def shutdown():
        return b"S"

    async def stop():
        return b""

    monkeypatch.setattr(main, "run_runtime", runtime)
    monkeypatch.setattr(main, "_record_service_shutdown", record)
    monkeypatch.setattr(main, "_wait_for_service_host_pipe", shutdown)
    assert await main._run_service_child(None) == 0
    assert recorded == ["shutdown", "cancelled"]
    recorded.clear()
    monkeypatch.setattr(main, "_wait_for_service_host_pipe", stop)
    assert await main._run_service_child(None) == 0
    assert recorded == ["cancelled"]


async def test_update_pending_completion_during_shutdown_record_keeps_exit42(
    monkeypatch,
):
    finished = asyncio.Event()

    async def runtime(_settings):
        await finished.wait()
        return 42

    async def record(_settings):
        finished.set()
        await asyncio.sleep(0)

    async def shutdown():
        return b"S"

    monkeypatch.setattr(main, "run_runtime", runtime)
    monkeypatch.setattr(main, "_record_service_shutdown", record)
    monkeypatch.setattr(main, "_wait_for_service_host_pipe", shutdown)
    assert await main._run_service_child(None) == 42


@pytest.mark.parametrize("mode", ["stop", "shutdown", "update", "shutdown_update"])
def test_stalled_native_read_cannot_hold_asyncio_run_or_update_exit(mode):
    # Real asyncio.run/process exit: a cancelled task alone does not prove this.
    script = r"""
import asyncio, sys, time
from datetime import UTC, datetime
from types import SimpleNamespace
from pc_agent.platform.windows.power_events import WindowsPowerSource
from pc_agent.power.runtime import PowerEventRuntime
from pc_agent.runtime import main

mode = sys.argv[1]
started = None
workers = []
active_counts = []
original_thread = asyncio.to_thread
original_spawn = asyncio.create_subprocess_exec
async def stalled_thread(*args, **kwargs):
    started.set()
    return await original_thread(time.sleep, 30)
async def stalled_process(*args, **kwargs):
    process = await original_spawn(sys.executable, '-c', 'import time; time.sleep(30)', **kwargs)
    workers.append(process)
    active_counts.append(sum(worker.returncode is None for worker in workers))
    started.set()
    return process
asyncio.to_thread = stalled_thread
asyncio.create_subprocess_exec = stalled_process

class Spool:
    async def open(self): pass
    async def checkpoint(self): return None
    async def set_unavailable(self, **kwargs): pass

async def runtime(_settings):
    collector = asyncio.create_task(PowerEventRuntime(Spool(), WindowsPowerSource(), collect_timeout=0.01, poll_seconds=0.01).collect_forever())
    try:
        await started.wait()
        await asyncio.sleep(0.06)
        if mode in {'update', 'shutdown_update'}: return 42
        await asyncio.Event().wait()
    finally:
        collector.cancel()
        await asyncio.gather(collector, return_exceptions=True)

async def control():
    if mode in {'shutdown', 'shutdown_update'}: return b'S'
    await started.wait()
    if mode == 'stop': return b''
    await asyncio.Event().wait()

async def run():
    global started
    started = asyncio.Event()
    main.run_runtime = runtime
    main._wait_for_service_host_pipe = control
    result = await main._run_service_child(SimpleNamespace(data_root=None))
    assert workers, 'native read was not isolated in a process'
    assert max(active_counts) == 1, 'native readers overlapped'
    assert all(worker.returncode is not None for worker in workers), 'native worker not reaped'
    return result

raise SystemExit(asyncio.run(run()))
"""
    process = subprocess.Popen(
        [sys.executable, "-c", script, mode],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        stdout, stderr = process.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate()
        pytest.fail(
            "stalled optional native read held the actual asyncio.run/process exit beyond 5 seconds"
        )
    assert process.returncode == (42 if "update" in mode else 0), (stdout, stderr)
