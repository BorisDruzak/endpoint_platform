"""SCM shutdown and ordinary service stop remain distinguishable and compatible."""

import asyncio
import io

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
