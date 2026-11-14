"""Regression tests for the isolated Gateway command worker."""

import asyncio
from datetime import UTC, datetime, timedelta
import sys
from uuid import uuid4

import pytest

from endpoint_contracts import AgentCommandV1
from pc_agent.runtime import command_executor


def _command(seconds=30):
    now = datetime.now(UTC)
    return AgentCommandV1(
        schema_version="agent_command_v1", command_id=uuid4(), device_id=uuid4(),
        capability="system.resource_snapshot", parameters={}, requested_by_service="test-runtime",
        idempotency_key=str(uuid4()), created_at=now - timedelta(seconds=60),
        deadline_at=now + timedelta(seconds=seconds),
    )


@pytest.mark.asyncio
async def test_builtin_command_runs_in_worker_and_returns_typed_result():
    executor = command_executor.CommandExecutor()
    await executor.start()
    try:
        command = _command()
        result = await executor.execute(command)
        assert result.command_id == command.command_id
        assert result.status == "succeeded"
        assert result.result_items[0]["schema_version"] == "system_resource_snapshot_result_v1"
    finally:
        await executor.stop()


@pytest.mark.asyncio
async def test_expired_command_does_not_start_worker(monkeypatch):
    async def unexpected_spawn(*args, **kwargs):
        pytest.fail("an expired command must not spawn a process")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", unexpected_spawn)
    executor = command_executor.CommandExecutor()
    await executor.start()
    try:
        result = await executor.execute(_command(seconds=-1))
        assert result.status == "expired"
        assert result.message == "AGENT_COMMAND_DEADLINE_EXCEEDED"
    finally:
        await executor.stop()


@pytest.mark.asyncio
@pytest.mark.parametrize("cancel", [False, True])
async def test_stalled_worker_and_descendant_are_terminated(tmp_path, monkeypatch, cancel):
    import os
    import time

    import psutil
    from pc_agent.runtime import command_worker

    child_path = tmp_path / "worker-descendant"
    sentinel = tmp_path / "descendant-survived"
    program = """
import pathlib, subprocess, sys, time
sys.stdin.buffer.readline()
child = subprocess.Popen([
    sys.executable, "-c",
    "import pathlib, sys, time; time.sleep(10); pathlib.Path(sys.argv[1]).touch()",
    sys.argv[2],
])
pathlib.Path(sys.argv[1]).write_text(str(child.pid))
time.sleep(30)
"""
    monkeypatch.setattr(command_worker, "_worker_arguments", lambda: [
        sys.executable, "-c", program, str(child_path), str(sentinel),
    ])
    monkeypatch.setitem(command_executor._CAPABILITY_BUDGETS, "system.resource_snapshot", 2)
    executor = command_executor.CommandExecutor()
    await executor.start()
    task = asyncio.create_task(executor.execute(_command()))
    pid = None
    try:
        async with asyncio.timeout(1.5):
            while not child_path.exists():
                await asyncio.sleep(0.02)
            while not (pid_text := child_path.read_text()):
                await asyncio.sleep(0.02)
        pid = int(pid_text)
        start = time.monotonic()
        async with asyncio.timeout(4):
            if cancel:
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task
            else:
                result = await task
                assert result.message == "AGENT_COMMAND_BUDGET_EXCEEDED"
            while psutil.pid_exists(pid):
                try:
                    if os.name == "posix" and psutil.Process(pid).status() == psutil.STATUS_ZOMBIE:
                        break
                except psutil.NoSuchProcess:
                    break
                await asyncio.sleep(0.02)
        assert time.monotonic() - start < 4
        assert not sentinel.exists()
    finally:
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        if pid is not None:
            try:
                child = psutil.Process(pid)
                if child.status() != psutil.STATUS_ZOMBIE:
                    child.kill()
            except psutil.NoSuchProcess:
                pass
        await executor.stop()


@pytest.mark.asyncio
async def test_oversized_reply_does_not_leave_worker_or_poison_next_command(monkeypatch):
    from pc_agent.runtime import command_worker

    executor = command_executor.CommandExecutor()
    await executor.start()
    try:
        with monkeypatch.context() as patch:
            program = "import sys,time; sys.stdin.readline(); sys.stdout.write('x' * (512 * 1024)); sys.stdout.flush(); time.sleep(30)"
            patch.setattr(command_worker, "_worker_arguments", lambda: [sys.executable, "-c", program])
            async with asyncio.timeout(5):
                result = await executor.execute(_command())
            assert result.message == "AGENT_COMMAND_WORKER_FAILED"
        assert (await executor.execute(_command())).status == "succeeded"
    finally:
        await executor.stop()
