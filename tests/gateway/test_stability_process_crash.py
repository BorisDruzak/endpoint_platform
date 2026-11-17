"""Opt-in API process kill and isolated PostgreSQL crash recovery."""

import asyncio
from contextlib import AsyncExitStack, asynccontextmanager
from datetime import UTC, datetime, timedelta
import json
import os
from pathlib import Path
import socket
import shutil
import subprocess
import sys
from tempfile import TemporaryFile, gettempdir
from time import perf_counter
from urllib.parse import urlsplit
from uuid import UUID, uuid4

import aiohttp
import pytest
from sqlalchemy import func, select

from endpoint_server.context.models import ContextCollection, ContextSnapshot
from endpoint_server.db.models import CommandResult, DeviceSession
from endpoint_server.db.session import AsyncSessionProvider
from tests.gateway.conftest import PEPPER, seed_device
from tests.gateway.test_stability_capacity import _connect, _grant, _receive, _result, _send_result
from tests.gateway.test_stability_restore import _REPOSITORY_ROOT, _restored_api


def _pg_tool(tool, *args):
    root = Path(os.environ["ENDPOINT_STABILITY_PG_SERVER_BIN"]).resolve(strict=True)
    executable = root / (tool + (".exe" if os.name == "nt" else ""))
    with TemporaryFile() as output:
        result = subprocess.run([str(executable), *map(str, args)], stdout=output,
                                stderr=subprocess.STDOUT, timeout=35)
        output.seek(0)
        assert result.returncode == 0, output.read().decode(errors="replace")


async def _start_db(data, port, log_path):
    # All rehearsal clients use TCP, so a private cluster needs no system socket.
    await asyncio.to_thread(_pg_tool, "pg_ctl", "-D", data, "-l", log_path,
                            "-o", f"-h 127.0.0.1 -p {port} -c unix_socket_directories=",
                            "-w", "-t", "20", "start")


async def _stop_db(data, mode):
    await asyncio.to_thread(_pg_tool, "pg_ctl", "-D", data, "-m", mode, "-w", "-t", "20", "stop")


def _migrate(database_url):
    # The deployment DATABASE_URL, if present in the parent environment, must
    # never be used by this rehearsal.
    result = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=_REPOSITORY_ROOT, env={**os.environ, "DATABASE_URL": database_url},
        capture_output=True, timeout=30,
    )
    assert result.returncode == 0, result.stderr.decode(errors="replace")


@asynccontextmanager
async def _disposable_cluster():
    workspace = Path(gettempdir()).resolve() / f"endpoint-crash-pg-{uuid4().hex}"
    workspace.mkdir()
    try:
        async with _ready_cluster(workspace / "data", workspace / "postgres.log") as db:
            yield db
    finally:
        if not (workspace / "data/postmaster.pid").exists():
            shutil.rmtree(workspace)


@asynccontextmanager
async def _ready_cluster(data, log_path):
    await asyncio.to_thread(_pg_tool, "initdb", "-D", data, "-U", "postgres",
                            "-A", "trust", "--locale=C", "-E", "UTF8")
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    try:
        await _start_db(data, port, log_path)
        database_url = f"postgresql+asyncpg://postgres@127.0.0.1:{port}/postgres"
        await asyncio.to_thread(_migrate, database_url)
        yield data, port, database_url, log_path
    finally:
        if (data / "postmaster.pid").is_file():
            await _stop_db(data, "fast")


async def _assert_durable(provider, device_id, command_id):
    async with provider() as db:
        assert await db.scalar(select(func.count()).select_from(CommandResult).where(
            CommandResult.command_id == UUID(command_id))) == 1
        assert await db.scalar(select(func.count()).select_from(ContextSnapshot).where(
            ContextSnapshot.device_id == device_id)) == 1
        assert await db.scalar(select(func.count()).select_from(DeviceSession).where(
            DeviceSession.device_id == device_id, DeviceSession.closed_at.is_(None))) == 1


async def _await_commit(provider, command_id):
    async with asyncio.timeout(10):
        while True:
            async with provider() as db:
                if await db.scalar(select(CommandResult.id).where(CommandResult.command_id == UUID(command_id))):
                    return
            await asyncio.sleep(.025)


@pytest.mark.skipif(not os.getenv("ENDPOINT_STABILITY_PG_SERVER_BIN"), reason="opt-in disposable PostgreSQL cluster")
@pytest.mark.parametrize("fault", ["api_before_commit", "api_ack_lost", "postgres"])
async def test_process_crash_recovers_exact_result(tmp_path, fault):
    identity = tmp_path / "identity"
    identity.mkdir()
    (identity / "device-pepper").write_bytes(PEPPER)
    (identity / "service-pepper").write_bytes(uuid4().bytes)
    (identity / "session-secret").write_bytes(uuid4().bytes)
    (tmp_path / "artifacts").mkdir()
    async with _disposable_cluster() as (data, pg_port, url, log_path):
        provider = AsyncSessionProvider(url)
        try:
            token, instance = uuid4().hex, uuid4()
            device = await seed_device(provider, token=token)
            now = datetime.now(UTC)
            async with provider() as db:
                db.add(ContextCollection(
                    device_id=device.id, profile="health_v1", requested_by="stability-process-crash",
                    idempotency_key=fault, status="requested", requested_at=now,
                    expires_at=now + timedelta(minutes=5),
                ))
                await db.commit()
            async with aiohttp.ClientSession(trust_env=False) as client, AsyncExitStack() as api, AsyncExitStack() as sockets:
                base, process = await api.enter_async_context(_restored_api(
                    tmp_path, url, application=_REPOSITORY_ROOT,
                ))
                ws = await _connect(client, sockets, f"{base}/agent/v1/connect", device.id, instance, token)
                command_id = (await _receive(ws, "command"))["command_id"]
                await _grant(ws, device.id, command_id)
                frame = _result(device.id, command_id, 5)
                if fault == "api_ack_lost":
                    await ws.send_json(frame)
                    await _await_commit(provider, command_id)

                failed_at = perf_counter()
                if fault == "postgres":
                    await _stop_db(data, "immediate")
                    await ws.send_json(frame)
                    closed = await ws.receive(timeout=10)
                    assert closed.type in {aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR}
                    await _start_db(data, pg_port, log_path)
                    assert "automatic recovery in progress" in log_path.read_text(encoding="utf-8")
                    assert process.returncode is None
                else:
                    process.kill()
                    await asyncio.wait_for(process.wait(), 10)
                    assert process.returncode != 0
                    await api.aclose()
                    recovered_base, _ = await api.enter_async_context(_restored_api(
                        tmp_path, url, application=_REPOSITORY_ROOT, port=urlsplit(base).port,
                    ))
                    assert recovered_base == base
                restored_at = perf_counter()
                restored = await _connect(client, sockets, f"{base}/agent/v1/connect", device.id, instance, token)
                await _send_result(restored, frame)
                await _send_result(restored, frame)
                await _assert_durable(provider, device.id, command_id)
                print(json.dumps({
                    "fault": fault, "restart_seconds": round(restored_at - failed_at, 3),
                    "total_seconds": round(perf_counter() - failed_at, 3),
                }), flush=True)
        finally:
            await provider.close()
