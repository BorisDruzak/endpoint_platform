"""Opt-in failure drill against disposable, migrated loopback PostgreSQL."""

import asyncio
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
import ipaddress
import json
import os
import re
import socket
from time import perf_counter
from uuid import UUID, uuid4

import aiohttp
import asyncpg
import pytest
from sqlalchemy import func, select
from sqlalchemy.engine import make_url
import uvicorn

from endpoint_server.context.models import ContextCollection, ContextSnapshot
from endpoint_server.db.models import CommandResult, DeviceSession
from endpoint_server.main import create_app
from endpoint_server.worker import run_worker
from tests.gateway.conftest import gateway_settings, seed_device
from tests.gateway.test_stability_capacity import _connect, _grant, _receive, _result, _send_result
from tests.server.test_update_postgresql import update_service_database_url, update_service_provider


@asynccontextmanager
async def _api(settings, provider):
    app = create_app(settings, provider)
    server = uvicorn.Server(uvicorn.Config(
        app, ws="websockets", proxy_headers=False, log_level="critical", timeout_graceful_shutdown=5,
    ))
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        base_url = f"http://127.0.0.1:{listener.getsockname()[1]}"
        task = asyncio.create_task(server.serve(sockets=[listener]))
        try:
            async with asyncio.timeout(10):
                while not server.started:
                    if task.done():
                        await task
                        pytest.fail("Gateway exited during start")
                    await asyncio.sleep(.01)
            yield base_url
        finally:
            server.should_exit = True
            await asyncio.wait_for(task, 10)


@asynccontextmanager
async def _database_unavailable(database_url):
    name = make_url(database_url).database
    assert re.fullmatch(r"endpoint_update_service_[a-f0-9]{32}", name)
    admin_url = make_url(os.environ["ENDPOINT_TEST_POSTGRES_URL"])
    assert admin_url.host in {"127.0.0.1", "localhost", "::1"}
    admin = await asyncpg.connect(admin_url.set(drivername="postgresql").render_as_string(hide_password=False))
    try:
        await admin.execute(f'ALTER DATABASE "{name}" ALLOW_CONNECTIONS false')
        try:
            terminated = await admin.fetch("""
                SELECT pg_terminate_backend(pid, 3000) FROM pg_stat_activity WHERE datname=$1
                """, name)
            assert all(row[0] for row in terminated)
            yield
        finally:
            await admin.execute(f'ALTER DATABASE "{name}" ALLOW_CONNECTIONS true')
    finally:
        await admin.close()


@asynccontextmanager
async def _running_worker(settings, provider):
    task = asyncio.create_task(run_worker(
        settings, provider, cleanup_interval_seconds=.25, context_schedule_interval_seconds=.25,
    ))
    try:
        yield task
    finally:
        task.cancel()
        result, = await asyncio.gather(task, return_exceptions=True)
        assert isinstance(result, asyncio.CancelledError), result


async def _wait_for_schedule(provider, device_id, worker):
    async with asyncio.timeout(10):
        while True:
            if worker.done():
                await worker
                pytest.fail("worker exited")
            async with provider() as db:
                scheduled = await db.scalar(select(func.count()).select_from(ContextCollection).where(
                    ContextCollection.device_id == device_id, ContextCollection.requested_by == "scheduler",
                ))
            if scheduled:
                assert scheduled == 5
                return
            await asyncio.sleep(.05)


@pytest.mark.skipif(os.getenv("ENDPOINT_STABILITY_RECOVERY") != "1", reason="opt-in recovery rehearsal")
@pytest.mark.parametrize("failure", ["api", "database"])
async def test_recover_gateway_and_worker(update_service_provider, update_service_database_url, tmp_path, failure, caplog):
    provider = update_service_provider
    token = uuid4().hex
    device = await seed_device(provider, token=token)
    instance_id = uuid4()
    root = tmp_path / "artifacts"
    root.mkdir()
    settings = replace(
        gateway_settings(artifact_root=root), database_url=update_service_database_url,
        allowed_agent_cidrs=(ipaddress.ip_network("127.0.0.0/8"),),
    )
    caplog.set_level("WARNING", logger="endpoint_server.worker")
    now = datetime.now(UTC)
    async with provider() as db:
        db.add(ContextCollection(
            device_id=device.id, profile="health_v1", requested_by="stability-recovery",
            idempotency_key="before-failure", status="requested", requested_at=now,
            expires_at=now + timedelta(minutes=5),
        ))
        await db.commit()

    async with aiohttp.ClientSession(trust_env=False) as client:
        async with AsyncExitStack() as api, AsyncExitStack() as first:
            base = await api.enter_async_context(_api(settings, provider))
            ws = await _connect(client, first, f"{base}/agent/v1/connect", device.id, instance_id, token)
            command = await _receive(ws, "command")
            await _grant(ws, device.id, command["command_id"])
            frame = _result(device.id, command["command_id"], 5)
            if failure == "database":
                # Let a real worker attempt its jobs while the database is down,
                # then require scheduling to recover in that same worker.
                worker_device = await seed_device(provider, token=uuid4().hex)
                async with _database_unavailable(update_service_database_url):
                    worker = await first.enter_async_context(_running_worker(settings, provider))
                    await ws.send_json(frame)
                    broken = await ws.receive(timeout=10)
                    assert broken.type in {aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR}
                    async with asyncio.timeout(10):
                        while not any("last_success=none" in entry.message and "safe_error=" in entry.message
                                      and "safe_error=none" not in entry.message for entry in caplog.records):
                            if worker.done():
                                await worker
                                pytest.fail("worker exited during database outage")
                            await asyncio.sleep(.025)
                resumed_at = perf_counter()
            else:
                resumed_at = perf_counter()
                await api.aclose()
                base = await api.enter_async_context(_api(settings, provider))
            async with AsyncExitStack() as recovery:
                ws = await _connect(client, recovery, f"{base}/agent/v1/connect", device.id, instance_id, token)
                await _send_result(ws, frame)
                await _send_result(ws, frame)
                recovered_at = perf_counter()
                async with provider() as db:
                    assert await db.scalar(select(func.count()).select_from(CommandResult)
                                           .where(CommandResult.command_id == UUID(command["command_id"]))) == 1
                    assert await db.scalar(select(func.count()).select_from(ContextSnapshot)
                                           .where(ContextSnapshot.device_id == device.id)) == 1
                    assert await db.scalar(select(func.count()).select_from(DeviceSession)
                                           .where(DeviceSession.device_id == device.id,
                                                  DeviceSession.closed_at.is_(None))) == 1
            if failure == "database":
                await _wait_for_schedule(provider, worker_device.id, worker)
                worker_recovered_at = perf_counter()

    started = perf_counter()
    worker_devices = []
    for run in range(2):
        worker_device = await seed_device(provider, token=uuid4().hex)
        worker_devices.append(worker_device.id)
        async with _running_worker(settings, provider) as worker:
            await _wait_for_schedule(provider, worker_device.id, worker)
        if run == 1:
            async with provider() as db:
                assert await db.scalar(select(func.count()).select_from(ContextCollection).where(
                    ContextCollection.device_id.in_(worker_devices), ContextCollection.requested_by == "scheduler",
                )) == 10
    print(json.dumps({"failure": failure, "gateway_and_result_seconds": round(recovered_at - resumed_at, 3),
                      "worker_after_database_seconds": round(worker_recovered_at - resumed_at, 3) if failure == "database" else None,
                      "worker_schedule_and_restart_seconds": round(perf_counter() - started, 3)}), flush=True)
