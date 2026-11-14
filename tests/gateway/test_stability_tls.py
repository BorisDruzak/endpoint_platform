"""Opt-in sustained Gateway rehearsal through a loopback HTTPS proxy."""

import asyncio
from contextlib import AsyncExitStack
from dataclasses import replace
from datetime import UTC, datetime, timedelta
import ipaddress
import json
import os
from pathlib import Path
import ssl
from time import perf_counter
from uuid import uuid4

import aiohttp
import pytest
from sqlalchemy import func, select
import uvicorn

from endpoint_server.context.models import ContextCollection, ContextSnapshot
from endpoint_server.db.models import DeviceSession
from endpoint_server.db.session import AsyncSessionProvider
from endpoint_server.main import create_app
from endpoint_server.worker import run_worker
from tests.gateway.conftest import gateway_settings, seed_device
from tests.gateway.test_stability_capacity import (
    _connect, _grant, _heartbeat, _lag, _metrics, _result, _send_result,
)
from tests.server.test_update_postgresql import update_service_database_url, update_service_provider


async def _open_all(client, stack, origin, devices):
    started = perf_counter()

    async def open_one(device):
        ws = await _connect(client, stack, origin, *device)
        elapsed = perf_counter() - started
        inbox = asyncio.Queue(maxsize=8)
        reader = asyncio.create_task(_read_frames(ws, inbox))
        stack.push_async_callback(_stop_reader, reader)
        return ws, inbox, elapsed

    opened = await asyncio.gather(*(open_one(device) for device in devices))
    return [(item[0], item[1]) for item in opened], _metrics([item[2] for item in opened])


async def _read_frames(ws, inbox):
    async for frame in ws:
        if frame.type == aiohttp.WSMsgType.TEXT:
            await inbox.put(json.loads(frame.data))
    await inbox.put({"kind": "closed", "code": ws.close_code})


async def _stop_reader(reader):
    reader.cancel()
    await asyncio.gather(reader, return_exceptions=True)


async def _next_frame(inbox, kind):
    frame = await asyncio.wait_for(inbox.get(), timeout=20)
    assert frame["kind"] == kind, frame
    return frame["payload"]


async def _complete(connection, device_id, result_sequence, *, received):
    ws, inbox = connection
    command = await _next_frame(inbox, "command")
    delivery = received()
    started = perf_counter()
    await _grant(ws, device_id, command["command_id"], receive=lambda kind: _next_frame(inbox, kind))
    acknowledged = perf_counter()
    await _send_result(ws, _result(device_id, command["command_id"], result_sequence),
                       receive=lambda kind: _next_frame(inbox, kind))
    return delivery, acknowledged - started, perf_counter() - acknowledged


def _phase_metrics(completions):
    return {name: _metrics(values) for name, values in zip(
        ("delivery_since_trigger", "start_ack", "result_ack"), zip(*completions, strict=True), strict=True,
    )}


@pytest.mark.skipif(not os.getenv("ENDPOINT_STABILITY_TLS_CA"), reason="opt-in loopback TLS rehearsal")
async def test_gateway_tls_with_worker(update_service_provider, update_service_database_url, tmp_path):
    provider = update_service_provider
    devices = []
    for _ in range(32):
        token = uuid4().hex
        device = await seed_device(provider, token=token)
        devices.append((device.id, uuid4(), token))
    ids = [device[0] for device in devices]
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    settings = replace(
        gateway_settings(artifact_root=artifacts), database_url=update_service_database_url,
        allowed_agent_cidrs=(ipaddress.ip_network("127.0.0.0/8"),), endpoint_policy_enabled=True,
    )
    app = create_app(settings, provider)
    server = uvicorn.Server(uvicorn.Config(
        app, host="127.0.0.1", port=18081, ws="wsproto", proxy_headers=False,
        log_level="error", timeout_graceful_shutdown=10,
    ))
    serving = asyncio.create_task(server.serve())
    worker_provider = AsyncSessionProvider(update_service_database_url)
    lag = []
    lag_task = asyncio.create_task(_lag(lag))
    worker = None
    try:
        async with asyncio.timeout(170):
            while not server.started:
                if serving.done():
                    await serving
                    pytest.fail("Gateway exited during startup")
                await asyncio.sleep(.025)
            ca = ssl.create_default_context(cafile=Path(os.environ["ENDPOINT_STABILITY_TLS_CA"]))
            origin = "https://localhost:18443/agent/v1/connect"
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=ca, limit=0), trust_env=False,
            ) as client, AsyncExitStack() as stack:
                first, hello_metrics = await _open_all(client, stack, origin, devices)
                worker = asyncio.create_task(run_worker(settings, worker_provider))
                start = perf_counter()
                # Worker schedules its initial profiles after a production-default 60 s tick.
                for interval in (30, 60, 90):
                    await asyncio.sleep(max(0, start + interval - perf_counter()))
                    await asyncio.gather(*(_heartbeat(ws, device_id, 10 + interval)
                                           for (ws, _), device_id in zip(first, ids, strict=True)))
                first_results = await asyncio.gather(*(
                    _complete(connection, device_id, 1000, received=lambda: perf_counter() - start)
                    for connection, device_id in zip(first, ids, strict=True)
                ))
                async with provider() as db:
                    health = await db.scalar(select(func.count()).select_from(ContextCollection).where(
                        ContextCollection.device_id.in_(ids), ContextCollection.profile == "health_v1",
                        ContextCollection.requested_by == "scheduler", ContextCollection.status == "completed",
                    ))
                    assert health == len(ids)
                    now = datetime.now(UTC)
                    db.add_all(ContextCollection(
                        device_id=device_id, profile="health_v1", requested_by="stability-tls",
                        idempotency_key="replacement", status="requested", requested_at=now,
                        expires_at=now + timedelta(minutes=5),
                    ) for device_id in ids)
                    await db.commit()
                replacement_started = perf_counter()
                second, replacement_metrics = await _open_all(client, stack, origin, devices)
                second_results = await asyncio.gather(*(
                    _complete(connection, device_id, 1001, received=lambda: perf_counter() - replacement_started)
                    for connection, device_id in zip(second, ids, strict=True)
                ))
                await asyncio.sleep(max(0, start + 125 - perf_counter()))
                await asyncio.gather(*(_heartbeat(ws, device_id, 1010)
                                       for (ws, _), device_id in zip(second, ids, strict=True)))
                assert not worker.done()
                assert app.state.gateway_connection_registry.connection_count == len(ids)
                async with provider() as db:
                    assert await db.scalar(select(func.count()).select_from(ContextSnapshot).where(
                        ContextSnapshot.device_id.in_(ids), ContextSnapshot.profile == "health_v1",
                    )) == 2 * len(ids)
                    assert await db.scalar(select(func.count()).select_from(DeviceSession).where(
                        DeviceSession.device_id.in_(ids), DeviceSession.closed_at.is_(None),
                    )) == len(ids)
                print(json.dumps({
                    "tls_devices": len(ids), "steady_seconds": round(perf_counter() - start, 3),
                    "hello": hello_metrics, "replacement_hello": replacement_metrics,
                    "worker_wave": _phase_metrics(first_results),
                    "replacement_wave": _phase_metrics(second_results), "lag": _metrics(lag),
                }), flush=True)
    finally:
        tasks = [lag_task] if worker is None else [lag_task, worker]
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await worker_provider.close()
        server.should_exit = True
        await asyncio.wait_for(serving, 20)
