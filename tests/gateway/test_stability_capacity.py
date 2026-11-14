"""Opt-in loopback capacity measurements against the migrated Gateway."""

from __future__ import annotations

import asyncio
from contextlib import AsyncExitStack
from dataclasses import replace
from datetime import UTC, datetime, timedelta
import ipaddress
import json
import math
import os
import socket
from time import perf_counter
from uuid import uuid4

import aiohttp
import pytest
from sqlalchemy import func, select
import uvicorn

from endpoint_contracts.gateway_ws import COMMAND_JOURNAL_FEATURE, COMMAND_JOURNAL_HEADER
from endpoint_server.context.models import ContextCollection, ContextSnapshot
from endpoint_server.db.models import DeviceSession
from endpoint_server.main import create_app
from tests.gateway.conftest import agent_hello, gateway_settings, seed_device
from tests.server.test_update_postgresql import update_service_database_url, update_service_provider


def _envelope(kind, sequence, payload):
    return {"schema_version": "gateway_ws_envelope_v1", "kind": kind,
            "sequence": sequence, "payload": payload}


def _metrics(samples):
    ordered = sorted(samples)
    return {label: round(1000 * ordered[math.ceil(len(ordered) * percentile) - 1], 1)
            for label, percentile in (("p50_ms", .50), ("p95_ms", .95), ("p99_ms", .99), ("max_ms", 1))}


async def _lag(samples):
    while True:
        started = perf_counter()
        await asyncio.sleep(.01)
        samples.append(max(0, perf_counter() - started - .01))


async def _receive(ws, kind):
    frame = await ws.receive_json(timeout=30)
    assert frame["kind"] == kind, frame
    return frame["payload"]


async def _sample(client, stack, origin, device_id, instance_id, token, sequence):
    started = perf_counter()
    ws = await _connect(client, stack, origin, device_id, instance_id, token)
    hello_seconds = perf_counter() - started
    command = await _receive(ws, "command")
    delivery_seconds = perf_counter() - started
    now = datetime.now(UTC).isoformat()
    await ws.send_json(_envelope("heartbeat", 1, {
        "schema_version": "agent_heartbeat_v1", "device_id": str(device_id),
        "platform": "linux", "agent_version": "4.0.0", "reported_at": now,
    }))
    ack_started = perf_counter()
    await _grant(ws, device_id, command["command_id"])
    start_seconds = perf_counter() - ack_started
    result_started = perf_counter()
    await _send_result(ws, _result(device_id, command["command_id"], sequence))
    return hello_seconds, delivery_seconds, start_seconds, perf_counter() - result_started


async def _connect(client, stack, origin, device_id, instance_id, token):
    ws = await stack.enter_async_context(client.ws_connect(origin, headers={
        "Authorization": f"Bearer {token}", "X-Forwarded-Proto": "https",
        "X-Forwarded-For": "127.0.0.1",
        COMMAND_JOURNAL_HEADER: "1",
    }))
    hello = agent_hello(device_id, instance_id=instance_id)
    hello.update(capabilities=["context.health.collect"], protocol_features=[COMMAND_JOURNAL_FEATURE])
    await ws.send_json(_envelope("agent_hello", 0, hello))
    await _receive(ws, "gateway_hello")
    return ws


async def _grant(ws, device_id, command_id):
    await ws.send_json(_envelope("command_ack", 2, {
        "schema_version": "agent_command_ack_v1", "device_id": str(device_id),
        "command_id": command_id, "status": "running", "acknowledged_at": datetime.now(UTC).isoformat(),
    }))
    grant = await _receive(ws, "command_start")
    assert grant["command_id"] == command_id


def _result(device_id, command_id, sequence):
    collected_at = datetime.now(UTC).isoformat()
    return _envelope("command_result", sequence, {
        "schema_version": "agent_result_v1", "device_id": str(device_id),
        "command_id": command_id, "status": "succeeded", "completed_at": collected_at,
        "result_items": [{
            "schema_version": "device_context_v1", "profile": "health_v1", "collected_at": collected_at,
            "warnings": [], "sections": {
                "resources": {"uptime_seconds": 100, "load_1m": 0.25, "free_bytes": 4096},
                "services": [{"name": "endpoint-agent-update.path", "status": "active"}],
            },
        }],
    })


async def _send_result(ws, frame):
    await ws.send_json(frame)
    result = await _receive(ws, "result_ack")
    assert result["command_id"] == frame["payload"]["command_id"]
    assert result["result_sequence"] == frame["sequence"]


@pytest.mark.parametrize("size", [8, 32, 96, 192])
@pytest.mark.skipif(os.getenv("ENDPOINT_STABILITY_CAPACITY") != "1", reason="opt-in loopback load rehearsal")
async def test_gateway_capacity(update_service_provider, update_service_database_url, tmp_path, size):
    provider = update_service_provider
    devices = []
    for _ in range(size):
        token = uuid4().hex
        device = await seed_device(provider, token=token)
        devices.append((device.id, uuid4(), token))
    device_ids = [device_id for device_id, _, _ in devices]
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    settings = replace(
        gateway_settings(artifact_root=artifacts), database_url=update_service_database_url,
        allowed_agent_cidrs=(ipaddress.ip_network("127.0.0.0/8"),),
    )
    app = create_app(settings, provider)
    server = uvicorn.Server(uvicorn.Config(app, ws="websockets", proxy_headers=False,
                                           log_level="error", timeout_graceful_shutdown=10))
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        origin = f"http://127.0.0.1:{listener.getsockname()[1]}/agent/v1/connect"
        serving = asyncio.create_task(server.serve(sockets=[listener]))
        try:
            async with asyncio.timeout(120):
                while not server.started:
                    if serving.done():
                        await serving
                        pytest.fail("loopback Gateway exited during startup")
                    await asyncio.sleep(.01)
                async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=0), trust_env=False) as client:
                    async with AsyncExitStack() as stack:
                        for wave in (1, 2):
                            now = datetime.now(UTC)
                            async with provider() as db:
                                db.add_all(ContextCollection(
                                    device_id=device_id, profile="health_v1", requested_by="stability-capacity",
                                    idempotency_key=f"wave-{wave}", status="requested", requested_at=now,
                                    expires_at=now + timedelta(minutes=5),
                                ) for device_id, _, _ in devices)
                                await db.commit()
                            lag = []
                            lag_task = asyncio.create_task(_lag(lag))
                            start = perf_counter()
                            try:
                                async with asyncio.TaskGroup() as group:
                                    tasks = [group.create_task(_sample(client, stack, origin, *device, 10 + wave))
                                             for device in devices]
                            finally:
                                lag_task.cancel()
                                await asyncio.gather(lag_task, return_exceptions=True)
                            elapsed = perf_counter() - start
                            async with provider() as db:
                                assert (await db.scalar(select(func.count()).select_from(ContextSnapshot)
                                                        .where(ContextSnapshot.device_id.in_(device_ids)))) == size * wave
                                assert (await db.scalar(select(func.count()).select_from(DeviceSession)
                                                        .where(DeviceSession.device_id.in_(device_ids),
                                                               DeviceSession.closed_at.is_(None)))) == size
                                assert (await db.scalar(select(func.count()).select_from(ContextCollection)
                                                        .where(ContextCollection.device_id.in_(device_ids),
                                                               ContextCollection.status != "completed"))) == 0
                            assert app.state.gateway_connection_registry.connection_count == size
                            clocks = zip(*(task.result() for task in tasks), strict=True)
                            print(json.dumps({
                                "devices": size, "wave": "cold" if wave == 1 else "replacement",
                                "elapsed_s": round(elapsed, 3), "results_per_s": round(size / elapsed, 1),
                                "lag": _metrics(lag),
                                **{name: _metrics(values) for name, values in zip(
                                    ("hello", "delivery", "start_ack", "result_ack"), clocks, strict=True,
                                )},
                            }), flush=True)
        finally:
            server.should_exit = True
            await asyncio.wait_for(serving, timeout=20)
