"""Opt-in sustained Gateway rehearsal through a loopback HTTPS proxy."""

import asyncio
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
import ipaddress
import json
import os
from pathlib import Path
import ssl
import sys
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
    _connect, _grant, _heartbeat, _metrics, _result, _send_result,
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
            await inbox.put((json.loads(frame.data), perf_counter()))
    await inbox.put(({"kind": "closed", "code": ws.close_code}, perf_counter()))


async def _stop_reader(reader):
    reader.cancel()
    await asyncio.gather(reader, return_exceptions=True)


async def _next_frame(inbox, kind, *, timed=False):
    frame, received = await asyncio.wait_for(inbox.get(), timeout=20)
    assert frame["kind"] == kind, frame
    return (frame["payload"], received) if timed else frame["payload"]


async def _complete(connection, device_id, result_sequence, *, started_at):
    ws, inbox = connection
    command, received = await _next_frame(inbox, "command", timed=True)
    delivery = received - started_at
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


def _settings(database_url, artifacts):
    return replace(
        gateway_settings(artifact_root=artifacts), database_url=database_url,
        allowed_agent_cidrs=(ipaddress.ip_network("127.0.0.0/8"),), endpoint_policy_enabled=True,
    )


@asynccontextmanager
async def _process(role, scratch, database_url, artifacts):
    env = {
        **os.environ,
        "ENDPOINT_STABILITY_TLS_DATABASE": database_url,
        "ENDPOINT_STABILITY_TLS_ARTIFACTS": str(artifacts),
    }
    log_path = scratch / f"{role}.log"
    with log_path.open("wb") as log:
        process = await asyncio.create_subprocess_exec(
            sys.executable, "-m", "tests.gateway.test_stability_tls", role,
            env=env, stdout=log, stderr=asyncio.subprocess.STDOUT,
        )
    try:
        yield process
    finally:
        if process.returncode is None:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), 15)
            except TimeoutError:
                process.kill()
                await process.wait()
        if process.returncode not in (0, -15):
            pytest.fail(f"{role} exited {process.returncode}. Log: {log_path}")


async def _sample_gateway(pool, samples):
    while True:
        started = perf_counter()
        await asyncio.sleep(.01)
        sampled = perf_counter()
        samples.append((sampled, max(0, sampled - started - .01), pool.checkedout(), pool.overflow()))


def _pool_window(samples, started_at, finished_at):
    window = [(checked_out, overflow) for sampled_at, _, checked_out, overflow in samples
              if started_at <= sampled_at <= finished_at]
    if not window:
        return None
    return {
        "samples": len(window),
        "checked_out_peak": max(count for count, _ in window),
        "overflow_peak": max(0, max(overflow for _, overflow in window)),
        # AsyncSessionProvider uses the SQLAlchemy default max_overflow of 10.
        "at_capacity_samples": sum(count >= 15 for count, _ in window),
    }


async def _run_child(role):
    settings = _settings(
        os.environ["ENDPOINT_STABILITY_TLS_DATABASE"], Path(os.environ["ENDPOINT_STABILITY_TLS_ARTIFACTS"]),
    )
    if role == "worker":
        provider = AsyncSessionProvider(settings.database_url)
        try:
            await run_worker(settings, provider)
        finally:
            await provider.close()
        return
    if role != "gateway":
        raise ValueError("unexpected TLS rehearsal process role")
    app = create_app(settings)
    pool = app.state.session_provider.engine.pool
    assert pool.size() == 5, "update the pool capacity used by the sampler"
    samples = []

    @app.get("/_stability_metrics")
    async def stability_metrics(started_at: float | None = None, finished_at: float | None = None):
        return {
            "pid": os.getpid(),
            "lag": _metrics([sample[1] for sample in samples]) if samples else None,
            "owners": app.state.gateway_connection_registry.connection_count,
            "pool": _pool_window(samples, started_at, finished_at)
            if started_at is not None and finished_at is not None else None,
        }

    sampler = asyncio.create_task(_sample_gateway(pool, samples))
    try:
        await uvicorn.Server(uvicorn.Config(
            app, host="127.0.0.1", port=18081, ws="wsproto", proxy_headers=False,
            log_level="error", timeout_graceful_shutdown=10,
        )).serve()
    finally:
        sampler.cancel()
        await asyncio.gather(sampler, return_exceptions=True)


async def _gateway_metrics(client, **window):
    async with client.get("http://127.0.0.1:18081/_stability_metrics", params=window) as response:
        response.raise_for_status()
        return await response.json()


@pytest.mark.skipif(not os.getenv("ENDPOINT_STABILITY_TLS_CA"), reason="opt-in loopback TLS rehearsal")
async def test_gateway_tls_with_worker(update_service_provider, update_service_database_url, tmp_path):
    provider = update_service_provider
    devices = []
    size = int(os.getenv("ENDPOINT_STABILITY_TLS_DEVICES", "32"))
    assert size in {8, 32, 96, 192}
    for _ in range(size):
        token = uuid4().hex
        device = await seed_device(provider, token=token)
        devices.append((device.id, uuid4(), token))
    ids = [device[0] for device in devices]
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    ca = ssl.create_default_context(cafile=Path(os.environ["ENDPOINT_STABILITY_TLS_CA"]))
    origin = "https://localhost:18443/agent/v1/connect"
    async with asyncio.timeout(190), AsyncExitStack() as stack:
        gateway = await stack.enter_async_context(_process("gateway", tmp_path, update_service_database_url, artifacts))
        client = await stack.enter_async_context(aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=ca, limit=0), trust_env=False,
        ))
        async with asyncio.timeout(20):
            while True:
                assert gateway.returncode is None, "Gateway exited during startup"
                try:
                    metrics = await _gateway_metrics(client)
                    break
                except aiohttp.ClientConnectionError:
                    await asyncio.sleep(.05)
        assert metrics["pid"] == gateway.pid and metrics["pid"] != os.getpid()
        hello_started = perf_counter()
        first, hello_metrics = await _open_all(client, stack, origin, devices)
        start = perf_counter()
        worker = await stack.enter_async_context(_process("worker", tmp_path, update_service_database_url, artifacts))
        assert worker.pid not in {gateway.pid, os.getpid()}
        for interval in (30, 60):
            await asyncio.sleep(max(0, start + interval - perf_counter()))
            await asyncio.gather(*(_heartbeat(ws, device_id, 10 + interval)
                                   for (ws, _), device_id in zip(first, ids, strict=True)))
        await asyncio.sleep(max(0, start + 90 - perf_counter()))
        worker_wave_started = perf_counter()
        await asyncio.gather(*(_heartbeat(ws, device_id, 100)
                               for (ws, _), device_id in zip(first, ids, strict=True)))
        first_results = await asyncio.gather(*(
            _complete(connection, device_id, 1000, started_at=start)
            for connection, device_id in zip(first, ids, strict=True)
        ))
        worker_wave_finished = perf_counter()
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
            _complete(connection, device_id, 1001, started_at=replacement_started)
            for connection, device_id in zip(second, ids, strict=True)
        ))
        replacement_finished = perf_counter()
        replacement_seconds = replacement_finished - replacement_started
        await asyncio.sleep(max(0, start + 125 - perf_counter()))
        await asyncio.gather(*(_heartbeat(ws, device_id, 1010)
                               for (ws, _), device_id in zip(second, ids, strict=True)))
        assert worker.returncode is None
        windows = {
            "hello": (hello_started, start),
            "worker_wave": (worker_wave_started, worker_wave_finished),
            "replacement": (replacement_started, replacement_finished),
        }
        pool_metrics = {}
        for phase, (started_at, finished_at) in windows.items():
            metrics = await _gateway_metrics(client, started_at=started_at, finished_at=finished_at)
            assert metrics["owners"] == len(ids)
            assert metrics["pool"] is not None
            pool_metrics[phase] = metrics["pool"]
        async with provider() as db:
            assert await db.scalar(select(func.count()).select_from(ContextSnapshot).where(
                ContextSnapshot.device_id.in_(ids), ContextSnapshot.profile == "health_v1",
            )) == 2 * len(ids)
            assert await db.scalar(select(func.count()).select_from(DeviceSession).where(
                DeviceSession.device_id.in_(ids), DeviceSession.closed_at.is_(None),
            )) == len(ids)
        print(json.dumps({
            "tls_devices": len(ids), "steady_seconds": round(perf_counter() - start, 3),
            "replacement_seconds": round(replacement_seconds, 3),
            "hello": hello_metrics, "replacement_hello": replacement_metrics,
            "worker_wave": _phase_metrics(first_results),
            "replacement_wave": _phase_metrics(second_results), "gateway_lag": metrics["lag"],
            "gateway_pool": pool_metrics,
            "gateway_pid": gateway.pid, "worker_pid": worker.pid, "client_pid": os.getpid(),
        }), flush=True)


if __name__ == "__main__":
    asyncio.run(_run_child(sys.argv[1]))
