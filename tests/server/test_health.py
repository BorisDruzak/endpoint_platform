from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from ipaddress import ip_network
from pathlib import Path
from typing import AsyncIterator

import pytest
from httpx import ASGITransport, AsyncClient

from endpoint_server.config import Settings
from endpoint_server.main import create_app
from endpoint_server.worker import run_worker


class SuccessfulSession:
    async def execute(self, statement: object) -> object:
        return object()


class FailingSession:
    async def execute(self, statement: object) -> object:
        raise RuntimeError("database password=not-for-response")


@asynccontextmanager
async def successful_session() -> AsyncIterator[SuccessfulSession]:
    yield SuccessfulSession()


@asynccontextmanager
async def failing_session() -> AsyncIterator[FailingSession]:
    yield FailingSession()


def _settings() -> Settings:
    return Settings(
        database_url="postgresql+asyncpg://endpoint:password@db/endpoint",
        public_base_url="https://endpoint.sosnadmin.local",
        device_token_pepper=b"device-pepper",
        service_token_pepper=b"service-pepper",
        session_secret=b"session-secret",
        allowed_agent_cidrs=(ip_network("10.20.0.0/16"),),
        allowed_admin_cidrs=(ip_network("192.168.100.0/24"),),
        artifact_root=Path("artifacts"),
    )


@pytest.mark.asyncio
async def test_healthz_returns_exact_payload_when_database_is_available() -> None:
    """A broken health contract would cause load balancers to misclassify the service."""
    app = create_app(_settings(), session_provider=successful_session)

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.get("/healthz")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "endpoint-platform",
        "database": "ok",
        "version": "0.0.0",
    }


@pytest.mark.asyncio
async def test_healthz_hides_database_exception_details() -> None:
    """Returning a database exception could leak credentials or infrastructure details."""
    app = create_app(_settings(), session_provider=failing_session)

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.get("/healthz")

    assert response.status_code == 503
    assert response.json()["database"] == "unavailable"
    assert "password" not in response.text.lower()
    assert "not-for-response" not in response.text


@pytest.mark.asyncio
async def test_worker_exits_when_cancelled() -> None:
    """A worker that ignores cancellation would block a graceful service shutdown."""
    task = asyncio.create_task(run_worker(_settings()))
    await asyncio.sleep(0)

    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task
