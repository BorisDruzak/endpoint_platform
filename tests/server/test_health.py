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
    def __init__(self) -> None:
        self.statement: object | None = None

    async def execute(self, statement: object) -> object:
        self.statement = statement
        return object()


class FailingSession:
    async def execute(self, statement: object) -> object:
        raise RuntimeError("database password=not-for-response")


class SuccessfulSessionProvider:
    def __init__(self) -> None:
        self.session = SuccessfulSession()

    @asynccontextmanager
    async def __call__(self) -> AsyncIterator[SuccessfulSession]:
        yield self.session


class ClosableSessionProvider:
    def __init__(self) -> None:
        self.close_calls = 0

    @asynccontextmanager
    async def __call__(self) -> AsyncIterator[SuccessfulSession]:
        yield SuccessfulSession()

    async def close(self) -> None:
        self.close_calls += 1


class _WorkerResult:
    class _Scalars:
        def all(self) -> list[object]:
            return []

    def scalars(self) -> "_WorkerResult._Scalars":
        return self._Scalars()


class WorkerSession:
    def __init__(self, *, fail_cleanup: bool = False) -> None:
        self.fail_cleanup = fail_cleanup
        self.commit_calls = 0
        self.rollback_calls = 0
        self.finished = asyncio.Event()

    async def execute(self, statement: object) -> _WorkerResult:
        del statement
        if self.fail_cleanup:
            raise RuntimeError("database password=worker-secret")
        return _WorkerResult()

    async def commit(self) -> None:
        self.commit_calls += 1
        self.finished.set()

    async def rollback(self) -> None:
        self.rollback_calls += 1
        self.finished.set()


class WorkerSessionProvider:
    def __init__(self, *, fail_cleanup: bool = False) -> None:
        self.session = WorkerSession(fail_cleanup=fail_cleanup)
        self.close_calls = 0

    @asynccontextmanager
    async def __call__(self) -> AsyncIterator[WorkerSession]:
        yield self.session

    async def close(self) -> None:
        self.close_calls += 1


@asynccontextmanager
async def failing_session() -> AsyncIterator[FailingSession]:
    yield FailingSession()


@asynccontextmanager
async def entering_failing_session() -> AsyncIterator[SuccessfulSession]:
    raise RuntimeError("database password=not-for-response")
    yield SuccessfulSession()


def synchronously_failing_session_provider() -> AsyncIterator[SuccessfulSession]:
    raise RuntimeError("database password=not-for-response")


@asynccontextmanager
async def exiting_failing_session() -> AsyncIterator[SuccessfulSession]:
    yield SuccessfulSession()
    raise RuntimeError("database password=not-for-response")


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
    provider = SuccessfulSessionProvider()
    app = create_app(_settings(), session_provider=provider)

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
    assert str(provider.session.statement) == "SELECT 1"


@pytest.mark.asyncio
async def test_healthz_hides_database_exception_details() -> None:
    """Returning a database exception could leak credentials or infrastructure details."""
    app = create_app(_settings(), session_provider=failing_session)

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.get("/healthz")

    assert response.status_code == 503
    assert response.json() == {
        "status": "unavailable",
        "service": "endpoint-platform",
        "database": "unavailable",
        "version": "0.0.0",
    }
    assert "password" not in response.text.lower()
    assert "not-for-response" not in response.text


@pytest.mark.asyncio
async def test_healthz_hides_exception_when_session_provider_fails_to_enter() -> None:
    """A connection failure before SELECT 1 must still be a generic health response."""
    app = create_app(_settings(), session_provider=entering_failing_session)

    async with AsyncClient(
        transport=ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://testserver",
    ) as client:
        response = await client.get("/healthz")

    assert response.status_code == 503
    assert response.json() == {
        "status": "unavailable",
        "service": "endpoint-platform",
        "database": "unavailable",
        "version": "0.0.0",
    }
    assert "password" not in response.text.lower()
    assert "not-for-response" not in response.text


@pytest.mark.asyncio
async def test_healthz_hides_exception_when_session_provider_raises_synchronously() -> (
    None
):
    """Creating a session context can fail before one is returned to the route."""
    app = create_app(
        _settings(), session_provider=synchronously_failing_session_provider
    )

    async with AsyncClient(
        transport=ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://testserver",
    ) as client:
        response = await client.get("/healthz")

    assert response.status_code == 503
    assert response.json() == {
        "status": "unavailable",
        "service": "endpoint-platform",
        "database": "unavailable",
        "version": "0.0.0",
    }


@pytest.mark.asyncio
async def test_healthz_hides_exception_when_session_provider_fails_to_exit() -> None:
    """A release failure after SELECT 1 must not bypass the generic health response."""
    app = create_app(_settings(), session_provider=exiting_failing_session)

    async with AsyncClient(
        transport=ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://testserver",
    ) as client:
        response = await client.get("/healthz")

    assert response.status_code == 503
    assert response.json() == {
        "status": "unavailable",
        "service": "endpoint-platform",
        "database": "unavailable",
        "version": "0.0.0",
    }
    assert "password" not in response.text.lower()
    assert "not-for-response" not in response.text


@pytest.mark.asyncio
async def test_app_lifespan_closes_default_session_provider() -> None:
    """Skipping session-provider cleanup would leave database connections open on shutdown."""
    provider = ClosableSessionProvider()
    app = create_app(_settings(), session_provider=provider)

    async with app.router.lifespan_context(app):
        assert provider.close_calls == 0

    assert provider.close_calls == 1


@pytest.mark.asyncio
async def test_worker_exits_when_cancelled() -> None:
    """A worker that ignores cancellation would block a graceful service shutdown."""
    task = asyncio.create_task(run_worker(_settings()))
    await asyncio.sleep(0)

    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task


@pytest.mark.asyncio
async def test_worker_commits_cleanup_and_does_not_close_injected_provider() -> None:
    """The worker must transact each batch without taking ownership of a test provider."""
    provider = WorkerSessionProvider()
    task = asyncio.create_task(
        run_worker(
            _settings(),
            provider,
            cleanup_interval_seconds=60,
        )
    )
    await asyncio.wait_for(provider.session.finished.wait(), timeout=1)

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert provider.session.commit_calls == 1
    assert provider.session.rollback_calls == 0
    assert provider.close_calls == 0


@pytest.mark.asyncio
async def test_worker_rolls_back_failed_cleanup_and_remains_cancellable() -> None:
    """One failed cleanup batch must roll back without preventing graceful shutdown."""
    provider = WorkerSessionProvider(fail_cleanup=True)
    task = asyncio.create_task(
        run_worker(
            _settings(),
            provider,
            cleanup_interval_seconds=60,
        )
    )
    await asyncio.wait_for(provider.session.finished.wait(), timeout=1)

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert provider.session.commit_calls == 0
    assert provider.session.rollback_calls == 1
    assert provider.close_calls == 0


@pytest.mark.asyncio
async def test_worker_closes_provider_it_creates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The default database engine belongs to the worker and must close on shutdown."""
    provider = WorkerSessionProvider()
    monkeypatch.setattr(
        "endpoint_server.worker.create_session_provider",
        lambda database_url: provider,
    )
    task = asyncio.create_task(
        run_worker(
            _settings(),
            cleanup_interval_seconds=60,
        )
    )
    await asyncio.wait_for(provider.session.finished.wait(), timeout=1)

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert provider.close_calls == 1


@pytest.mark.asyncio
async def test_worker_isolates_context_scheduler_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failed scheduler batch must not block retention or the following worker tick."""
    provider = WorkerSessionProvider()
    retained = asyncio.Event()

    async def failing_scheduler(_: WorkerSession) -> int:
        raise RuntimeError("scheduler database fault")

    async def successful_retention(_: WorkerSession) -> int:
        retained.set()
        return 0

    monkeypatch.setattr("endpoint_server.worker.schedule_due_collections", failing_scheduler)
    monkeypatch.setattr("endpoint_server.worker.retain_context_snapshots", successful_retention)
    task = asyncio.create_task(
        run_worker(
            _settings(),
            provider,
            cleanup_interval_seconds=0.01,
            context_schedule_interval_seconds=0.01,
            context_retention_interval_seconds=0.01,
        )
    )
    await asyncio.wait_for(retained.wait(), timeout=1)

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert provider.session.rollback_calls >= 1
    assert provider.session.commit_calls >= 2
