from __future__ import annotations

import asyncio
import os
import subprocess
import sys
from contextlib import asynccontextmanager
from ipaddress import ip_network
from pathlib import Path
from typing import AsyncIterator
from uuid import UUID

import pytest
from httpx import ASGITransport, AsyncClient

from endpoint_server.config import Settings
from endpoint_server.main import create_app
from endpoint_server.worker import run_worker
from endpoint_server.activity.analytics_models import ActivityDaily


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
    def first(self) -> None:
        return None

    class _Scalars:
        def all(self) -> list[object]:
            return []

    def scalars(self) -> "_WorkerResult._Scalars":
        return self._Scalars()


class WorkerSession:
    def __init__(self, *, fail_cleanup: bool = False, fail_analytics: bool = False) -> None:
        self.fail_cleanup = fail_cleanup
        self.fail_analytics = fail_analytics
        self.commit_calls = 0
        self.rollback_calls = 0
        self.finished = asyncio.Event()
        self.operation_expiry_finished = asyncio.Event()
        self.analytics_finished = asyncio.Event()
        self.completed_jobs: list[str] = []
        self._job: str | None = None

    async def execute(self, statement: object) -> _WorkerResult:
        if getattr(statement, "column_descriptions", [{}])[0].get("entity") is ActivityDaily:
            return _WorkerResult()
        del statement
        self._job = "cleanup"
        if self.fail_cleanup:
            raise RuntimeError("database password=worker-secret")
        return _WorkerResult()

    async def scalars(self, statement: object) -> _WorkerResult._Scalars:
        self._job = "analytics" if statement.column_descriptions[0].get("entity") is ActivityDaily else "operation_expiry"
        if self._job == "analytics" and self.fail_analytics:
            raise RuntimeError("analytics database failure")
        return _WorkerResult._Scalars()

    async def scalar(self, statement: object) -> None:
        return None

    async def flush(self) -> None:
        return None

    async def commit(self) -> None:
        self.commit_calls += 1
        self.completed_jobs.append(self._job)
        self.finished.set()
        if self._job == "operation_expiry":
            self.operation_expiry_finished.set()
        if self._job == "analytics":
            self.analytics_finished.set()

    async def rollback(self) -> None:
        self.rollback_calls += 1
        self.completed_jobs.append(self._job)
        self.finished.set()
        if self._job == "operation_expiry":
            self.operation_expiry_finished.set()
        if self._job == "analytics":
            self.analytics_finished.set()


class WorkerSessionProvider:
    def __init__(self, *, fail_cleanup: bool = False, fail_analytics: bool = False) -> None:
        self.session = WorkerSession(fail_cleanup=fail_cleanup, fail_analytics=fail_analytics)
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
@pytest.mark.parametrize("free_gib, expected", [(1, "low"), (8, "ok")])
async def test_worker_artifact_disk_pressure_is_read_only_and_redacted(
    monkeypatch, caplog, tmp_path, free_gib, expected
):
    import logging
    from collections import namedtuple
    from endpoint_server import worker

    usage = namedtuple("Usage", "total used free")
    root = tmp_path / "private-release-location"
    root.mkdir()
    release = root / "immutable-release.zip"
    release.write_bytes(b"release")
    gib = 1024**3
    monkeypatch.setattr(worker.shutil, "disk_usage",
                        lambda path: usage(100 * gib, (100 - free_gib) * gib, free_gib * gib))
    with caplog.at_level(logging.INFO, logger=worker.__name__):
        await worker._report_artifact_disk_pressure(root)
    assert f"artifact_disk status={expected} free_bytes={free_gib * gib}" in caplog.text
    assert root.name not in caplog.text
    assert release.read_bytes() == b"release"


def test_worker_module_fails_closed_when_runtime_settings_are_missing() -> None:
    """An executable worker module must load settings instead of exiting idle."""
    environment = dict(os.environ)
    for name in (
        "DATABASE_URL",
        "PUBLIC_BASE_URL",
        "DEVICE_TOKEN_PEPPER_FILE",
        "SERVICE_TOKEN_PEPPER_FILE",
        "SESSION_SECRET_FILE",
        "ALLOWED_AGENT_CIDRS",
        "ALLOWED_ADMIN_CIDRS",
        "ARTIFACT_ROOT",
    ):
        environment.pop(name, None)
    completed = subprocess.run(
        [sys.executable, "-m", "endpoint_server.worker"],
        capture_output=True,
        cwd=Path(__file__).parents[2],
        env=environment,
        text=True,
        timeout=5,
    )

    assert completed.returncode != 0
    assert "DATABASE_URL is required" in completed.stderr


@pytest.fixture
def isolated_maintenance_jobs(monkeypatch: pytest.MonkeyPatch) -> None:
    # These transaction-domain tests exercise cleanup, expiry and analytics.
    # Setup preparation/fleet transactions have their own scheduler tests.
    from endpoint_server import worker

    async def preparation_noop(session):
        session._job = "preparation"
        return 0

    async def fleet_noop(provider):
        del provider

    async def isolated_transaction(provider, job, **kwargs):
        if job is fleet_noop:
            return None
        return await transactional_job(provider, job, **kwargs)

    transactional_job = worker._run_transactional_job
    monkeypatch.setattr(worker, "advance_preparations", preparation_noop)
    monkeypatch.setattr(worker, "setup_preparation_backlog_age", preparation_noop)
    monkeypatch.setattr(worker, "schedule_one_with_backlog", fleet_noop)
    monkeypatch.setattr(worker, "_run_transactional_job", isolated_transaction)


@pytest.mark.asyncio
async def test_worker_commits_cleanup_and_does_not_close_injected_provider(isolated_maintenance_jobs) -> None:
    """The worker must transact each batch without taking ownership of a test provider."""
    provider = WorkerSessionProvider()
    task = asyncio.create_task(
        run_worker(
            _settings(),
            provider,
            cleanup_interval_seconds=60,
        )
    )
    await asyncio.wait_for(
        provider.session.analytics_finished.wait(),
        timeout=1,
    )

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert provider.session.commit_calls == 4
    assert provider.session.rollback_calls == 0
    assert provider.session.completed_jobs == ["cleanup", "operation_expiry", "preparation", "analytics"]
    assert provider.close_calls == 0


@pytest.mark.asyncio
async def test_worker_rolls_back_failed_cleanup_and_remains_cancellable(isolated_maintenance_jobs) -> None:
    """One failed cleanup batch must roll back without preventing graceful shutdown."""
    provider = WorkerSessionProvider(fail_cleanup=True)
    task = asyncio.create_task(
        run_worker(
            _settings(),
            provider,
            cleanup_interval_seconds=60,
        )
    )
    await asyncio.wait_for(
        provider.session.analytics_finished.wait(),
        timeout=1,
    )

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert provider.session.commit_calls == 3
    assert provider.session.rollback_calls == 1
    assert provider.session.completed_jobs == ["cleanup", "operation_expiry", "preparation", "analytics"]
    assert provider.close_calls == 0


@pytest.mark.asyncio
async def test_worker_rolls_back_failed_analytics_without_rolling_back_sibling_jobs(isolated_maintenance_jobs) -> None:
    provider = WorkerSessionProvider(fail_analytics=True)
    task = asyncio.create_task(run_worker(_settings(), provider, cleanup_interval_seconds=60))
    await asyncio.wait_for(provider.session.analytics_finished.wait(), timeout=1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert provider.session.commit_calls == 3
    assert provider.session.rollback_calls == 1
    assert provider.session.completed_jobs == ["cleanup", "operation_expiry", "preparation", "analytics"]
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

    async def failing_scheduler(_: WorkerSession, **_options) -> int:
        raise RuntimeError("scheduler database fault")

    async def successful_retention(_: WorkerSession) -> int:
        retained.set()
        return 0

    monkeypatch.setattr("endpoint_server.worker.schedule_due_collections_with_backlog", failing_scheduler)
    monkeypatch.setattr("endpoint_server.worker.retain_context_snapshots_with_backlog", successful_retention)
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


@pytest.mark.asyncio
async def test_worker_retries_context_schedule_from_last_committed_page(monkeypatch):
    from endpoint_server import worker

    provider = WorkerSessionProvider()
    jobs = worker.MaintenanceJobs(provider)
    first, second = UUID(int=1), UUID(int=2)
    cursors = []
    times = []
    original_commit = provider.session.commit

    async def schedule(_session, *, now, page_size, after_device_id):
        assert page_size == 16
        cursors.append(after_device_id)
        times.append(now)
        next_device = {None: first, first: second, second: None}[after_device_id]
        return worker.ContextScheduleBatch(1, 1.0, next_device)

    async def commit():
        if len(cursors) == 2:
            raise RuntimeError("commit failed")
        await original_commit()

    monkeypatch.setattr(worker, "schedule_due_collections_with_backlog", schedule)
    monkeypatch.setattr(provider.session, "commit", commit)
    due_at = asyncio.get_running_loop().time()

    cursor = await worker._run_context_schedule(jobs, due_at=due_at, after_device_id=None)
    assert cursor == first
    assert await worker._run_context_schedule(jobs, due_at=due_at, after_device_id=cursor) is None
    assert cursors == [None, first, first, second]
    assert times[0] == times[1] and times[2] == times[3]
    assert provider.session.commit_calls == 3
    assert provider.session.rollback_calls == 1


@pytest.mark.asyncio
async def test_worker_reports_context_lateness_only_after_commit(monkeypatch, caplog):
    from endpoint_server import worker

    provider = WorkerSessionProvider()
    sampled = asyncio.Event()
    calls = 0

    async def schedule(_session, **_options):
        nonlocal calls
        calls += 1
        return worker.ContextScheduleBatch(1, 240.0)

    async def commit():
        if calls == 1 and not sampled.is_set():
            sampled.set()
            raise RuntimeError("private details")

    monkeypatch.setattr(worker, "schedule_due_collections_with_backlog", schedule)
    monkeypatch.setattr(provider.session, "commit", commit)
    with caplog.at_level("INFO", logger=worker.__name__):
        task = asyncio.create_task(run_worker(
            _settings(), provider, cleanup_interval_seconds=0.01, context_schedule_interval_seconds=0.01,
        ))
        try:
            async with asyncio.timeout(2):
                while calls < 2:
                    await asyncio.sleep(0.01)
        finally:
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
    records = [record.message for record in caplog.records
               if record.message.startswith("worker_job job=schedule_due_collections ")]
    starts = [record.message for record in caplog.records
              if record.message.startswith("worker_job_started job=schedule_due_collections ")]
    for start, completed in zip(starts[:2], records[:2], strict=True):
        assert start.split()[2] == completed.split()[2]
    assert "data_backlog_age_seconds=unknown" in records[0]
    assert "safe_error=commit_outcome_unknown" in records[0]
    assert "data_backlog_age_seconds=240.000" in records[1]
    assert "private details" not in caplog.text


@pytest.mark.asyncio
async def test_worker_runs_payload_cleanup_on_minute_cadence_independently_of_snapshot_retention(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = WorkerSessionProvider()
    completed = asyncio.Event()
    calls: list[str] = []

    async def record(name: str, _: WorkerSession) -> int:
        calls.append(name)
        if len(calls) == 5:
            completed.set()
        return 0

    for name, implementation in (
        ("cleanup_raw_context_payloads", "cleanup_raw_context_payloads_with_backlog"),
        ("cleanup_context_collections", "cleanup_context_collections_with_backlog"),
        ("cleanup_operation_results", "cleanup_operation_results"),
        ("cleanup_module_step_results", "cleanup_module_step_results_with_backlog"),
        ("retain_security_events", "retain_security_events_with_backlog"),
    ):
        monkeypatch.setattr(
            "endpoint_server.worker." + implementation,
            lambda session, job=name: record(job, session),
        )
    task = asyncio.create_task(run_worker(
        _settings(), provider,
        cleanup_interval_seconds=0.01,
        context_schedule_interval_seconds=60,
        context_retention_interval_seconds=3600,
    ))
    try:
        await asyncio.wait_for(completed.wait(), timeout=1)
    finally:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    assert calls == [
        "cleanup_raw_context_payloads", "cleanup_context_collections",
        "cleanup_operation_results", "cleanup_module_step_results",
        "retain_security_events",
    ]


@pytest.mark.asyncio
async def test_worker_periodic_jobs_keep_cadence_after_a_slow_batch(monkeypatch):
    from types import SimpleNamespace

    from endpoint_server import worker

    now = 0.0
    due_times = {"retain_security_events": [], "schedule_due_collections": [], "retain_context_snapshots": []}

    async def sleep(delay):
        nonlocal now
        now += delay
        if now >= 30:
            raise asyncio.CancelledError

    async def run_job(_self, name, _job, *, due_at, **_kwargs):
        nonlocal now
        if name in due_times:
            due_times[name].append(due_at)
        if name == "retain_security_events":
            now += 3

    async def disk_check(_root):
        pass

    clock = SimpleNamespace(time=lambda: now)
    monkeypatch.setattr(worker, "asyncio", SimpleNamespace(get_running_loop=lambda: clock, sleep=sleep))
    monkeypatch.setattr(worker.MaintenanceJobs, "run", run_job)
    monkeypatch.setattr(worker, "_report_artifact_disk_pressure", disk_check)
    with pytest.raises(asyncio.CancelledError):
        await run_worker(
            _settings(), WorkerSessionProvider(), cleanup_interval_seconds=10,
            context_schedule_interval_seconds=10, context_retention_interval_seconds=10,
        )
    assert due_times == {
        "retain_security_events": [10, 20],
        "schedule_due_collections": [10, 20],
        "retain_context_snapshots": [10, 20],
    }


@pytest.mark.asyncio
async def test_worker_records_attempt_before_database_checkout(caplog):
    from endpoint_server import worker

    checking_out = asyncio.Event()

    @asynccontextmanager
    async def provider():
        checking_out.set()
        await asyncio.Future()
        yield

    async def job(_session):
        pytest.fail("A job cannot run before checkout returns")

    jobs = worker.MaintenanceJobs(provider)
    with caplog.at_level("INFO", logger=worker.__name__):
        running = asyncio.create_task(jobs.run(
            "expire_operations", job, due_at=asyncio.get_running_loop().time(),
        ))
        try:
            async with asyncio.timeout(1):
                await checking_out.wait()
            records = [record.message for record in caplog.records]
            assert len(records) == 1
            assert records[0].startswith("worker_job_started job=expire_operations last_attempt=")
            assert "last_success=none" in records[0]
            assert "budget_seconds=15.0" in records[0]
        finally:
            running.cancel()
            with pytest.raises(asyncio.CancelledError):
                await running
    assert not any(record.message.startswith("worker_job ") for record in caplog.records)


@pytest.mark.asyncio
async def test_worker_budget_reports_stalled_job_and_allows_other_jobs(monkeypatch, caplog):
    from endpoint_server import worker

    provider = WorkerSessionProvider()
    started = asyncio.Event()
    sibling = asyncio.Event()

    async def stalled(*args, **kwargs):
        started.set()
        await asyncio.Future()

    async def expire(_session):
        sibling.set()

    async def noop(_session, **kwargs):
        return 0

    monkeypatch.setattr(worker, "_DEFAULT_JOB_BUDGET_SECONDS", 0.15, raising=False)
    monkeypatch.setattr(worker, "cleanup_expired_retry_envelopes", stalled)
    monkeypatch.setattr(worker, "expire_operations", expire)
    monkeypatch.setattr(worker, "advance_preparations", noop)
    monkeypatch.setattr(worker, "schedule_one_with_backlog", noop)
    monkeypatch.setattr(worker, "rebuild_daily", noop)
    with caplog.at_level("INFO", logger=worker.__name__):
        task = asyncio.create_task(run_worker(_settings(), provider))
        try:
            async with asyncio.timeout(1):
                await started.wait()
                await sibling.wait()
                while "safe_error=job_timeout" not in caplog.text:
                    await asyncio.sleep(0.01)
            assert "job=cleanup_expired_retry_envelopes" in caplog.text
            assert "backlog_age_seconds=" in caplog.text
            assert "last_success=" in caplog.text
        finally:
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task


@pytest.mark.asyncio
async def test_worker_reports_data_backlog_independently_of_schedule_lag(caplog):
    from endpoint_server import worker

    jobs = worker.MaintenanceJobs(WorkerSessionProvider())

    async def oldest_age(_session):
        return 67.5

    async def failing_job(_session):
        raise RuntimeError("private details")

    now = asyncio.get_running_loop().time()
    await jobs.run("expire_operations", failing_job, due_at=now - 5, measure_backlog=oldest_age)
    await jobs.run("expire_operations", failing_job, due_at=now)
    assert "data_backlog_age_seconds=67.500" in caplog.records[-2].message
    assert "data_backlog_age_seconds=unknown" in caplog.records[-1].message
    assert "safe_error=job_failed" in caplog.records[-2].message
    assert "private details" not in caplog.text


@pytest.mark.asyncio
async def test_worker_reports_oldest_committed_fleet_evaluation_in_tick(caplog):
    from endpoint_server import worker

    batches = iter((
        worker.FleetScheduleBatch(True, 5),
        worker.FleetScheduleBatch(True, 20),
        worker.FleetScheduleBatch(False, None),
    ))

    async def evaluate(_session):
        return next(batches)

    with caplog.at_level("INFO", logger=worker.__name__):
        await worker.MaintenanceJobs(WorkerSessionProvider()).run(
            "schedule_fleet", evaluate, due_at=asyncio.get_running_loop().time(), batches=16,
            continue_if=lambda result: result.evaluated,
            committed_backlog=worker._committed_batch_backlog_age,
        )
    assert "data_backlog_age_seconds=20.000" in caplog.records[-1].message
    assert "safe_error=none" in caplog.records[-1].message


@pytest.mark.asyncio
async def test_worker_postgresql_reports_lock_timeout_and_rolls_back_without_blocking_sibling(caplog):
    from uuid import uuid4

    from sqlalchemy import text
    from sqlalchemy.engine import make_url
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from endpoint_server import worker

    url = os.environ.get("ENDPOINT_TEST_POSTGRES_URL")
    if not url:
        pytest.skip("set ENDPOINT_TEST_POSTGRES_URL to a disposable loopback PostgreSQL server")
    parsed = make_url(url)
    if parsed.host not in {"127.0.0.1", "localhost", "::1"} or parsed.query:
        pytest.fail("worker lock test requires a disposable loopback PostgreSQL server")

    engine = create_async_engine(parsed.set(drivername="postgresql+asyncpg"))
    table = f"worker_lock_{uuid4().hex}"
    provider = async_sessionmaker(engine)
    sibling_finished = asyncio.Event()
    try:
        async with engine.begin() as db:
            await db.execute(text(f"CREATE TABLE {table} (id integer PRIMARY KEY, value integer)"))
            await db.execute(text(f"INSERT INTO {table} VALUES (1, 0), (2, 0)"))

        async def blocked(session):
            await session.execute(text(f"UPDATE {table} SET value=10 WHERE id=2"))
            await session.execute(text(f"UPDATE {table} SET value=10 WHERE id=1"))

        async def sibling(session):
            assert await session.scalar(text(f"SELECT value FROM {table} WHERE id=2")) == 0
            sibling_finished.set()

        jobs = worker.MaintenanceJobs(provider)
        async with engine.begin() as holder:
            await holder.execute(text(f"SELECT id FROM {table} WHERE id=1 FOR UPDATE"))
            due = asyncio.get_running_loop().time()
            async with asyncio.timeout(8):
                await jobs.run("advance_preparations", blocked, due_at=due)
                await jobs.run("expire_operations", sibling, due_at=due)

        assert sibling_finished.is_set()
        assert "safe_error=lock_timeout" in caplog.text
        assert "advance_preparations" not in jobs.last_success

        async with engine.connect() as db:
            assert await db.scalar(text(f"SELECT sum(value) FROM {table}")) == 0
    finally:
        try:
            async with engine.begin() as db:
                await db.execute(text(f"DROP TABLE IF EXISTS {table}"))
        finally:
            await engine.dispose()


@pytest.mark.asyncio
async def test_worker_counts_confirmed_batch_when_session_cleanup_fails(caplog):
    from endpoint_server import worker

    commits = 0

    class Session:
        async def commit(self):
            nonlocal commits
            commits += 1

    @asynccontextmanager
    async def provider():
        yield Session()
        raise OSError("private cleanup detail")

    async def job(_session):
        return worker.FleetScheduleBatch(True, 67.5)

    jobs = worker.MaintenanceJobs(provider)
    await jobs.run(
        "schedule_fleet", job, due_at=asyncio.get_running_loop().time(), batches=16,
        committed_backlog=worker._committed_batch_backlog_age,
    )
    assert commits == 1
    assert "committed_batches=1 safe_error=session_cleanup_error" in caplog.text
    assert "data_backlog_age_seconds=67.500" in caplog.text
    assert "private cleanup detail" not in caplog.text
    assert jobs.last_success == {}


@pytest.mark.asyncio
async def test_worker_does_not_log_driver_details_or_retry_ambiguous_commit(caplog):
    from endpoint_server import worker

    commits = 0
    rollbacks = 0

    class Session:
        async def commit(self):
            nonlocal commits
            commits += 1
            raise OSError("password=fixture-secret")

        async def rollback(self):
            nonlocal rollbacks
            rollbacks += 1

    @asynccontextmanager
    async def provider():
        yield Session()

    async def job(_session):
        return True

    jobs = worker.MaintenanceJobs(provider)
    await jobs.run("schedule_fleet", job, due_at=asyncio.get_running_loop().time(), batches=16)
    assert commits == rollbacks == 1
    assert "safe_error=commit_outcome_unknown" in caplog.text
    assert "fixture-secret" not in caplog.text
    assert jobs.last_success == {}
