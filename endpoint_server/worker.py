"""Background worker for bounded server maintenance jobs."""

from __future__ import annotations

import asyncio
import logging
import shutil
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from endpoint_server.config import Settings
from endpoint_server.context.retention import cleanup_context_collections, cleanup_raw_context_payloads, retain_context_snapshots
from endpoint_server.context.scheduler import ContextScheduleBatch, schedule_due_collections_with_backlog
from endpoint_server.db.session import SessionProvider, create_session_provider
from endpoint_server.enrollment.delivery import cleanup_expired_retry_envelopes, enrollment_retry_backlog_age
from endpoint_server.operations.service import expire_operations, operation_expiry_backlog_age
from endpoint_server.operations.evidence import (
    StepCleanupBatch, cleanup_module_step_results_with_backlog,
    cleanup_operation_results, operation_result_cleanup_backlog_age,
)
from endpoint_server.security.retention import retain_security_events
from endpoint_server.power.retention import retain_power_events
from endpoint_server.activity.analytics_store import analytics_backlog_age, rebuild_daily, retain_analytics
from endpoint_server.setup_updates.preparation import advance_preparations, setup_preparation_backlog_age
from endpoint_server.setup_updates.scheduler import schedule_one


logger = logging.getLogger(__name__)
_ARTIFACT_SPACE_WARNING_BYTES = 5 * 1024**3
_DEFAULT_JOB_BUDGET_SECONDS = 15.0
_ROLLBACK_BUDGET_SECONDS = 3.0
_JOB_BUDGETS = {
    "advance_preparations": 25.0,
    "schedule_fleet": 25.0,
    "rebuild_daily": 25.0,
    "schedule_due_collections": 30.0,
    "retain_context_snapshots": 30.0,
}
_SQL_TIMEOUTS = text(
    "SELECT set_config('lock_timeout', :lock, true), "
    "set_config('statement_timeout', :statement, true)"
)


async def _run_transactional_job(
    provider: SessionProvider,
    job: Callable[[Any], Awaitable[object]],
    *,
    budget: float | None = None,
) -> object:
    """Run one transaction, preserving commit uncertainty and task cancellation."""
    if budget is None:
        budget = _DEFAULT_JOB_BUDGET_SECONDS
    committed = False
    committing = False
    try:
        async with asyncio.timeout(budget):
            async with provider() as session:
                try:
                    dialect = getattr(getattr(session, "bind", None), "dialect", None)
                    if dialect is not None and dialect.name == "postgresql":
                        statement_ms = max(1, int(budget * 800))
                        await session.execute(_SQL_TIMEOUTS, {
                            "lock": f"{min(3000, max(1, statement_ms // 2))}ms",
                            "statement": f"{statement_ms}ms",
                        })
                    result = await job(session)
                    committing = True
                    await session.commit()
                    committed = True
                except (Exception, asyncio.CancelledError):
                    # The main deadline may have already fired. Give rollback
                    # its own bounded grace while preserving the original error.
                    try:
                        async with asyncio.timeout(_ROLLBACK_BUDGET_SECONDS):
                            await session.rollback()
                    except Exception:
                        logger.warning("worker_transaction safe_error=rollback_failed")
                    raise
    except Exception as error:
        if committed:
            raise MaintenanceFailure("session_cleanup_error") from error
        if committing:
            raise MaintenanceFailure("commit_outcome_unknown") from error
        if isinstance(error, TimeoutError):
            raise MaintenanceFailure("job_timeout") from error
        if isinstance(error, DBAPIError):
            code = {"55P03": "lock_timeout", "57014": "statement_timeout",
                    "40P01": "deadlock"}.get(getattr(error.orig, "sqlstate", None), "database_error")
            raise MaintenanceFailure(code) from error
        raise MaintenanceFailure("job_failed") from error
    return result


class MaintenanceFailure(Exception):
    """Only fixed codes from the worker wrapper may enter diagnostics."""


async def _report_artifact_disk_pressure(root: Path) -> None:
    try:
        async with asyncio.timeout(3):
            usage = await asyncio.to_thread(shutil.disk_usage, root)
    except (OSError, TimeoutError):
        logger.warning("artifact_disk status=unavailable")
        return
    low = usage.free < min(_ARTIFACT_SPACE_WARNING_BYTES, usage.total // 10)
    logger.log(logging.WARNING if low else logging.INFO,
        "artifact_disk status=%s free_bytes=%d capacity_bytes=%d",
        "low" if low else "ok", usage.free, usage.total)


class MaintenanceJobs:
    def __init__(self, provider: SessionProvider) -> None:
        self.provider = provider
        self.last_success: dict[str, datetime] = {}
        self.oldest_due: dict[str, float] = {}

    async def run(
        self, name: str, job: Callable[[Any], Awaitable[object]], *,
        due_at: float, batches: int = 1, continue_if: Callable[[object], bool] = bool,
        measure_backlog: Callable[[Any], Awaitable[float | None]] | None = None,
        committed_backlog: Callable[[object], float | None] | None = None,
    ) -> None:
        loop = asyncio.get_running_loop()
        started = loop.time()
        attempt_at = datetime.now(UTC)
        oldest_due = self.oldest_due.setdefault(name, due_at)
        budget = _JOB_BUDGETS.get(name, _DEFAULT_JOB_BUDGET_SECONDS)
        deadline = started + budget
        error = "none"
        completed = 0
        backlog_age = None
        backlog_sampled = False

        async def measure_then_run(session: Any) -> object:
            nonlocal backlog_age, backlog_sampled
            if measure_backlog is not None and not backlog_sampled:
                backlog_age = await measure_backlog(session)
                backlog_sampled = True
            return await job(session)

        task = measure_then_run if measure_backlog is not None else job
        try:
            for _ in range(batches):
                remaining = deadline - loop.time()
                if remaining <= 0:
                    raise MaintenanceFailure("job_timeout")
                result = await _run_transactional_job(self.provider, task, budget=remaining)
                completed += 1
                if committed_backlog is not None and completed == 1:
                    backlog_age = committed_backlog(result)
                if not continue_if(result):
                    break
            self.last_success[name] = datetime.now(UTC)
            self.oldest_due.pop(name, None)
        except MaintenanceFailure as failure:
            error = str(failure)
        last_success = self.last_success.get(name)
        logger.log(
            logging.INFO if error == "none" else logging.WARNING,
            "worker_job job=%s last_attempt=%s last_success=%s duration_seconds=%.3f "
            "backlog_age_seconds=%.3f data_backlog_age_seconds=%s "
            "budget_seconds=%.1f committed_batches=%d safe_error=%s",
            name, attempt_at.isoformat(), last_success.isoformat() if last_success else "none",
            loop.time() - started, max(0.0, started - oldest_due),
            f"{backlog_age:.3f}" if backlog_age is not None else "unknown", budget, completed, error,
        )


async def run_worker(
    settings: Settings,
    session_provider: SessionProvider | None = None,
    *,
    cleanup_interval_seconds: float = 60.0,
    context_schedule_interval_seconds: float = 60.0,
    context_retention_interval_seconds: float = 3600.0,
) -> None:
    """Run bounded maintenance jobs with independent transaction failure domains."""
    if (
        cleanup_interval_seconds <= 0
        or context_schedule_interval_seconds <= 0
        or context_retention_interval_seconds <= 0
    ):
        raise ValueError("worker intervals must be positive")
    owns_provider = session_provider is None
    provider = session_provider or create_session_provider(settings.database_url)
    loop = asyncio.get_running_loop()
    jobs = MaintenanceJobs(provider)
    tick = loop.time()
    next_payload = tick + cleanup_interval_seconds
    next_schedule = tick + context_schedule_interval_seconds
    next_retention = tick + context_retention_interval_seconds
    next_disk_check = tick
    try:
        while True:
            if loop.time() >= next_disk_check:
                await _report_artifact_disk_pressure(settings.artifact_root)
                next_disk_check = loop.time() + 900.0
            await jobs.run("cleanup_expired_retry_envelopes", lambda session: cleanup_expired_retry_envelopes(
                session, request_id=f"server_{uuid4().hex}",
            ), due_at=tick, measure_backlog=enrollment_retry_backlog_age)
            await jobs.run(
                "expire_operations", expire_operations, due_at=tick,
                measure_backlog=operation_expiry_backlog_age,
            )
            await jobs.run(
                "advance_preparations", advance_preparations, due_at=tick,
                measure_backlog=setup_preparation_backlog_age,
            )
            await jobs.run("schedule_fleet", schedule_one, due_at=tick, batches=16)
            # 256 user-days per tick, one commit per batch.
            await jobs.run("rebuild_daily", lambda session: rebuild_daily(
                session, policy=settings.activity_analytics,
            ), due_at=tick, batches=16, continue_if=lambda count: isinstance(count, int) and count >= 16,
                measure_backlog=lambda session: analytics_backlog_age(session, policy=settings.activity_analytics),
            )
            await _run_worktime_maintenance(provider, enabled=settings.worktime_enabled, jobs=jobs, due_at=tick)
            if loop.time() >= next_payload:
                for name, job in (
                    ("cleanup_raw_context_payloads", cleanup_raw_context_payloads),
                    ("cleanup_context_collections", cleanup_context_collections),
                ):
                    await jobs.run(name, job, due_at=next_payload)
                await jobs.run(
                    "cleanup_operation_results", cleanup_operation_results, due_at=next_payload,
                    measure_backlog=operation_result_cleanup_backlog_age,
                )
                await jobs.run(
                    "cleanup_module_step_results", cleanup_module_step_results_with_backlog, due_at=next_payload,
                    committed_backlog=lambda result: (
                        result.oldest_due_age_seconds if isinstance(result, StepCleanupBatch) else None
                    ),
                )
                for name, job in (
                    ("retain_security_events", retain_security_events),
                    ("retain_power_events", retain_power_events),
                    ("retain_analytics", lambda session: retain_analytics(session, policy=settings.activity_analytics)),
                ):
                    await jobs.run(name, job, due_at=next_payload)
                next_payload = loop.time() + cleanup_interval_seconds
            if loop.time() >= next_schedule:
                await jobs.run(
                    "schedule_due_collections", schedule_due_collections_with_backlog, due_at=next_schedule,
                    committed_backlog=lambda result: (
                        result.oldest_due_age_seconds if isinstance(result, ContextScheduleBatch) else None
                    ),
                )
                next_schedule = loop.time() + context_schedule_interval_seconds
            if loop.time() >= next_retention:
                await jobs.run("retain_context_snapshots", retain_context_snapshots, due_at=next_retention)
                next_retention = loop.time() + context_retention_interval_seconds
            next_tick = tick + cleanup_interval_seconds
            now = loop.time()
            # Skip overrun ticks instead of immediately replaying costly work.
            tick = next_tick if next_tick > now else now + cleanup_interval_seconds
            await asyncio.sleep(max(0.0, tick - loop.time()))
    finally:
        if owns_provider:
            await provider.close()


async def _run_worktime_maintenance(
    provider: SessionProvider, *, enabled: bool, jobs: MaintenanceJobs | None = None,
    due_at: float | None = None,
) -> None:
    """Keep explanation generation and personnel retention independently atomic."""
    if not enabled:
        return
    from endpoint_server.worktime.service import generate_due_requests, retain_worktime

    jobs = jobs or MaintenanceJobs(provider)
    if due_at is None:
        due_at = asyncio.get_running_loop().time()
    await jobs.run("generate_due_requests", generate_due_requests, due_at=due_at)
    await jobs.run("retain_worktime", retain_worktime, due_at=due_at)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
    asyncio.run(run_worker(Settings.from_environment()))
