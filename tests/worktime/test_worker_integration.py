"""Optional WorkTime jobs retain the worker's transaction failure isolation."""

from contextlib import asynccontextmanager

import pytest

from endpoint_server.worker import _run_worktime_maintenance
from endpoint_server.worktime import service


@pytest.mark.asyncio
async def test_worktime_worker_disabled_and_failed_queue_do_not_affect_retention(monkeypatch, caplog):
    events = []

    class Session:
        async def commit(self): events.append("commit")
        async def rollback(self): events.append("rollback")

    @asynccontextmanager
    async def provider():
        events.append("open")
        yield Session()

    async def generation(session):
        events.append("queue")
        raise RuntimeError("synthetic queue failure")

    async def retention(session):
        events.append("retention")
        return service.WorktimeMaintenanceBatch(1, 60)

    monkeypatch.setattr(service, "generate_due_requests_with_backlog", generation)
    monkeypatch.setattr(service, "retain_worktime_with_backlog", retention)
    await _run_worktime_maintenance(provider, enabled=False)
    assert events == []
    with caplog.at_level("INFO", logger="endpoint_server.worker"):
        await _run_worktime_maintenance(provider, enabled=True)
    assert events == ["open", "queue", "rollback", "open", "retention", "commit"]
    completed = [
        record.message for record in caplog.records
        if record.name == "endpoint_server.worker" and record.message.startswith("worker_job job=")
    ]
    generation_log, retention_log = completed
    assert generation_log.startswith("worker_job job=generate_due_requests ")
    assert "data_backlog_age_seconds=unknown" in generation_log
    assert retention_log.startswith("worker_job job=retain_worktime ")
    assert "data_backlog_age_seconds=60.000" in retention_log
