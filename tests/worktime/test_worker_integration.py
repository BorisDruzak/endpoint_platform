"""Optional WorkTime jobs retain the worker's transaction failure isolation."""

from contextlib import asynccontextmanager
from types import SimpleNamespace

import pytest

from endpoint_server.worker import _run_worktime_maintenance
from endpoint_server.worktime import service


@pytest.mark.asyncio
async def test_worktime_worker_disabled_and_failed_queue_do_not_affect_retention(monkeypatch):
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

    async def retention(session): events.append("retention")

    monkeypatch.setattr(service, "generate_due_requests", generation)
    monkeypatch.setattr(service, "retain_worktime", retention)
    await _run_worktime_maintenance(provider, enabled=False)
    assert events == []
    await _run_worktime_maintenance(provider, enabled=True)
    assert events == ["open", "queue", "rollback", "open", "retention", "commit"]
