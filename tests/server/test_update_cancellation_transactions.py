"""Real PostgreSQL lock/deadline tests; explicitly marked synthetic driver faults."""

import asyncio
import copy
from datetime import UTC, datetime, timedelta
from uuid import NAMESPACE_URL, uuid4, uuid5

import pytest
from sqlalchemy import select, text

from endpoint_server.auth.admin_sessions import issue_admin_session
from endpoint_server.db.models import AdminSession, AdminUser, AuditEvent, Device, UpdateBuild, UpdateRollout, UpdateTarget
from endpoint_server.updates import admin_routes
from endpoint_server.updates import admin_transaction
from endpoint_server.updates.admin_transaction import BudgetSession, NOT_APPLIED, UNKNOWN
from endpoint_server.updates.admin_transaction import logger as transaction_logger
from tests.server.test_update_cancellation import (
    cancellation_case, cancellation_body, path, update_service_database_url, update_service_provider,
)

pytestmark = pytest.mark.usefixtures("preserve_migration_loggers")


@pytest.fixture(autouse=True)
def capture_transaction_outcomes(cancellation_case, monkeypatch, caplog):
    # In-process Alembic's fileConfig disables existing non-Alembic loggers.
    monkeypatch.setattr(transaction_logger, "disabled", False)
    caplog.set_level("WARNING", logger=transaction_logger.name)


def receipt_id(case):
    return uuid5(NAMESPACE_URL, "endpoint-platform:update-rollout-cancellation:v1:" + str(case["ids"]["rollout"]))


async def assert_unapplied(case):
    async with case["provider"]() as session:
        assert (await session.get(UpdateTarget, case["ids"]["target"])).status == "assigned"
        rollout = await session.get(UpdateRollout, case["ids"]["rollout"])
        assert rollout.status == "paused" and rollout.cancelled_at is None and rollout.completed_at is None
        assert await session.get(AuditEvent, receipt_id(case)) is None


async def blocked_by(case, holder_pid, *, sql_fragment=None):
    async with asyncio.timeout(3):
        while True:
            async with case["provider"]() as session:
                rows = (await session.execute(text("SELECT pid, query FROM pg_stat_activity "
                    "WHERE datname=current_database() AND CAST(:holders AS integer[]) && pg_blocking_pids(pid)"),
                    {"holders": holder_pid if isinstance(holder_pid, list) else [holder_pid]})).all()
                if any(sql_fragment is None or sql_fragment in row.query for row in rows):
                    return rows
            await asyncio.sleep(0.01)  # poll actual lock graph; never infer a wait from sleep


@pytest.mark.parametrize("model,key", [(UpdateBuild, "build"), (UpdateRollout, "rollout"),
    (Device, "device"), (UpdateTarget, "target"), (AdminUser, "user"), (AdminSession, "session")])
async def test_cancel_domain_and_admin_lock_timeout_rolls_back_exact_retry(
        cancellation_case, model, key, caplog, record_property):
    case = cancellation_case
    body = await cancellation_body(case)
    async with case["provider"]() as holder:
        holder_pid = await holder.scalar(text("SELECT pg_backend_pid()"))
        await holder.scalar(select(model).where(model.id == case["ids"][key]).with_for_update())
        start = asyncio.get_running_loop().time()
        request = asyncio.create_task(case["client"].post(path(case, "cancel"), json=body))
        await blocked_by(case, holder_pid)
        response = await asyncio.wait_for(request, 16)
        elapsed = asyncio.get_running_loop().time() - start
        assert response.status_code == 503 and response.json() == {"code": NOT_APPLIED, "detail": NOT_APPLIED}
        assert 0.9 <= elapsed < 16
        assert any(getattr(r, "sqlstate", None) == "55P03" for r in caplog.records)
        record_property("lock_table", model.__tablename__)
        record_property("actual_elapsed_seconds", round(elapsed, 3))
        record_property("actual_sqlstate", "55P03")
        await assert_unapplied(case)
        await holder.rollback()
    response = await case["client"].post(path(case, "cancel"), json=body)
    assert response.status_code == 200, response.text


@pytest.mark.parametrize("change,expected", [("revoke", 401), ("disable", 401), ("scope", 403), ("expiry", 401)])
async def test_cancel_revalidates_admin_authority_after_domain_wait(cancellation_case, change, expected):
    case = cancellation_case
    body = await cancellation_body(case)
    async with case["provider"]() as holder:
        pid = await holder.scalar(text("SELECT pg_backend_pid()"))
        await holder.scalar(select(UpdateBuild).where(UpdateBuild.id == case["ids"]["build"]).with_for_update())
        request = asyncio.create_task(case["client"].post(path(case, "cancel"), json=body))
        await blocked_by(case, pid, sql_fragment="update_builds")
        async with case["provider"]() as modifier:
            if change in ("revoke", "expiry"):
                record = await modifier.get(AdminSession, case["ids"]["session"])
                if change == "revoke": record.revoked_at = datetime.now(UTC)
                else: record.expires_at = datetime.now(UTC) - timedelta(seconds=1)
            else:
                user = await modifier.get(AdminUser, case["ids"]["user"])
                if change == "disable": user.disabled_at = datetime.now(UTC)
                else: user.scopes = []
            await modifier.commit()
        await holder.rollback()
        response = await asyncio.wait_for(request, 4)
        assert response.status_code == expected, response.text
    await assert_unapplied(case)


@pytest.mark.parametrize("conflicting", [False, True])
async def test_cancel_concurrent_exact_and_conflicting_requests(cancellation_case, conflicting):
    case = cancellation_case
    body = await cancellation_body(case)
    second = copy.deepcopy(body)
    if conflicting: second["cancellation_id"] = str(uuid4())
    async with case["provider"]() as holder:
        pid = await holder.scalar(text("SELECT pg_backend_pid()"))
        await holder.scalar(select(UpdateBuild).where(UpdateBuild.id == case["ids"]["build"]).with_for_update())
        first_task = asyncio.create_task(case["client"].post(path(case, "cancel"), json=body))
        first_waiters = await blocked_by(case, pid)
        second_task = asyncio.create_task(case["client"].post(path(case, "cancel"), json=second))
        async with asyncio.timeout(3):
            while len(await blocked_by(case, [pid, first_waiters[0].pid])) < 2:
                await asyncio.sleep(0.01)
        await holder.rollback()
        responses = await asyncio.wait_for(asyncio.gather(first_task, second_task), 4)
    assert sorted(r.status_code for r in responses) == ([200, 409] if conflicting else [200, 200])
    if not conflicting: assert responses[0].json() == responses[1].json()
    async with case["provider"]() as session:
        assert await session.get(AuditEvent, receipt_id(case)) is not None


@pytest.mark.parametrize("suffix", ["cancel", "cancellation-context"])
async def test_context_and_cancel_pool_checkout_is_bounded(cancellation_case, suffix, record_property):
    case = cancellation_case
    body = await cancellation_body(case)
    async with case["scoped"].engine.connect() as first, case["scoped"].engine.connect() as second:
        start = asyncio.get_running_loop().time()
        response = await (case["client"].post(path(case, suffix), json=body) if suffix == "cancel"
            else case["client"].get(path(case, suffix)))
        elapsed = asyncio.get_running_loop().time() - start
        assert response.status_code == 503 and response.json()["detail"] == NOT_APPLIED
        assert 0.9 <= elapsed < 5
        record_property("actual_checkout_elapsed_seconds", round(elapsed, 3))
        await assert_unapplied(case)
    retry = await case["client"].post(path(case, "cancel"), json=body)
    assert retry.status_code == 200


async def test_cancel_commit_response_loss_is_unknown_and_exact_retry_reconciles(cancellation_case, monkeypatch):
    """Synthetic lost acknowledgement AFTER an actual PostgreSQL COMMIT."""
    case = cancellation_case
    body = await cancellation_body(case)
    original = BudgetSession.commit
    commits = []
    async def lost_ack(session):
        await original(session)
        commits.append(True)
        raise ConnectionError("synthetic commit acknowledgement loss")
    with monkeypatch.context() as patch:
        patch.setattr(BudgetSession, "commit", lost_ack)
        response = await case["client"].post(path(case, "cancel"), json=body)
    assert response.status_code == 503 and response.json()["detail"] == UNKNOWN and len(commits) == 1
    async with case["provider"]() as session:
        receipt = await session.get(AuditEvent, receipt_id(case))
        original_response = receipt.details["response"]
    retry = await case["client"].post(path(case, "cancel"), json=body)
    assert retry.status_code == 200 and retry.json() == original_response


async def test_cancel_flush_failure_rolls_back_transition_and_receipt(cancellation_case, monkeypatch):
    """Synthetic local flush fault, real rollback and independent DB assertion."""
    case = cancellation_case
    body = await cancellation_body(case)
    async def failed_flush(session, *args, **kwargs):
        raise RuntimeError("synthetic flush failure")
    with monkeypatch.context() as patch:
        patch.setattr(BudgetSession, "flush", failed_flush)
        response = await case["client"].post(path(case, "cancel"), json=body)
    assert response.status_code == 503 and response.json()["detail"] == NOT_APPLIED
    await assert_unapplied(case)
    assert (await case["client"].post(path(case, "cancel"), json=body)).status_code == 200


async def test_cancel_real_statement_timeout_is_rolled_back(cancellation_case, monkeypatch, caplog, record_property):
    case = cancellation_case
    body = await cancellation_body(case)
    original = admin_routes.revalidate_update_admin_in_transaction
    async def slow_query(request, session, principal, budget):
        await original(request, session, principal, budget)
        # Make the server deadline decisively earlier than the 3s driver deadline.
        assert (await session.scalar(text("SHOW statement_timeout"))) == "3s"
        await session.execute(text("SET LOCAL statement_timeout='500ms'"))
        await session.execute(text("SELECT pg_sleep(1)"))
    with monkeypatch.context() as patch:
        patch.setattr(admin_routes, "revalidate_update_admin_in_transaction", slow_query)
        start = asyncio.get_running_loop().time()
        response = await case["client"].post(path(case, "cancel"), json=body)
        elapsed = asyncio.get_running_loop().time() - start
    assert response.status_code == 503 and response.json()["detail"] == NOT_APPLIED
    assert 0.45 <= elapsed < 2
    assert any(getattr(r, "sqlstate", None) == "57014" for r in caplog.records)
    record_property("actual_statement_elapsed_seconds", round(elapsed, 3))
    record_property("actual_sqlstate", "57014")
    await assert_unapplied(case)


async def test_cancel_unconfirmed_cleanup_retains_slot_and_is_unknown(cancellation_case, monkeypatch):
    """Synthetic close stall after acknowledged precommit rollback; actual PG remains unchanged."""
    case = cancellation_case
    body = await cancellation_body(case)
    original_close = BudgetSession.close
    stalled, release = asyncio.Event(), asyncio.Event()
    async def failed_flush(session, *args, **kwargs):
        raise RuntimeError("synthetic flush fault")
    async def stalled_close(session):
        stalled.set()
        while not release.is_set():
            try: await release.wait()
            except asyncio.CancelledError: pass  # explicitly model a cancellation-resistant library await
        await original_close(session)
    with monkeypatch.context() as patch:
        patch.setattr(BudgetSession, "flush", failed_flush)
        patch.setattr(BudgetSession, "close", stalled_close)
        task = asyncio.create_task(case["client"].post(path(case, "cancel"), json=body))
        await asyncio.wait_for(stalled.wait(), 4)
        try:
            response = await asyncio.wait_for(task, 5)
            assert response.status_code == 503 and response.json()["detail"] == UNKNOWN
            assert len(case["scoped"]._owners) == 1
            await assert_unapplied(case)
        finally:
            release.set()
            owners = tuple(case["scoped"]._owners)
            await asyncio.wait_for(asyncio.gather(*(o.task for o in owners)), 4)
    assert (await case["client"].post(path(case, "cancel"), json=body)).status_code == 200


async def test_cancel_whole_deadline_stops_cumulative_waits_before_commit(cancellation_case, monkeypatch, record_property):
    """Actual individually bounded PG statements cumulatively exceed the whole budget."""
    case = cancellation_case
    body = await cancellation_body(case)
    original = admin_routes.revalidate_update_admin_in_transaction
    commits = []
    async def cumulative_queries(request, session, principal, budget):
        await original(request, session, principal, budget)
        for _ in range(20): await session.execute(text("SELECT pg_sleep(0.8)"))
    original_commit = BudgetSession.commit
    async def counted_commit(session):
        commits.append(True)
        await original_commit(session)
    with monkeypatch.context() as patch:
        patch.setattr(admin_routes, "revalidate_update_admin_in_transaction", cumulative_queries)
        patch.setattr(BudgetSession, "commit", counted_commit)
        start = asyncio.get_running_loop().time()
        response = await asyncio.wait_for(case["client"].post(path(case, "cancel"), json=body), 16)
        elapsed = asyncio.get_running_loop().time() - start
    assert response.status_code == 503 and response.json()["detail"] == UNKNOWN
    assert 11.8 <= elapsed <= 16 and not commits
    record_property("actual_whole_elapsed_seconds", round(elapsed, 3))
    await assert_unapplied(case)
    assert (await case["client"].post(path(case, "cancel"), json=body)).status_code == 200


async def test_cancel_cumulative_real_lock_waits_reserve_commit_budget(cancellation_case, monkeypatch, record_property):
    """Three measured PG lock waits below 1s plus actual prior SQL consume the commit reserve."""
    case = cancellation_case
    body = await cancellation_body(case)
    loader = admin_transaction.load_update_admin_in_transaction
    async def initial_queries(request, session):
        principal = await loader(request, session)
        for _ in range(5): await session.execute(text("SELECT pg_sleep(1.5)"))
        return principal
    with monkeypatch.context() as patch:
        patch.setattr(admin_transaction, "load_update_admin_in_transaction", initial_queries)
        async with case["provider"]() as build_holder, case["provider"]() as device_holder, case["provider"]() as user_holder:
            holders = [(build_holder, UpdateBuild, "build"), (device_holder, Device, "device"), (user_holder, AdminUser, "user")]
            pids = []
            for holder, model, key in holders:
                pids.append(await holder.scalar(text("SELECT pg_backend_pid()")))
                await holder.scalar(select(model).where(model.id == case["ids"][key]).with_for_update())
            start = asyncio.get_running_loop().time()
            task = asyncio.create_task(case["client"].post(path(case, "cancel"), json=body))
            async with asyncio.timeout(16):
                for (holder, _, _), pid in zip(holders, pids):
                    # First domain wait occurs after 7.5s of genuine queries.
                    async with case["provider"]() as observer:
                        while not (await observer.scalar(text("SELECT count(*) FROM pg_stat_activity WHERE "
                                "datname=current_database() AND :pid=ANY(pg_blocking_pids(pid))"), {"pid": pid})):
                            await asyncio.sleep(0.01)
                    await asyncio.sleep(0.75)  # deliberate held-lock schedule, after graph confirmation
                    await holder.rollback()
                response = await task
            elapsed = asyncio.get_running_loop().time() - start
    assert response.status_code == 503 and response.json()["detail"] == UNKNOWN
    assert 9 <= elapsed < 16
    record_property("actual_cumulative_lock_elapsed_seconds", round(elapsed, 3))
    await assert_unapplied(case)


async def test_cancel_late_resume_cannot_commit_and_slots_bound_pending_owners(cancellation_case, monkeypatch):
    """Synthetic cancellation-resistant callback, actual owned PG lease and retirement token."""
    case = cancellation_case
    body = await cancellation_body(case)
    original = admin_routes.revalidate_update_admin_in_transaction
    entered, release = asyncio.Event(), asyncio.Event()
    async def stalled(request, session, principal, budget):
        await original(request, session, principal, budget)
        entered.set()
        while not release.is_set():
            try: await release.wait()
            except asyncio.CancelledError: pass
    with monkeypatch.context() as patch:
        patch.setattr(admin_routes, "revalidate_update_admin_in_transaction", stalled)
        task = asyncio.create_task(case["client"].post(path(case, "cancel"), json=body))
        await asyncio.wait_for(entered.wait(), 4)
        owners = tuple(case["scoped"]._owners)
        owners[0].budget.deadline = asyncio.get_running_loop().time()  # synthetic earlier acceptance boundary
        owners[0].budget.retire()
        owners[0].task.cancel()
        # A second owned operation is admitted; a third must fail without queuing.
        second_entered = asyncio.Event()
        async def second_operation(session, budget, principal):
            second_entered.set()
            while not release.is_set():
                try: await release.wait()
                except asyncio.CancelledError: pass
            budget.check()
        from starlette.requests import Request
        # Use the real persisted cookie/CSRF in a direct scoped owner; no auth override.
        headers = [(b"cookie", ("endpoint_admin_session=" + case["issued"].token).encode())]
        direct = Request({"type": "http", "method": "GET", "headers": headers, "app": case["app"]},
            receive=lambda: asyncio.Future())
        second = asyncio.create_task(case["scoped"].run(direct, readonly=True, operation=second_operation))
        try:
            await asyncio.wait_for(second_entered.wait(), 4)
            assert len(case["scoped"]._owners) == 2
            response = await case["client"].get(path(case, "cancellation-context"))
            assert response.status_code == 503 and response.json()["detail"] == NOT_APPLIED
        finally:
            release.set()
            await asyncio.wait_for(asyncio.gather(task, second, return_exceptions=True), 16)
    await assert_unapplied(case)
    assert (await case["client"].post(path(case, "cancel"), json=body)).status_code == 200


async def test_cancel_late_checkout_is_discarded_without_auth_or_domain_sql(cancellation_case, monkeypatch, record_property):
    """Synthetic delayed checkout return, real physical PG connection and late disposal."""
    from sqlalchemy import event
    case = cancellation_case
    body = await cancellation_body(case)
    engine_type = type(case["scoped"].engine)
    original_connect = engine_type.connect
    acquired, release = asyncio.Event(), asyncio.Event()
    statements = []
    @event.listens_for(case["scoped"].engine.sync_engine, "before_cursor_execute")
    def statement(*args): statements.append(args[2].split()[0])
    async def late_connect():
        connection = await original_connect(case["scoped"].engine)
        acquired.set()
        while not release.is_set():
            try: await release.wait()
            except asyncio.CancelledError: pass
        return connection
    with monkeypatch.context() as patch:
        patch.setattr(engine_type, "connect", lambda engine: late_connect()
            if engine is case["scoped"].engine else original_connect(engine))
        start = asyncio.get_running_loop().time()
        task = asyncio.create_task(case["client"].post(path(case, "cancel"), json=body))
        await asyncio.wait_for(acquired.wait(), 3)
        try:
            response = await asyncio.wait_for(task, 7)
            elapsed = asyncio.get_running_loop().time() - start
            assert response.status_code == 503 and response.json()["detail"] == UNKNOWN
            assert 4.8 <= elapsed <= 7 and len(case["scoped"]._owners) == 1
            record_property("synthetic_late_checkout_elapsed_seconds", round(elapsed, 3))
        finally:
            owners = tuple(case["scoped"]._owners)
            release.set()
            await asyncio.wait_for(asyncio.gather(*(o.task for o in owners)), 4)
    assert statements == []
    await assert_unapplied(case)
    assert (await case["client"].post(path(case, "cancel"), json=body)).status_code == 200


async def test_cancel_stalled_rollback_is_unknown_and_owned_driver_terminated(cancellation_case, monkeypatch, record_property):
    """Synthetic rollback stall; actual driver terminated, DB independently reconciled."""
    case = cancellation_case
    body = await cancellation_body(case)
    original = BudgetSession.rollback
    entered, release = asyncio.Event(), asyncio.Event()
    async def failed_flush(session, *args, **kwargs):
        raise RuntimeError("synthetic flush fault")
    async def stalled_rollback(session):
        entered.set()
        while not release.is_set():
            try: await release.wait()
            except asyncio.CancelledError: pass
        await original(session)
    with monkeypatch.context() as patch:
        patch.setattr(BudgetSession, "flush", failed_flush)
        patch.setattr(BudgetSession, "rollback", stalled_rollback)
        start = asyncio.get_running_loop().time()
        task = asyncio.create_task(case["client"].post(path(case, "cancel"), json=body))
        await asyncio.wait_for(entered.wait(), 4)
        owner = next(iter(case["scoped"]._owners))
        try:
            response = await asyncio.wait_for(task, 16)
            assert response.status_code == 503 and response.json()["detail"] == UNKNOWN
            elapsed = asyncio.get_running_loop().time() - start
            record_property("synthetic_stalled_rollback_elapsed_seconds", round(elapsed, 3))
            assert elapsed < 5
            assert owner.driver.is_closed() and owner in case["scoped"]._owners
            await assert_unapplied(case)
        finally:
            release.set()
            await asyncio.wait_for(owner.task, 4)
    assert (await case["client"].post(path(case, "cancel"), json=body)).status_code == 200


async def test_confirmed_commit_with_stalled_cleanup_stays_successful(cancellation_case, monkeypatch):
    case = cancellation_case
    body = await cancellation_body(case)
    original = BudgetSession.close
    release = asyncio.Event()
    async def stalled_close(session):
        while not release.is_set():
            try: await release.wait()
            except asyncio.CancelledError: pass
        await original(session)
    with monkeypatch.context() as patch:
        patch.setattr(BudgetSession, "close", stalled_close)
        try:
            response = await asyncio.wait_for(case["client"].post(path(case, "cancel"), json=body), 5)
            assert response.status_code == 200
            assert len(case["scoped"]._owners) == 1
        finally:
            owners = tuple(case["scoped"]._owners)
            release.set()
            await asyncio.wait_for(asyncio.gather(*(o.task for o in owners)), 4)
    assert (await case["client"].post(path(case, "cancel"), json=body)).json() == response.json()


async def test_late_old_finalizer_cannot_terminate_reused_connection(cancellation_case):
    case = cancellation_case
    body = await cancellation_body(case)
    captured = []
    original = case["scoped"]._release_when_settled
    def retain(owner):
        if owner.task.done(): captured.append(owner)
        original(owner)
    case["scoped"]._release_when_settled = retain
    assert (await case["client"].post(path(case, "cancel"), json=body)).status_code == 200
    old = captured[-1]
    assert not old.leased
    async with case["scoped"].engine.connect() as reused:
        raw = await reused.get_raw_connection()
        case["scoped"]._force_disconnect(old)
        assert not raw.driver_connection.is_closed()
        assert await reused.scalar(text("SELECT 1")) == 1


async def test_scoped_shutdown_is_bounded_with_pending_cleanup(cancellation_case, monkeypatch):
    case = cancellation_case
    body = await cancellation_body(case)
    release = asyncio.Event()
    original = BudgetSession.close
    async def stalled_close(session):
        while not release.is_set():
            try: await release.wait()
            except asyncio.CancelledError: pass
        await original(session)
    with monkeypatch.context() as patch:
        patch.setattr(BudgetSession, "close", stalled_close)
        assert (await case["client"].post(path(case, "cancel"), json=body)).status_code == 200
        owners = tuple(case["scoped"]._owners)
        try:
            start = asyncio.get_running_loop().time()
            await asyncio.wait_for(case["scoped"].close(), 3)
            assert asyncio.get_running_loop().time() - start < 3
            assert case["scoped"]._closed and owners[0].driver.is_closed()
        finally:
            release.set()
            await asyncio.wait_for(asyncio.gather(*(o.task for o in owners)), 4)


@pytest.mark.parametrize("change,expected", [("revoke", 401), ("disable", 401), ("scope", 403)])
async def test_cancel_admin_authority_locks_preserve_winning_commit(cancellation_case, change, expected, monkeypatch):
    case = cancellation_case
    body = await cancellation_body(case)
    entered, release = asyncio.Event(), asyncio.Event()
    original = admin_routes.revalidate_update_admin_in_transaction
    async def hold_authority(request, session, principal, budget):
        await original(request, session, principal, budget)
        entered.set()
        await release.wait()
    async def revoke():
        async with case["provider"]() as session:
            if change == "revoke":
                record = await session.scalar(select(AdminSession).where(AdminSession.id == case["ids"]["session"]).with_for_update())
                record.revoked_at = datetime.now(UTC)
            else:
                user = await session.scalar(select(AdminUser).where(AdminUser.id == case["ids"]["user"]).with_for_update())
                if change == "disable": user.disabled_at = datetime.now(UTC)
                else: user.scopes = []
            await session.commit()
    with monkeypatch.context() as patch:
        patch.setattr(admin_routes, "revalidate_update_admin_in_transaction", hold_authority)
        cancellation = asyncio.create_task(case["client"].post(path(case, "cancel"), json=body))
        await asyncio.wait_for(entered.wait(), 4)
        owner = next(iter(case["scoped"]._owners))
        revocation = asyncio.create_task(revoke())
        try: await blocked_by(case, owner.driver.get_server_pid())
        finally:
            release.set()
            response, _ = await asyncio.wait_for(asyncio.gather(cancellation, revocation), 4)
    assert response.status_code == 200
    async with case["provider"]() as session:
        assert (await session.get(UpdateTarget, case["ids"]["target"])).status == "cancelled"
        assert await session.get(AuditEvent, receipt_id(case)) is not None
    assert (await case["client"].post(path(case, "cancel"), json=body)).status_code == expected


async def test_cancel_explicit_sql_boundary_cap_prevents_late_work(cancellation_case, monkeypatch):
    case = cancellation_case
    body = await cancellation_body(case)
    original = admin_routes.revalidate_update_admin_in_transaction
    async def too_many(request, session, principal, budget):
        await original(request, session, principal, budget)
        for _ in range(70): await session.execute(text("SELECT 1"))
    with monkeypatch.context() as patch:
        patch.setattr(admin_routes, "revalidate_update_admin_in_transaction", too_many)
        response = await case["client"].post(path(case, "cancel"), json=body)
    assert response.status_code == 503 and response.json()["detail"] == UNKNOWN
    await assert_unapplied(case)


async def test_context_read_only_and_scoped_limits_do_not_leak_to_global_pool(cancellation_case, monkeypatch):
    case = cancellation_case
    original = admin_routes.rollout_cancellation_context
    async def inspect(session, rollout_id, **kwargs):
        assert await session.scalar(text("SHOW transaction_read_only")) == "on"
        assert await session.scalar(text("SHOW lock_timeout")) == "1s"
        assert await session.scalar(text("SHOW statement_timeout")) == "3s"
        assert await session.scalar(text("SHOW idle_in_transaction_session_timeout")) == "3s"
        return await original(session, rollout_id, **kwargs)
    monkeypatch.setattr(admin_routes, "rollout_cancellation_context", inspect)
    assert (await case["client"].get(path(case, "cancellation-context"))).status_code == 200
    async with case["provider"]() as session:
        assert await session.scalar(text("SHOW lock_timeout")) == "0"
        assert await session.scalar(text("SHOW statement_timeout")) == "0"
        assert await session.scalar(text("SHOW idle_in_transaction_session_timeout")) == "0"


async def test_settled_task_retains_slot_when_connection_disposal_fails(cancellation_case, monkeypatch):
    """Synthetic close/invalidate errors after real COMMIT cannot surrender an owned lease."""
    from sqlalchemy.ext.asyncio import AsyncConnection
    case = cancellation_case
    body = await cancellation_body(case)
    original_close, original_invalidate = AsyncConnection.close, AsyncConnection.invalidate
    captured = []
    release = case["scoped"]._release_when_settled
    def capture(owner):
        if owner not in captured: captured.append(owner)
        release(owner)
    monkeypatch.setattr(case["scoped"], "_release_when_settled", capture)
    async def broken(*args, **kwargs): raise RuntimeError("synthetic local disposal fault")
    owner = None
    try:
        with monkeypatch.context() as patch:
            patch.setattr(AsyncConnection, "close", broken)
            patch.setattr(AsyncConnection, "invalidate", broken)
            response = await case["client"].post(path(case, "cancel"), json=body)
            owner = captured[-1]
            assert response.status_code == 200 and owner.task.done() and owner.leased
            assert owner in case["scoped"]._owners
    finally:
        if owner is not None:
            await original_invalidate(owner.connection)
            await original_close(owner.connection)
            case["scoped"]._release_when_settled(owner)
    assert owner not in case["scoped"]._owners
    assert (await case["client"].post(path(case, "cancel"), json=body)).json() == response.json()
