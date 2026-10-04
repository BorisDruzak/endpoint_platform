"""Migrated PostgreSQL owner/agent interleavings using real persisted credentials."""

import asyncio
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from sqlalchemy import func, select, text

from endpoint_contracts import AgentUpdateReportV1
from endpoint_server.db.models import AuditEvent, Device, DeviceCredential, UpdateBuild, UpdateReport, UpdateRollout, UpdateTarget
from endpoint_server.enrollment.credentials import device_token_digest
from endpoint_server.updates import admin_routes, agent_routes, service
from tests.server.test_update_cancellation import (
    cancellation_case, cancellation_body, path, update_service_database_url, update_service_provider,
)
from tests.server.test_update_cancellation_transactions import blocked_by, receipt_id
from tests.server.test_update_postgresql import _postgres_manifest

pytestmark = pytest.mark.usefixtures("preserve_migration_loggers")


async def credential(case):
    token = "synthetic-cancellation-agent-" + uuid4().hex
    async with case["provider"]() as session:
        record = DeviceCredential(id=uuid4(), device_id=case["ids"]["device"], credential_identifier=uuid4().hex,
            token_digest=device_token_digest(token, case["app"].state.settings.device_token_pepper),
            pending_token_digest=None, rotation_overlap_expires_at=None, expires_at=None, revoked_at=None)
        session.add(record)
        await session.commit()
        case["credential_id"] = record.id
    return {"authorization": "Bearer " + token}


async def report_body(case):
    async with case["provider"]() as session:
        build = await session.get(UpdateBuild, case["ids"]["build"])
        return {"schema_version": "agent_update_report_v1", "report_key": "synthetic-genuine-report",
            "status": "failed", "reported_version": build.version, "safe_code": "update.failed"}


async def request_old(case, branch, headers, report):
    base = "/agent/v1/updates/" + case["ids"]["operation"]
    if branch == "ack": return await case["client"].post(base + "/ack", headers=headers,
        json={"schema_version": "agent_update_ack_v1", "status": "requested"})
    if branch == "artifact":
        async with case["provider"]() as session:
            identifier = (await session.get(UpdateBuild, case["ids"]["build"])).build_identifier
        return await case["client"].get("/agent/v1/updates/artifacts/" + identifier, headers=headers)
    return await case["client"].post(base + "/reports", headers=headers, json=report)


async def retire_old(case, branch, report):
    if branch in ("replay", "changed"):
        # Genuine service report, followed by a deliberately retained legacy cancelled fixture.
        # The new cancellation service never manufactures or accepts this terminal report.
        async with case["provider"]() as session:
            await service.record_report(session, device_id=case["ids"]["device"], operation_id=case["ids"]["operation"],
                report=AgentUpdateReportV1.model_validate(report), request_id="synthetic-genuine-report")
            await session.commit()
        async with case["provider"]() as session:
            old = await session.get(UpdateTarget, case["ids"]["target"])
            rollout = await session.get(UpdateRollout, case["ids"]["rollout"])
            old.status = rollout.status = "cancelled"
            rollout.cancelled_at = datetime.now(UTC)
            await session.commit()
    else:
        body = await cancellation_body(case)
        assert (await case["client"].post(path(case, "cancel"), json=body)).status_code == 200
    if branch == "changed": report = {**report, "safe_code": "update.other"}
    return report


async def another_build(case, *, before=False, older=False):
    from unittest.mock import patch
    async with case["provider"]() as session:
        old = await session.get(UpdateBuild, case["ids"]["build"])
        candidate = UUID(int=old.id.int - 1 if before else old.id.int + 1)
        # Deterministic generation before INSERT preserves immutable build/audit identity.
        with patch.object(service, "uuid4", return_value=candidate):
            build = await service.register_build(session, _postgres_manifest(build_identifier=uuid4().hex,
                version=f"{1 if older else 3}.0.{uuid4().int % 1000000000}", channel="canary", digest_character="c"),
                case["ids"]["user"], "synthetic-new-build")
        await session.commit()
        return build.id


async def history(case):
    async with case["provider"]() as session:
        target = await session.get(UpdateTarget, case["ids"]["target"])
        rollout = await session.get(UpdateRollout, case["ids"]["rollout"])
        reports = (await session.scalars(select(UpdateReport).where(UpdateReport.update_target_id == target.id))).all()
        events = (await session.scalars(select(AuditEvent).where(
            AuditEvent.object_identifier.in_((str(target.id), str(rollout.id)))))).all()
        return (target.status, target.operation_id, target.terminal_at, target.updated_at,
            rollout.status, rollout.paused_at, rollout.completed_at, rollout.cancelled_at,
            [(r.id, r.status, r.report_key, r.created_at) for r in reports],
            [(e.id, e.action, e.created_at) for e in events])


async def assert_new_owner(case, new_id):
    async with case["provider"]() as session:
        owners = (await session.scalars(select(UpdateTarget).where(UpdateTarget.device_id == case["ids"]["device"],
            UpdateTarget.status.in_(("assigned", "requested", "scheduled"))))).all()
        assert len(owners) == 1 and owners[0].id == new_id and owners[0].status == "assigned"


@pytest.mark.parametrize("branch,expected", [("ack", 404), ("report", 404), ("artifact", 404)])
async def test_cancelled_operation_rejects_ack_new_report_and_artifact(cancellation_case, branch, expected):
    case = cancellation_case
    headers = await credential(case)
    report = await report_body(case)
    await retire_old(case, branch, report)
    before = await history(case)
    assert (await request_old(case, branch, headers, report)).status_code == expected
    async with case["provider"]() as session:
        record = await session.get(DeviceCredential, case["credential_id"])
        record.revoked_at = datetime.now(UTC)
        await session.commit()
    assert (await request_old(case, branch, headers, report)).status_code == 401
    assert await history(case) == before


@pytest.mark.parametrize("branch,expected", [("ack", 404), ("report", 404), ("replay", 200), ("changed", 409)])
@pytest.mark.parametrize("before", [True, False])
async def test_cancelled_old_agent_revalidation_waits_for_new_owner_device(cancellation_case, branch, expected, before):
    case = cancellation_case
    headers = await credential(case)
    report = await retire_old(case, branch, await report_body(case))
    baseline = await history(case)
    new_build = await another_build(case, before=before)
    async with case["provider"]() as creator:
        pid = await creator.scalar(text("SELECT pg_backend_pid()"))
        new = await service.create_rollout(creator, new_build, "canary", [case["ids"]["device"]], "new owner",
            case["ids"]["user"], "synthetic-new-owner")
        new_target = await creator.scalar(select(UpdateTarget).where(UpdateTarget.rollout_id == new.id))
        task = asyncio.create_task(request_old(case, branch, headers, report))
        # Actual query proves old domain locks were passed and it is now waiting on Device.
        await blocked_by(case, pid, sql_fragment="devices")
        await creator.commit()
        response = await asyncio.wait_for(task, 4)
    assert response.status_code == expected, response.text
    assert await history(case) == baseline
    await assert_new_owner(case, new_target.id)


@pytest.mark.parametrize("branch,expected", [("ack", 404), ("report", 404), ("replay", 200), ("changed", 409)])
@pytest.mark.parametrize("rotation_first", [True, False])
async def test_cancelled_old_agent_revalidation_waits_for_credential_rotation(cancellation_case, branch, expected, rotation_first, monkeypatch):
    case = cancellation_case
    headers = await credential(case)
    report = await retire_old(case, branch, await report_body(case))
    baseline = await history(case)
    new_build = await another_build(case)
    async with case["provider"]() as session:
        new = await service.create_rollout(session, new_build, "canary", [case["ids"]["device"]], None,
            case["ids"]["user"], "synthetic-new-owner")
        new_id = await session.scalar(select(UpdateTarget.id).where(UpdateTarget.rollout_id == new.id))
        await session.commit()
    if rotation_first:
        async with case["provider"]() as rotation:
            pid = await rotation.scalar(text("SELECT pg_backend_pid()"))
            record = await rotation.scalar(select(DeviceCredential).where(DeviceCredential.id == case["credential_id"]).with_for_update())
            task = asyncio.create_task(request_old(case, branch, headers, report))
            await blocked_by(case, pid, sql_fragment="device_credentials")
            record.token_digest = device_token_digest("synthetic-new-agent-" + uuid4().hex, case["app"].state.settings.device_token_pepper)
            await rotation.commit()
            assert (await asyncio.wait_for(task, 4)).status_code == 401
    else:
        validated, release = asyncio.Event(), asyncio.Event()
        original = agent_routes._revalidate_device_principal
        async def after_valid_auth(session, request, principal):
            await original(session, request, principal)
            validated.set()
            await release.wait()
        with monkeypatch.context() as patch:
            patch.setattr(agent_routes, "_revalidate_device_principal", after_valid_auth)
            task = asyncio.create_task(request_old(case, branch, headers, report))
            await asyncio.wait_for(validated.wait(), 3)
            async def rotate():
                async with case["provider"]() as session:
                    record = await session.scalar(select(DeviceCredential).where(DeviceCredential.id == case["credential_id"]).with_for_update())
                    record.revoked_at = datetime.now(UTC)
                    await session.commit()
            rotation_task = asyncio.create_task(rotate())
            # Find the owner holding the credential row from the already validated agent transaction.
            try:
                async with asyncio.timeout(3):
                    while True:
                        async with case["provider"]() as observer:
                            count = await observer.scalar(text("SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() "
                                "AND wait_event_type='Lock' AND query LIKE '%device_credentials%FOR UPDATE%'"))
                        if count: break
                        await asyncio.sleep(0.01)
            finally:
                release.set()
                response, _ = await asyncio.wait_for(asyncio.gather(task, rotation_task), 4)
            assert response.status_code == expected
        assert (await request_old(case, branch, headers, report)).status_code == 401
    assert await history(case) == baseline
    await assert_new_owner(case, new_id)


@pytest.mark.parametrize("report_first", [True, False])
async def test_cancel_vs_report_preserves_winner(cancellation_case, report_first):
    case = cancellation_case
    headers = await credential(case)
    body = await cancellation_body(case)
    report = await report_body(case)
    async with case["provider"]() as holder:
        pid = await holder.scalar(text("SELECT pg_backend_pid()"))
        await holder.scalar(select(UpdateBuild).where(UpdateBuild.id == case["ids"]["build"]).with_for_update())
        first = asyncio.create_task(request_old(case, "report", headers, report) if report_first else
            case["client"].post(path(case, "cancel"), json=body))
        waiters = await blocked_by(case, pid)
        second = asyncio.create_task(case["client"].post(path(case, "cancel"), json=body) if report_first else
            request_old(case, "report", headers, report))
        async with asyncio.timeout(3):
            while len(await blocked_by(case, [pid, waiters[0].pid])) < 2: await asyncio.sleep(0.01)
        await holder.rollback()
        responses = await asyncio.wait_for(asyncio.gather(first, second), 4)
    assert [r.status_code for r in responses] == ([200, 409] if report_first else [200, 404])
    async with case["provider"]() as session:
        target = await session.get(UpdateTarget, case["ids"]["target"])
        rollout = await session.get(UpdateRollout, case["ids"]["rollout"])
        count = await session.scalar(select(func.count()).select_from(UpdateReport).where(UpdateReport.update_target_id == target.id))
        assert (target.status, rollout.status, count) == (("failed", "completed", 1) if report_first else ("cancelled", "cancelled", 0))
        assert (await session.get(AuditEvent, receipt_id(case)) is None) == report_first


async def test_cancel_replay_leaves_new_owner_untouched_and_avoids_its_device_lock(cancellation_case):
    case = cancellation_case
    body = await cancellation_body(case)
    first = await case["client"].post(path(case, "cancel"), json=body)
    assert first.status_code == 200
    baseline = await history(case)
    new_build = await another_build(case)
    async with case["provider"]() as creator:
        new = await service.create_rollout(creator, new_build, "canary", [case["ids"]["device"]], None,
            case["ids"]["user"], "synthetic-new-owner")
        new_id = await creator.scalar(select(UpdateTarget.id).where(UpdateTarget.rollout_id == new.id))
        replay = await asyncio.wait_for(case["client"].post(path(case, "cancel"), json=body), 1)
        assert replay.status_code == 200 and replay.json() == first.json()
        await creator.commit()
    async with case["provider"]() as session:
        (await session.get(Device, case["ids"]["device"])).retired_at = datetime.now(UTC)
        await session.commit()
    assert (await case["client"].post(path(case, "cancel"), json=body)).json() == first.json()
    assert await history(case) == baseline
    await assert_new_owner(case, new_id)


@pytest.mark.parametrize("same_build", [False, True])
@pytest.mark.parametrize("creator_first", [False, True])
async def test_cancel_vs_create_preserves_one_owner_without_deadlock(cancellation_case, same_build, creator_first, monkeypatch):
    case = cancellation_case
    body = await cancellation_body(case)
    build_id = case["ids"]["build"] if same_build else await another_build(case)
    entered, release = asyncio.Event(), asyncio.Event()
    original = service._lock_assignable_devices
    async def held_devices(session, device_ids):
        # Existing helper locks Device before checking active targets. Hold at the real boundary.
        await session.scalars(select(Device).where(Device.id.in_(device_ids)).with_for_update())
        entered.set()
        await release.wait()
        return await original(session, device_ids)
    async def create():
        async with case["provider"]() as session:
            try:
                rollout = await service.create_rollout(session, build_id, "canary", [case["ids"]["device"]], None,
                    case["ids"]["user"], "synthetic-concurrent-create")
                target_id = await session.scalar(select(UpdateTarget.id).where(UpdateTarget.rollout_id == rollout.id))
                await session.commit()
                return target_id
            except (service.UpdateStateError, service.UpdateConflict):
                await session.rollback()
                return None
    if creator_first:
        with monkeypatch.context() as patch:
            patch.setattr(service, "_lock_assignable_devices", held_devices)
            creation = asyncio.create_task(create())
            await asyncio.wait_for(entered.wait(), 3)
            cancellation = asyncio.create_task(case["client"].post(path(case, "cancel"), json=body))
            try:
                async with case["provider"]() as observer:
                    async with asyncio.timeout(3):
                        while not (await observer.scalar(text("SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() "
                                "AND wait_event_type='Lock' AND query LIKE '%FOR UPDATE%'"))):
                            await observer.rollback()
                            await asyncio.sleep(0.01)
            finally:
                release.set()
                new_id, cancelled = await asyncio.wait_for(asyncio.gather(creation, cancellation), 4)
        assert new_id is None and cancelled.status_code == 200
    else:
        original_revalidator = admin_routes.revalidate_update_admin_in_transaction
        async def held_cancellation(request, session, principal, budget):
            await original_revalidator(request, session, principal, budget)
            entered.set()
            await release.wait()
        with monkeypatch.context() as patch:
            patch.setattr(admin_routes, "revalidate_update_admin_in_transaction", held_cancellation)
            cancellation = asyncio.create_task(case["client"].post(path(case, "cancel"), json=body))
            await asyncio.wait_for(entered.wait(), 3)
            owner = next(iter(case["scoped"]._owners))
            creation = asyncio.create_task(create())
            try: await blocked_by(case, owner.driver.get_server_pid())
            finally:
                release.set()
                cancelled, new_id = await asyncio.wait_for(asyncio.gather(cancellation, creation), 4)
        assert cancelled.status_code == 200
        assert new_id is not None
        await assert_new_owner(case, new_id)


@pytest.mark.parametrize("resume_first", [True, False])
async def test_cancel_vs_resume_and_repause_rejects_stale_context(cancellation_case, resume_first):
    case = cancellation_case
    body = await cancellation_body(case)
    if resume_first:
        async with case["provider"]() as resumer:
            await service.activate_rollout(resumer, case["ids"]["rollout"], case["ids"]["user"], "synthetic-resume")
            pid = await resumer.scalar(text("SELECT pg_backend_pid()"))
            task = asyncio.create_task(case["client"].post(path(case, "cancel"), json=body))
            await blocked_by(case, pid)
            await resumer.commit()
            assert (await asyncio.wait_for(task, 4)).status_code == 409
        async with case["provider"]() as session:
            await service.pause_rollout(session, case["ids"]["rollout"], case["ids"]["user"], "synthetic-repause")
            await session.commit()
        assert (await case["client"].post(path(case, "cancel"), json=body)).status_code == 409
        fresh = await cancellation_body(case)
        assert (await case["client"].post(path(case, "cancel"), json=fresh)).status_code == 200
    else:
        assert (await case["client"].post(path(case, "cancel"), json=body)).status_code == 200
        assert (await case["client"].post(path(case, "activate"))).status_code == 409


@pytest.mark.parametrize("before", [False, True])
async def test_cancel_vs_rollback_and_old_report_replay_no_deadlock(cancellation_case, before):
    case = cancellation_case
    headers = await credential(case)
    report = await retire_old(case, "replay", await report_body(case))
    baseline = await history(case)
    rollback_build = await another_build(case, before=before, older=True)
    async with case["provider"]() as session:
        rollback = await service.create_rollback_rollout(session, case["ids"]["rollout"], rollback_build,
            [case["ids"]["device"]], "synthetic rollback", case["ids"]["user"], "synthetic-rollback")
        new_id = await session.scalar(select(UpdateTarget.id).where(UpdateTarget.rollout_id == rollback.id))
        # The rollback owns old build/domain before Device; old report waits there, preserving order.
        pid = await session.scalar(text("SELECT pg_backend_pid()"))
        replay = asyncio.create_task(request_old(case, "replay", headers, report))
        await blocked_by(case, pid)
        await session.commit()
        assert (await asyncio.wait_for(replay, 4)).status_code == 200
    assert await history(case) == baseline
    await assert_new_owner(case, new_id)


@pytest.mark.parametrize("ack_first", [True, False])
async def test_cancel_vs_ack_and_pause_does_not_resurrect(cancellation_case, ack_first, monkeypatch):
    case = cancellation_case
    headers = await credential(case)
    stale = await cancellation_body(case)
    assert (await case["client"].post(path(case, "activate"))).status_code == 200
    report = await report_body(case)
    if ack_first:
        entered, release = asyncio.Event(), asyncio.Event()
        original = agent_routes._revalidate_device_principal
        pid = []
        async def held_auth(session, request, principal):
            await original(session, request, principal)
            pid.append(await session.scalar(text("SELECT pg_backend_pid()")))
            entered.set()
            await release.wait()
        with monkeypatch.context() as patch:
            patch.setattr(agent_routes, "_revalidate_device_principal", held_auth)
            ack = asyncio.create_task(request_old(case, "ack", headers, report))
            await asyncio.wait_for(entered.wait(), 3)
            pause = asyncio.create_task(case["client"].post(path(case, "pause")))
            try: await blocked_by(case, pid[0])
            finally:
                release.set()
                responses = await asyncio.wait_for(asyncio.gather(ack, pause), 4)
        assert [r.status_code for r in responses] == [204, 200]
    else:
        async with case["provider"]() as pauser:
            await service.pause_rollout(pauser, case["ids"]["rollout"], case["ids"]["user"], "synthetic-pause")
            pid = await pauser.scalar(text("SELECT pg_backend_pid()"))
            ack = asyncio.create_task(request_old(case, "ack", headers, report))
            await blocked_by(case, pid)
            await pauser.commit()
            assert (await asyncio.wait_for(ack, 4)).status_code == 404
    assert (await case["client"].post(path(case, "cancel"), json=stale)).status_code == 409
    fresh = await cancellation_body(case)
    assert fresh["expected"]["target_status"] == ("requested" if ack_first else "assigned")
    assert (await case["client"].post(path(case, "cancel"), json=fresh)).status_code == 200
    assert (await request_old(case, "ack", headers, report)).status_code == 404
