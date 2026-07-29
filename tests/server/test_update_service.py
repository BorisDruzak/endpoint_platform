"""Domain behavior for immutable builds and controlled update rollouts."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from endpoint_contracts import (
    AgentUpdateAcknowledgementV1,
    AgentUpdateReportV1,
    UpdateBuildManifestV1,
)
import endpoint_server.updates.service as update_service_module
from endpoint_server.db.models import (
    AuditEvent,
    Device,
    UpdateBuild,
    UpdateReport,
    UpdateRollout,
    UpdateTarget,
)
from endpoint_server.updates.errors import (
    UpdateConflict,
    UpdateNotFound,
    UpdateStateError,
    UpdateValidationError,
)
from endpoint_server.updates.service import (
    activate_rollout,
    complete_rollout,
    create_rollback_rollout,
    create_rollout,
    pause_rollout,
    recommendation_for_device,
    record_ack,
    record_report,
    register_build,
)


NOW = datetime(2026, 7, 29, 10, 0, tzinfo=UTC)
ADMIN_ID = uuid4()
VALID_MANIFEST = {
    "schema_version": "update_build_manifest_v1",
    "build_identifier": "endpoint-linux-2.0.0",
    "version": "2.0.0",
    "platform": "linux_amd64",
    "channel": "stable",
    "artifact_url": "https://releases.example.test/endpoint-linux-2.0.0.tar.gz",
    "artifact_name": "endpoint-linux-2.0.0.tar.gz",
    "archive_type": "tar.gz",
    "sha256": "1" * 64,
    "size": 4096,
    "release_notes": "Endpoint Platform 2.0.0",
}


@pytest_asyncio.fixture
async def session() -> AsyncIterator[AsyncSession]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    tables = (
        Device.__table__,
        UpdateBuild.__table__,
        UpdateRollout.__table__,
        UpdateTarget.__table__,
        UpdateReport.__table__,
        AuditEvent.__table__,
    )
    async with engine.begin() as connection:
        await connection.run_sync(
            lambda sync_connection: Device.metadata.create_all(
                sync_connection,
                tables=tables,
            )
        )
        # SQLite ignores the PostgreSQL predicate and would otherwise turn the
        # production partial index into an all-history uniqueness constraint.
        await connection.execute(text("DROP INDEX uq_update_targets_active_device"))
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as database_session:
        yield database_session
    await engine.dispose()


def _manifest(**overrides: object) -> UpdateBuildManifestV1:
    return UpdateBuildManifestV1.model_validate({**VALID_MANIFEST, **overrides})


async def _device(session: AsyncSession, suffix: str) -> Device:
    record = Device(
        id=uuid4(),
        device_identifier=f"device-{suffix}",
        display_name=f"Device {suffix}",
        retired_at=None,
    )
    session.add(record)
    await session.flush()
    return record


async def _build(
    session: AsyncSession,
    *,
    version: str = "2.0.0",
    platform: str = "linux_amd64",
    channel: str = "stable",
    suffix: str = "current",
) -> UpdateBuild:
    archive_type = "zip" if platform == "windows_amd64" else "tar.gz"
    artifact_name = f"endpoint-{suffix}.{archive_type}"
    return await register_build(
        session,
        _manifest(
            build_identifier=f"endpoint-{suffix}",
            version=version,
            platform=platform,
            channel=channel,
            artifact_url=f"https://releases.example.test/{artifact_name}",
            artifact_name=artifact_name,
            archive_type=archive_type,
            sha256=("2" if suffix == "old" else "1") * 64,
        ),
        ADMIN_ID,
        f"register-{suffix}",
        now=NOW,
    )


@pytest.mark.asyncio
async def test_conflicting_manifest_cannot_replace_existing_build(
    session: AsyncSession,
) -> None:
    """Changing an immutable digest must fail while an exact replay is idempotent."""
    first = await register_build(
        session,
        _manifest(),
        ADMIN_ID,
        "req-build-a",
        now=NOW,
    )
    replay = await register_build(
        session,
        _manifest(),
        ADMIN_ID,
        "req-build-replay",
        now=NOW,
    )

    assert replay.id == first.id
    with pytest.raises(UpdateConflict):
        await register_build(
            session,
            _manifest(sha256="f" * 64),
            ADMIN_ID,
            "req-build-conflict",
            now=NOW,
        )

    assert await session.scalar(select(func.count()).select_from(UpdateBuild)) == 1
    audits = (
        await session.scalars(
            select(AuditEvent).where(AuditEvent.action == "updates.build_registered")
        )
    ).all()
    assert len(audits) == 1
    assert audits[0].details == {
        "build_identifier": "endpoint-linux-2.0.0",
        "channel": "stable",
        "platform": "linux_amd64",
        "version": "2.0.0",
    }
    assert "artifact_url" not in audits[0].details
    assert "sha256" not in audits[0].details


@pytest.mark.asyncio
async def test_build_and_audit_remain_uncommitted_for_caller_atomicity(
    session: AsyncSession,
) -> None:
    """Rolling back the caller transaction must remove both state and audit."""
    await register_build(
        session,
        _manifest(),
        ADMIN_ID,
        "req-rollback",
        now=NOW,
    )
    await session.rollback()

    assert await session.scalar(select(func.count()).select_from(UpdateBuild)) == 0
    assert await session.scalar(select(func.count()).select_from(AuditEvent)) == 0


@pytest.mark.asyncio
async def test_assignment_and_partial_audit_are_rolled_back_together(
    session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An audit failure mid-assignment must leave no rollout or target state."""
    build = await _build(session)
    device = await _device(session, "audit-failure")
    await session.commit()
    original_append = update_service_module.append_audit_event
    calls = 0

    async def fail_second_audit(*args: object, **kwargs: object) -> object:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("injected update audit failure")
        return await original_append(*args, **kwargs)

    monkeypatch.setattr(
        update_service_module,
        "append_audit_event",
        fail_second_audit,
    )
    with pytest.raises(RuntimeError, match="injected update audit failure"):
        await create_rollout(
            session,
            build.id,
            "canary",
            [device.id],
            "audit failure",
            ADMIN_ID,
            "req-audit-failure",
            now=NOW,
        )
    await session.rollback()

    assert await session.scalar(select(func.count()).select_from(UpdateRollout)) == 0
    assert await session.scalar(select(func.count()).select_from(UpdateTarget)) == 0
    assert (
        await session.scalar(
            select(func.count())
            .select_from(AuditEvent)
            .where(AuditEvent.action.like("updates.rollout_%"))
        )
        == 0
    )
    assert (
        await session.scalar(
            select(func.count())
            .select_from(AuditEvent)
            .where(AuditEvent.action == "updates.target_assigned")
        )
        == 0
    )


@pytest.mark.asyncio
async def test_bulk_requires_completed_canary_for_same_build(
    session: AsyncSession,
) -> None:
    """Removing the completed-canary gate would permit an untested bulk release."""
    build = await _build(session)
    device = await _device(session, "canary")

    with pytest.raises(UpdateStateError):
        await create_rollout(
            session,
            build.id,
            "bulk",
            [device.id],
            "release",
            ADMIN_ID,
            "req-bulk-early",
            now=NOW,
        )

    canary = await create_rollout(
        session,
        build.id,
        "canary",
        [device.id],
        "canary validation",
        ADMIN_ID,
        "req-canary",
        now=NOW,
    )
    target = await session.scalar(
        select(UpdateTarget).where(UpdateTarget.rollout_id == canary.id)
    )
    assert target is not None
    await record_ack(
        session,
        device_id=device.id,
        operation_id=target.operation_id,
        acknowledgement=AgentUpdateAcknowledgementV1(
            schema_version="agent_update_ack_v1",
            status="requested",
        ),
        request_id="req-ack-requested",
        now=NOW,
    )
    await record_ack(
        session,
        device_id=device.id,
        operation_id=target.operation_id,
        acknowledgement=AgentUpdateAcknowledgementV1(
            schema_version="agent_update_ack_v1",
            status="scheduled",
        ),
        request_id="req-ack-scheduled",
        now=NOW,
    )
    await record_report(
        session,
        device_id=device.id,
        operation_id=target.operation_id,
        report=AgentUpdateReportV1(
            schema_version="agent_update_report_v1",
            report_key="canary-result",
            status="applied",
            reported_version="2.0.0",
        ),
        request_id="req-canary-result",
        now=NOW,
    )
    await complete_rollout(
        session,
        canary.id,
        ADMIN_ID,
        "req-canary-complete",
        now=NOW,
    )

    bulk_device = await _device(session, "bulk")
    bulk = await create_rollout(
        session,
        build.id,
        "bulk",
        [bulk_device.id],
        "release",
        ADMIN_ID,
        "req-bulk",
        now=NOW,
    )
    assert bulk.mode == "bulk"
    assert bulk.status == "active"


@pytest.mark.asyncio
async def test_second_active_assignment_is_rejected_before_target_creation(
    session: AsyncSession,
) -> None:
    """A device must never own two active update operations."""
    first_build = await _build(session, suffix="current")
    second_build = await _build(
        session,
        version="2.1.0",
        channel="canary",
        suffix="next",
    )
    device = await _device(session, "exclusive")
    await create_rollout(
        session,
        first_build.id,
        "canary",
        [device.id],
        "first assignment",
        ADMIN_ID,
        "req-first",
        now=NOW,
    )

    with pytest.raises(UpdateConflict):
        await create_rollout(
            session,
            second_build.id,
            "canary",
            [device.id],
            "conflicting assignment",
            ADMIN_ID,
            "req-second",
            now=NOW,
        )

    assert await session.scalar(select(func.count()).select_from(UpdateTarget)) == 1


@pytest.mark.asyncio
async def test_rollback_is_new_older_compatible_rollout_with_trigger_reason(
    session: AsyncSession,
) -> None:
    """Rollback must preserve the trigger and select a different older build."""
    current = await _build(session, version="2.0.0", suffix="current")
    older = await _build(session, version="1.9.1", suffix="old")
    incompatible = await _build(
        session,
        version="1.8.0",
        platform="windows_amd64",
        suffix="windows",
    )
    trigger_device = await _device(session, "trigger")
    rollback_device = await _device(session, "rollback")
    trigger = await create_rollout(
        session,
        current.id,
        "canary",
        [trigger_device.id],
        "detected regression",
        ADMIN_ID,
        "req-trigger",
        now=NOW,
    )

    with pytest.raises(UpdateStateError):
        await create_rollback_rollout(
            session,
            trigger.id,
            current.id,
            [rollback_device.id],
            "same build is not a rollback",
            ADMIN_ID,
            "req-same",
            now=NOW,
        )
    with pytest.raises(UpdateStateError):
        await create_rollback_rollout(
            session,
            trigger.id,
            incompatible.id,
            [rollback_device.id],
            "foreign platform",
            ADMIN_ID,
            "req-incompatible",
            now=NOW,
        )

    draft_trigger = UpdateRollout(
        id=uuid4(),
        rollout_identifier=f"draft-trigger-{uuid4().hex}",
        build_id=current.id,
        mode="canary",
        reason=None,
        status="draft",
        started_at=None,
        paused_at=None,
        completed_at=None,
        cancelled_at=None,
    )
    session.add(draft_trigger)
    await session.flush()
    with pytest.raises(UpdateStateError):
        await create_rollback_rollout(
            session,
            draft_trigger.id,
            older.id,
            [rollback_device.id],
            "draft has no affected devices",
            ADMIN_ID,
            "req-draft-trigger",
            now=NOW,
        )

    rollback = await create_rollback_rollout(
        session,
        trigger.id,
        older.id,
        [rollback_device.id],
        "restore last known good",
        ADMIN_ID,
        "req-rollback",
        now=NOW,
    )
    assert rollback.mode == "rollback"
    assert rollback.build_id == older.id
    assert trigger.rollout_identifier in (rollback.reason or "")
    assert "restore last known good" in (rollback.reason or "")
    assert rollback.status == "active"


@pytest.mark.asyncio
async def test_recommendation_is_device_platform_and_rollout_scoped(
    session: AsyncSession,
) -> None:
    """A foreign device or platform must not learn an active operation."""
    build = await _build(session)
    assigned = await _device(session, "assigned")
    foreign = await _device(session, "foreign")
    rollout = await create_rollout(
        session,
        build.id,
        "canary",
        [assigned.id],
        "safe canary reason",
        ADMIN_ID,
        "req-recommendation",
        now=NOW,
    )
    target = await session.scalar(
        select(UpdateTarget).where(UpdateTarget.rollout_id == rollout.id)
    )
    assert target is not None

    recommendation = await recommendation_for_device(
        session,
        assigned.id,
        "linux_amd64",
        NOW,
    )
    assert recommendation is not None
    assert recommendation.operation_id == UUID(target.operation_id)
    assert recommendation.sha256 == "1" * 64
    assert recommendation.reason == "safe canary reason"
    assert (
        await recommendation_for_device(
            session,
            foreign.id,
            "linux_amd64",
            NOW,
        )
        is None
    )
    assert (
        await recommendation_for_device(
            session,
            assigned.id,
            "windows_amd64",
            NOW,
        )
        is None
    )

    await pause_rollout(
        session,
        rollout.id,
        ADMIN_ID,
        "req-pause",
        now=NOW,
    )
    assert (
        await recommendation_for_device(
            session,
            assigned.id,
            "linux_amd64",
            NOW,
        )
        is None
    )


@pytest.mark.asyncio
async def test_activate_only_resumes_paused_rollout_with_same_targets(
    session: AsyncSession,
) -> None:
    """Activation must not turn an internal targetless draft into live work."""
    build = await _build(session)
    device = await _device(session, "resume")
    rollout = await create_rollout(
        session,
        build.id,
        "canary",
        [device.id],
        "resume boundary",
        ADMIN_ID,
        "req-create-resume",
        now=NOW,
    )
    target_ids = set(
        (
            await session.scalars(
                select(UpdateTarget.id).where(UpdateTarget.rollout_id == rollout.id)
            )
        ).all()
    )
    await pause_rollout(
        session,
        rollout.id,
        ADMIN_ID,
        "req-pause-resume",
        now=NOW,
    )
    resumed = await activate_rollout(
        session,
        rollout.id,
        ADMIN_ID,
        "req-resume",
        now=NOW,
    )
    assert resumed.status == "active"
    assert (
        set(
            (
                await session.scalars(
                    select(UpdateTarget.id).where(UpdateTarget.rollout_id == rollout.id)
                )
            ).all()
        )
        == target_ids
    )

    draft = UpdateRollout(
        id=uuid4(),
        rollout_identifier=f"draft-{uuid4().hex}",
        build_id=build.id,
        mode="canary",
        reason=None,
        status="draft",
        started_at=None,
        paused_at=None,
        completed_at=None,
        cancelled_at=None,
    )
    session.add(draft)
    draft_device = await _device(session, "draft")
    session.add(
        UpdateTarget(
            id=uuid4(),
            rollout_id=draft.id,
            device_id=draft_device.id,
            target_identifier=f"draft-target-{uuid4().hex}",
            operation_id=str(uuid4()),
            status="assigned",
            assigned_at=NOW,
            requested_at=None,
            scheduled_at=None,
            terminal_at=None,
            safe_reason=None,
            updated_at=NOW,
        )
    )
    await session.flush()
    with pytest.raises(UpdateStateError):
        await activate_rollout(
            session,
            draft.id,
            ADMIN_ID,
            "req-draft-activation",
            now=NOW,
        )


@pytest.mark.asyncio
async def test_nonterminal_rollout_cannot_complete_and_unsafe_reason_is_rejected(
    session: AsyncSession,
) -> None:
    """Completion must not imply success, and raw path/token text must not persist."""
    build = await _build(session)
    device = await _device(session, "terminal-gate")
    with pytest.raises(UpdateValidationError):
        await create_rollout(
            session,
            build.id,
            "canary",
            [device.id],
            r"failed at C:\agent\pending_update.json with Bearer raw-token",
            ADMIN_ID,
            "req-unsafe-reason",
            now=NOW,
        )
    with pytest.raises(UpdateValidationError):
        await register_build(
            session,
            _manifest(build_identifier="unsafe-actor-build", version="2.0.1"),
            "Bearer raw-admin-session",
            "req-unsafe-actor",
            now=NOW,
        )
    rollout = await create_rollout(
        session,
        build.id,
        "canary",
        [device.id],
        "terminal gate",
        ADMIN_ID,
        "req-terminal-gate",
        now=NOW,
    )
    with pytest.raises(UpdateStateError):
        await complete_rollout(
            session,
            rollout.id,
            ADMIN_ID,
            "req-premature-complete",
            now=NOW,
        )


@pytest.mark.asyncio
async def test_ack_and_report_are_monotonic_idempotent_and_device_bound(
    session: AsyncSession,
) -> None:
    """Removing transition/idempotency checks would allow replay or downgrade."""
    build = await _build(session)
    assigned = await _device(session, "state")
    foreign = await _device(session, "state-foreign")
    rollout = await create_rollout(
        session,
        build.id,
        "canary",
        [assigned.id],
        "state transitions",
        ADMIN_ID,
        "req-state",
        now=NOW,
    )
    target = await session.scalar(
        select(UpdateTarget).where(UpdateTarget.rollout_id == rollout.id)
    )
    assert target is not None
    requested = AgentUpdateAcknowledgementV1(
        schema_version="agent_update_ack_v1",
        status="requested",
    )
    scheduled = AgentUpdateAcknowledgementV1(
        schema_version="agent_update_ack_v1",
        status="scheduled",
    )

    with pytest.raises(UpdateStateError):
        await record_ack(
            session,
            device_id=assigned.id,
            operation_id=target.operation_id,
            acknowledgement=scheduled,
            request_id="req-skipped-ack",
            now=NOW,
        )
    with pytest.raises(UpdateNotFound):
        await record_ack(
            session,
            device_id=foreign.id,
            operation_id=target.operation_id,
            acknowledgement=requested,
            request_id="req-foreign-ack",
            now=NOW,
        )

    first_requested = await record_ack(
        session,
        device_id=assigned.id,
        operation_id=target.operation_id,
        acknowledgement=requested,
        request_id="req-requested",
        now=NOW,
    )
    replay_requested = await record_ack(
        session,
        device_id=assigned.id,
        operation_id=target.operation_id,
        acknowledgement=requested,
        request_id="req-requested-replay",
        now=NOW,
    )
    assert replay_requested.id == first_requested.id
    assert target.status == "requested"
    await record_ack(
        session,
        device_id=assigned.id,
        operation_id=target.operation_id,
        acknowledgement=scheduled,
        request_id="req-scheduled",
        now=NOW,
    )
    stale_replay = await record_ack(
        session,
        device_id=assigned.id,
        operation_id=target.operation_id,
        acknowledgement=requested,
        request_id="req-requested-stale",
        now=NOW,
    )
    assert stale_replay.status == "scheduled"

    report = AgentUpdateReportV1(
        schema_version="agent_update_report_v1",
        report_key="launcher-result-1",
        status="applied",
        reported_version="2.0.0",
        safe_code="update.applied",
    )
    first_report = await record_report(
        session,
        device_id=assigned.id,
        operation_id=target.operation_id,
        report=report,
        request_id="req-report",
        now=NOW,
    )
    replay_report = await record_report(
        session,
        device_id=assigned.id,
        operation_id=target.operation_id,
        report=report,
        request_id="req-report-replay",
        now=NOW,
    )
    assert replay_report.id == first_report.id
    assert target.status == "applied"

    with pytest.raises(UpdateConflict):
        await record_report(
            session,
            device_id=assigned.id,
            operation_id=target.operation_id,
            report=report.model_copy(update={"status": "failed"}),
            request_id="req-report-conflict",
            now=NOW,
        )
    assert await session.scalar(select(func.count()).select_from(UpdateReport)) == 1
    report_audits = (
        await session.scalars(
            select(AuditEvent).where(AuditEvent.action == "updates.target_reported")
        )
    ).all()
    assert len(report_audits) == 1
    assert report_audits[0].details == {
        "reported_version": "2.0.0",
        "safe_code": "update.applied",
        "status": "applied",
    }
    assert "report_key" not in report_audits[0].details


@pytest.mark.asyncio
async def test_applied_report_requires_scheduled_ack(session: AsyncSession) -> None:
    """Treating download acknowledgement as success would bypass launcher proof."""
    build = await _build(session)
    device = await _device(session, "not-scheduled")
    rollout = await create_rollout(
        session,
        build.id,
        "canary",
        [device.id],
        "launcher proof",
        ADMIN_ID,
        "req-launcher-proof",
        now=NOW,
    )
    target = await session.scalar(
        select(UpdateTarget).where(UpdateTarget.rollout_id == rollout.id)
    )
    assert target is not None

    with pytest.raises(UpdateStateError):
        await record_report(
            session,
            device_id=device.id,
            operation_id=target.operation_id,
            report=AgentUpdateReportV1(
                schema_version="agent_update_report_v1",
                report_key="premature-success",
                status="applied",
                reported_version="2.0.0",
            ),
            request_id="req-premature-success",
            now=NOW,
        )
