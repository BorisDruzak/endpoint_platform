"""Persistence and populated PostgreSQL checks for update rollout control state."""

from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator, Iterator
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import asyncpg
import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from sqlalchemy import UniqueConstraint, func, select
from sqlalchemy.dialects import postgresql
from sqlalchemy.engine import make_url
from sqlalchemy.schema import CreateIndex

from endpoint_contracts import (
    AgentUpdateAcknowledgementV1,
    AgentUpdateReportV1,
    UpdateBuildManifestV1,
)
from endpoint_server.db.models import (
    AuditEvent,
    Device,
    UpdateBuild,
    UpdateReport,
    UpdateRollout,
    UpdateTarget,
)
from endpoint_server.db.session import AsyncSessionProvider
from endpoint_server.updates import (
    UpdateConflict,
    create_rollout,
    record_ack,
    record_report,
    register_build,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


async def _execute(database_url: str, statement: str) -> None:
    connection = await asyncpg.connect(database_url)
    try:
        await connection.execute(statement)
    finally:
        await connection.close()


async def _fetch(database_url: str, statement: str) -> list[asyncpg.Record]:
    connection = await asyncpg.connect(database_url)
    try:
        return await connection.fetch(statement)
    finally:
        await connection.close()


def _alembic_config(database_url: str) -> Config:
    config = Config(REPOSITORY_ROOT / "alembic.ini")
    config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    return config


@pytest.fixture(scope="module")
def update_migration_database_urls() -> Iterator[tuple[str, str]]:
    admin_url = os.environ.get("ENDPOINT_TEST_POSTGRES_URL")
    if not admin_url:
        pytest.skip(
            "set ENDPOINT_TEST_POSTGRES_URL to a disposable local PostgreSQL server"
        )
    parsed = make_url(admin_url)
    if parsed.host not in {"127.0.0.1", "localhost", "::1"}:
        pytest.fail("update migration tests may only use loopback PostgreSQL")
    plain_admin_url = parsed.set(drivername="postgresql").render_as_string(
        hide_password=False
    )
    database_name = f"endpoint_updates_{uuid4().hex}"
    asyncio.run(_execute(plain_admin_url, f'CREATE DATABASE "{database_name}"'))
    plain_database_url = parsed.set(
        drivername="postgresql", database=database_name
    ).render_as_string(hide_password=False)
    async_database_url = parsed.set(
        drivername="postgresql+asyncpg", database=database_name
    ).render_as_string(hide_password=False)
    try:
        yield async_database_url, plain_database_url
    finally:
        asyncio.run(
            _execute(
                plain_admin_url,
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                f"WHERE datname = '{database_name}' AND pid <> pg_backend_pid()",
            )
        )
        asyncio.run(_execute(plain_admin_url, f'DROP DATABASE "{database_name}"'))


def test_update_models_persist_safe_control_plane_state() -> None:
    """Removing a required manifest/operation field would make delivery unverifiable."""
    build_columns = UpdateBuild.__table__.c
    rollout_columns = UpdateRollout.__table__.c
    target_columns = UpdateTarget.__table__.c
    report_columns = UpdateReport.__table__.c

    assert {
        "channel",
        "artifact_url",
        "artifact_name",
        "archive_type",
        "size",
        "release_notes",
    } <= set(build_columns.keys())
    assert not build_columns.artifact_url.nullable
    assert not build_columns.artifact_name.nullable
    assert not build_columns.archive_type.nullable
    assert not build_columns.channel.nullable
    assert not build_columns.size.nullable
    assert {"mode", "reason", "paused_at", "cancelled_at"} <= set(
        rollout_columns.keys()
    )
    assert not rollout_columns.mode.nullable
    assert {
        "operation_id",
        "assigned_at",
        "requested_at",
        "scheduled_at",
        "terminal_at",
        "safe_reason",
    } <= set(target_columns.keys())
    assert not target_columns.operation_id.nullable
    assert not target_columns.assigned_at.nullable
    assert {"report_key", "safe_code"} <= set(report_columns.keys())
    assert not report_columns.report_key.nullable
    assert "safe_message" not in report_columns


def test_update_models_enforce_manifest_and_report_identities() -> None:
    """Dropping either identity constraint would permit conflicting persisted state."""
    build_uniques = {
        (constraint.name, tuple(column.name for column in constraint.columns))
        for constraint in UpdateBuild.__table__.constraints
        if isinstance(constraint, UniqueConstraint)
    }
    report_uniques = {
        (constraint.name, tuple(column.name for column in constraint.columns))
        for constraint in UpdateReport.__table__.constraints
        if isinstance(constraint, UniqueConstraint)
    }

    assert (
        "uq_update_builds_platform_channel_version",
        ("platform", "channel", "version"),
    ) in build_uniques
    assert (
        "uq_update_reports_target_report_key",
        ("update_target_id", "report_key"),
    ) in report_uniques


def test_update_models_have_postgresql_partial_unique_active_target_index() -> None:
    """A non-unique or unfiltered index would not prevent concurrent assignments."""
    index = next(
        item
        for item in UpdateTarget.__table__.indexes
        if item.name == "uq_update_targets_active_device"
    )
    rendered = " ".join(
        str(CreateIndex(index).compile(dialect=postgresql.dialect())).split()
    )

    assert index.unique
    assert rendered == (
        "CREATE UNIQUE INDEX uq_update_targets_active_device ON update_targets "
        "(device_id) WHERE status IN ('assigned', 'requested', 'scheduled')"
    )


def test_update_downgrade_preserves_history_and_neutralizes_active_state(
    update_migration_database_urls: tuple[str, str],
) -> None:
    """A populated downgrade/re-upgrade must preserve rows without reviving work."""
    async_url, plain_url = update_migration_database_urls
    config = _alembic_config(async_url)
    device_id = uuid4()
    build_id = uuid4()
    rollout_id = uuid4()
    target_id = uuid4()
    report_id = uuid4()

    command.upgrade(config, "0005_enrollment_campaigns")
    asyncio.run(
        _execute(
            plain_url,
            "INSERT INTO devices (id, device_identifier) "
            f"VALUES ('{device_id}', 'update-device'); "
            "INSERT INTO update_builds "
            "(id, build_identifier, version, platform, artifact_identifier, "
            "sha256_digest) "
            f"VALUES ('{build_id}', 'legacy-update-build', '1.0.0', "
            "'linux_amd64', 'legacy/archive.tar.gz', "
            f"'{('1' * 64)}'); "
            "INSERT INTO update_rollouts "
            "(id, rollout_identifier, build_id, status, started_at) "
            f"VALUES ('{rollout_id}', 'legacy-rollout', '{build_id}', "
            "'active', CURRENT_TIMESTAMP); "
            "INSERT INTO update_targets "
            "(id, rollout_id, device_id, target_identifier, status) "
            f"VALUES ('{target_id}', '{rollout_id}', '{device_id}', "
            "'legacy-target', 'scheduled'); "
            "INSERT INTO update_reports "
            "(id, update_target_id, device_id, report_identifier, "
            "reported_version, status) "
            f"VALUES ('{report_id}', '{target_id}', '{device_id}', "
            "'legacy-report', '0.9.0', 'legacy_success')",
        )
    )

    command.upgrade(config, "head")
    upgraded = asyncio.run(
        _fetch(
            plain_url,
            "SELECT b.channel, b.artifact_url, b.artifact_name, b.archive_type, "
            "b.size, b.artifact_identifier, r.status AS rollout_status, "
            "t.operation_id, t.status AS target_status, t.terminal_at IS NOT NULL "
            "AS target_terminal, p.report_key, p.status AS report_status "
            "FROM update_builds b "
            "JOIN update_rollouts r ON r.build_id = b.id "
            "JOIN update_targets t ON t.rollout_id = r.id "
            "JOIN update_reports p ON p.update_target_id = t.id "
            f"WHERE b.id = '{build_id}'",
        )
    )
    assert len(upgraded) == 1
    assert upgraded[0]["channel"] == f"legacy-{build_id.hex}"
    assert upgraded[0]["artifact_url"] == (f"https://invalid.invalid/legacy/{build_id}")
    assert upgraded[0]["artifact_name"] == f"legacy-{build_id.hex}.zip"
    assert upgraded[0]["archive_type"] == "zip"
    assert upgraded[0]["size"] == 1
    assert upgraded[0]["artifact_identifier"] == f"legacy-{build_id.hex}.zip"
    assert upgraded[0]["rollout_status"] == "cancelled"
    assert upgraded[0]["operation_id"] == str(target_id)
    assert upgraded[0]["target_status"] == "cancelled"
    assert upgraded[0]["target_terminal"]
    assert upgraded[0]["report_key"] == "legacy-report"
    assert upgraded[0]["report_status"] == "legacy_success"

    with pytest.raises(asyncpg.UniqueViolationError):
        asyncio.run(
            _execute(
                plain_url,
                "INSERT INTO update_builds "
                "(id, build_identifier, version, platform, channel, "
                "artifact_identifier, artifact_url, artifact_name, archive_type, "
                "sha256_digest, size) "
                f"VALUES ('{uuid4()}', 'conflicting-manifest', '1.0.0', "
                f"'linux_amd64', 'legacy-{build_id.hex}', 'conflict.zip', "
                "'https://releases.example.test/conflict.zip', 'conflict.zip', "
                f"'zip', '{('2' * 64)}', 2)",
            )
        )
    with pytest.raises(asyncpg.UniqueViolationError):
        asyncio.run(
            _execute(
                plain_url,
                "INSERT INTO update_reports "
                "(id, update_target_id, device_id, report_identifier, report_key, "
                "reported_version, status) "
                f"VALUES ('{uuid4()}', '{target_id}', '{device_id}', "
                "'conflicting-report', 'legacy-report', '0.9.1', 'failed')",
            )
        )

    live_rollout_id = uuid4()
    live_target_id = uuid4()
    operation_id = uuid4()
    asyncio.run(
        _execute(
            plain_url,
            "INSERT INTO update_rollouts "
            "(id, rollout_identifier, build_id, status, mode, started_at) "
            f"VALUES ('{live_rollout_id}', 'live-rollout', '{build_id}', "
            "'active', 'canary', CURRENT_TIMESTAMP); "
            "INSERT INTO update_targets "
            "(id, rollout_id, device_id, target_identifier, status, operation_id, "
            "assigned_at) "
            f"VALUES ('{live_target_id}', '{live_rollout_id}', '{device_id}', "
            f"'live-target', 'assigned', '{operation_id}', CURRENT_TIMESTAMP)",
        )
    )
    conflicting_rollout_id = uuid4()
    conflicting_target_id = uuid4()
    asyncio.run(
        _execute(
            plain_url,
            "INSERT INTO update_rollouts "
            "(id, rollout_identifier, build_id, status, mode, started_at) "
            f"VALUES ('{conflicting_rollout_id}', 'conflicting-rollout', "
            f"'{build_id}', 'active', 'canary', CURRENT_TIMESTAMP)",
        )
    )
    with pytest.raises(asyncpg.UniqueViolationError):
        asyncio.run(
            _execute(
                plain_url,
                "INSERT INTO update_targets "
                "(id, rollout_id, device_id, target_identifier, status, "
                "operation_id, assigned_at) "
                f"VALUES ('{conflicting_target_id}', '{conflicting_rollout_id}', "
                f"'{device_id}', 'conflicting-target', 'requested', "
                f"'{uuid4()}', CURRENT_TIMESTAMP)",
            )
        )

    command.downgrade(config, "0005_enrollment_campaigns")
    downgraded = asyncio.run(
        _fetch(
            plain_url,
            "SELECT r.id AS rollout_id, r.status AS rollout_status, "
            "r.completed_at IS NOT NULL AS rollout_terminal, "
            "t.id AS target_id, t.status AS target_status, "
            "t.updated_at IS NOT NULL AS target_terminal "
            "FROM update_rollouts r "
            "JOIN update_targets t ON t.rollout_id = r.id "
            f"WHERE r.id IN ('{rollout_id}', '{live_rollout_id}') "
            "ORDER BY r.id",
        )
    )
    assert len(downgraded) == 2
    assert all(row["rollout_status"] == "cancelled" for row in downgraded)
    assert all(row["rollout_terminal"] for row in downgraded)
    assert all(row["target_status"] == "cancelled" for row in downgraded)
    assert all(row["target_terminal"] for row in downgraded)
    history_counts = asyncio.run(
        _fetch(
            plain_url,
            "SELECT "
            f"(SELECT count(*) FROM update_builds WHERE id = '{build_id}') "
            "AS builds, "
            f"(SELECT count(*) FROM update_reports WHERE id = '{report_id}') "
            "AS reports",
        )
    )[0]
    assert history_counts["builds"] == 1
    assert history_counts["reports"] == 1

    command.upgrade(config, "head")
    round_trip = asyncio.run(
        _fetch(
            plain_url,
            "SELECT r.status AS rollout_status, t.status AS target_status, "
            "p.report_key, p.status AS report_status "
            "FROM update_rollouts r "
            "JOIN update_targets t ON t.rollout_id = r.id "
            "LEFT JOIN update_reports p ON p.update_target_id = t.id "
            f"WHERE r.id IN ('{rollout_id}', '{live_rollout_id}') "
            "ORDER BY r.id",
        )
    )
    assert len(round_trip) == 2
    assert all(row["rollout_status"] == "cancelled" for row in round_trip)
    assert all(row["target_status"] == "cancelled" for row in round_trip)
    assert {row["report_key"] for row in round_trip} == {"legacy-report", None}
    assert {row["report_status"] for row in round_trip} == {"legacy_success", None}


@pytest.fixture(scope="module")
def update_service_database_url() -> Iterator[str]:
    admin_url = os.environ.get("ENDPOINT_TEST_POSTGRES_URL")
    if not admin_url:
        pytest.skip("set ENDPOINT_TEST_POSTGRES_URL to a disposable PostgreSQL server")
    parsed = make_url(admin_url)
    if parsed.host not in {"127.0.0.1", "localhost", "::1"}:
        pytest.fail("update service tests may only use loopback PostgreSQL")
    plain_admin_url = parsed.set(drivername="postgresql").render_as_string(
        hide_password=False
    )
    database_name = f"endpoint_update_service_{uuid4().hex}"
    asyncio.run(_execute(plain_admin_url, f'CREATE DATABASE "{database_name}"'))
    async_url = parsed.set(
        drivername="postgresql+asyncpg",
        database=database_name,
    ).render_as_string(hide_password=False)
    command.upgrade(_alembic_config(async_url), "head")
    try:
        yield async_url
    finally:
        asyncio.run(
            _execute(
                plain_admin_url,
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                f"WHERE datname = '{database_name}' AND pid <> pg_backend_pid()",
            )
        )
        asyncio.run(_execute(plain_admin_url, f'DROP DATABASE "{database_name}"'))


@pytest_asyncio.fixture
async def update_service_provider(
    update_service_database_url: str,
) -> AsyncIterator[AsyncSessionProvider]:
    provider = AsyncSessionProvider(update_service_database_url)
    try:
        yield provider
    finally:
        await provider.close()


def _postgres_manifest(
    *,
    build_identifier: str,
    version: str,
    channel: str,
    digest_character: str,
) -> UpdateBuildManifestV1:
    artifact_name = f"{build_identifier}.tar.gz"
    return UpdateBuildManifestV1(
        schema_version="update_build_manifest_v1",
        build_identifier=build_identifier,
        version=version,
        platform="linux_amd64",
        channel=channel,
        artifact_url=f"https://releases.example.test/{artifact_name}",
        artifact_name=artifact_name,
        archive_type="tar.gz",
        sha256=digest_character * 64,
        size=8192,
        release_notes=None,
    )


@pytest.mark.asyncio
async def test_concurrent_active_assignments_leave_one_target(
    update_service_provider: AsyncSessionProvider,
) -> None:
    """Device-row locking and the partial unique index must elect one assignment."""
    now = datetime.now(UTC)
    device = Device(
        id=uuid4(),
        device_identifier=f"update-race-{uuid4().hex}",
        display_name="Update assignment race",
        retired_at=None,
    )
    async with update_service_provider() as session:
        first_build = await register_build(
            session,
            _postgres_manifest(
                build_identifier=f"race-first-{uuid4().hex}",
                version="3.0.0",
                channel="stable",
                digest_character="3",
            ),
            "postgres-admin",
            f"build-first-{uuid4().hex}",
            now=now,
        )
        second_build = await register_build(
            session,
            _postgres_manifest(
                build_identifier=f"race-second-{uuid4().hex}",
                version="3.1.0",
                channel="canary",
                digest_character="4",
            ),
            "postgres-admin",
            f"build-second-{uuid4().hex}",
            now=now,
        )
        session.add(device)
        await session.commit()

    async def assign(build_id: object, suffix: str) -> object:
        async with update_service_provider() as session:
            try:
                rollout = await create_rollout(
                    session,
                    build_id,
                    "canary",
                    [device.id],
                    f"{suffix} race assignment",
                    "postgres-admin",
                    f"assign-{suffix}-{uuid4().hex}",
                    now=now,
                )
                await session.commit()
                return rollout
            except Exception as error:
                await session.rollback()
                return error

    outcomes = await asyncio.gather(
        assign(first_build.id, "first"),
        assign(second_build.id, "second"),
    )
    assert sum(isinstance(item, UpdateRollout) for item in outcomes) == 1
    assert sum(isinstance(item, UpdateConflict) for item in outcomes) == 1

    async with update_service_provider() as session:
        active_targets = await session.scalar(
            select(func.count())
            .select_from(UpdateTarget)
            .where(
                UpdateTarget.device_id == device.id,
                UpdateTarget.status.in_(("assigned", "requested", "scheduled")),
            )
        )
        rollout_audits = await session.scalar(
            select(func.count())
            .select_from(AuditEvent)
            .where(
                AuditEvent.action == "updates.rollout_created",
                AuditEvent.details["target_count"].as_integer() == 1,
            )
        )
        target_audits = await session.scalar(
            select(func.count())
            .select_from(AuditEvent)
            .where(
                AuditEvent.action == "updates.target_assigned",
                AuditEvent.details["device_id"].as_string() == str(device.id),
            )
        )
    assert active_targets == 1
    assert rollout_audits >= 1
    assert target_audits == 1


@pytest.mark.asyncio
async def test_concurrent_conflicting_report_key_persists_one_terminal_result(
    update_service_provider: AsyncSessionProvider,
) -> None:
    """Target-row locking must make one report-key payload authoritative."""
    now = datetime.now(UTC)
    device = Device(
        id=uuid4(),
        device_identifier=f"report-race-{uuid4().hex}",
        display_name="Update report race",
        retired_at=None,
    )
    async with update_service_provider() as session:
        build = await register_build(
            session,
            _postgres_manifest(
                build_identifier=f"report-build-{uuid4().hex}",
                version="4.0.0",
                channel="stable",
                digest_character="5",
            ),
            "postgres-admin",
            f"report-build-{uuid4().hex}",
            now=now,
        )
        session.add(device)
        await session.flush()
        rollout = await create_rollout(
            session,
            build.id,
            "canary",
            [device.id],
            "report race assignment",
            "postgres-admin",
            f"report-rollout-{uuid4().hex}",
            now=now,
        )
        target = await session.scalar(
            select(UpdateTarget).where(UpdateTarget.rollout_id == rollout.id)
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
            request_id=f"report-requested-{uuid4().hex}",
            now=now,
        )
        await record_ack(
            session,
            device_id=device.id,
            operation_id=target.operation_id,
            acknowledgement=AgentUpdateAcknowledgementV1(
                schema_version="agent_update_ack_v1",
                status="scheduled",
            ),
            request_id=f"report-scheduled-{uuid4().hex}",
            now=now,
        )
        operation_id = target.operation_id
        await session.commit()

    async def report(status: str, safe_code: str) -> object:
        async with update_service_provider() as session:
            try:
                result = await record_report(
                    session,
                    device_id=device.id,
                    operation_id=operation_id,
                    report=AgentUpdateReportV1(
                        schema_version="agent_update_report_v1",
                        report_key="same-operation-result",
                        status=status,
                        reported_version="4.0.0",
                        safe_code=safe_code,
                    ),
                    request_id=f"report-{status}-{uuid4().hex}",
                    now=now,
                )
                await session.commit()
                return result
            except Exception as error:
                await session.rollback()
                return error

    outcomes = await asyncio.gather(
        report("applied", "update.applied"),
        report("failed", "update.failed"),
    )
    assert sum(isinstance(item, UpdateReport) for item in outcomes) == 1
    assert sum(isinstance(item, UpdateConflict) for item in outcomes) == 1

    async with update_service_provider() as session:
        reports = (
            await session.scalars(
                select(UpdateReport).where(UpdateReport.update_target_id == target.id)
            )
        ).all()
        persisted_target = await session.get(UpdateTarget, target.id)
        report_audits = (
            await session.scalars(
                select(AuditEvent).where(
                    AuditEvent.action == "updates.target_reported",
                    AuditEvent.object_identifier == str(target.id),
                )
            )
        ).all()
    assert len(reports) == 1
    assert persisted_target is not None
    assert persisted_target.status == reports[0].status
    assert persisted_target.status in {"applied", "failed"}
    assert len(report_audits) == 1
