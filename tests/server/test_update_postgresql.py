"""Persistence and populated PostgreSQL checks for update rollout control state."""

from __future__ import annotations

import asyncio
import os
from collections.abc import Iterator
from pathlib import Path
from uuid import uuid4

import asyncpg
import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import UniqueConstraint
from sqlalchemy.dialects import postgresql
from sqlalchemy.engine import make_url
from sqlalchemy.schema import CreateIndex

from endpoint_server.db.models import (
    UpdateBuild,
    UpdateReport,
    UpdateRollout,
    UpdateTarget,
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
    asyncio.run(
        _execute(plain_admin_url, f'CREATE DATABASE "{database_name}"')
    )
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
        asyncio.run(
            _execute(plain_admin_url, f'DROP DATABASE "{database_name}"')
        )


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
    assert upgraded[0]["artifact_url"] == (
        f"https://invalid.invalid/legacy/{build_id}"
    )
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
