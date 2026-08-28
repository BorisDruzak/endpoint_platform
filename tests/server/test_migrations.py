"""Integration tests for the initial Endpoint Platform PostgreSQL schema."""

from __future__ import annotations

import asyncio
import io
import os
from collections.abc import Iterator
from pathlib import Path
from uuid import uuid4

import asyncpg
import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy.dialects import postgresql
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError
from sqlalchemy.schema import CreateIndex
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from endpoint_server.db.models import DeviceSession, EndpointOperation
from endpoint_server.modules.execution_routes import _project_module_operation


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
APPLICATION_TABLES = {
    "admin_sessions",
    "admin_users",
    "audit_events",
    "command_deliveries",
    "command_results",
    "commands",
    "context_collections",
    "context_current",
    "context_diffs",
    "context_findings",
    "context_snapshots",
    "device_credentials",
    "device_instances",
    "device_sessions",
    "devices",
    "enrollment_campaigns",
    "enrollment_claims",
    "enrollment_events",
    "enrollment_retry_envelopes",
    "endpoint_operations",
    "service_clients",
    "service_credentials",
    "update_builds",
    "update_reports",
    "update_rollouts",
    "update_targets",
}
CREDENTIAL_TABLE_COLUMNS = {
    "admin_users": {"password_digest"},
    "device_credentials": {"token_digest"},
    "enrollment_campaigns": {"token_digest"},
    "enrollment_claims": {"claim_digest"},
    "service_credentials": {"secret_digest"},
}
FORBIDDEN_RAW_CREDENTIAL_COLUMNS = {
    "credential",
    "password",
    "private_key",
    "secret",
    "token",
}


def _admin_database_url() -> str:
    url = os.environ.get("ENDPOINT_TEST_POSTGRES_URL")
    if not url:
        pytest.skip(
            "set ENDPOINT_TEST_POSTGRES_URL to a disposable local PostgreSQL server"
        )
    parsed = make_url(url)
    if parsed.host not in {"127.0.0.1", "localhost", "::1"}:
        pytest.fail("migration tests may only use a loopback PostgreSQL server")
    return url


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


@pytest.fixture(scope="module")
def empty_database_url() -> Iterator[str]:
    admin_url = _admin_database_url()
    database_name = f"endpoint_migrations_{uuid4().hex}"
    asyncio.run(_execute(admin_url, f'CREATE DATABASE "{database_name}"'))
    database_url = (
        make_url(admin_url)
        .set(drivername="postgresql+asyncpg", database=database_name)
        .render_as_string(hide_password=False)
    )
    try:
        yield database_url
    finally:
        asyncio.run(
            _execute(
                admin_url,
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                f"WHERE datname = '{database_name}' AND pid <> pg_backend_pid()",
            )
        )
        asyncio.run(_execute(admin_url, f'DROP DATABASE "{database_name}"'))


def _alembic_config(database_url: str) -> Config:
    config = Config(REPOSITORY_ROOT / "alembic.ini")
    config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    return config


def test_migration_history_has_exactly_one_head() -> None:
    script = ScriptDirectory.from_config(
        _alembic_config("postgresql+asyncpg://unused@127.0.0.1/unused")
    )

    assert script.get_heads() == ["0018_module_step_count"]


def test_migration_revisions_fit_alembic_version_storage() -> None:
    """Alembic's default version table stores identifiers in VARCHAR(32)."""
    script = ScriptDirectory.from_config(
        _alembic_config("postgresql+asyncpg://unused@127.0.0.1/unused")
    )

    assert all(len(revision.revision) <= 32 for revision in script.walk_revisions())


def test_module_operation_step_migration_preserves_context_boundary() -> None:
    output = io.StringIO()
    config = Config(REPOSITORY_ROOT / "alembic.ini", output_buffer=output)
    config.set_main_option(
        "sqlalchemy.url",
        "postgresql+asyncpg://unused@127.0.0.1/unused",
    )

    command.upgrade(
        config,
        "0016_module_validation_evidence:0017_module_operation_steps",
        sql=True,
    )

    rendered = " ".join(output.getvalue().split())
    assert "ADD COLUMN module_version_id UUID" in rendered
    assert "ADD COLUMN module_inputs JSONB" in rendered
    assert "CREATE TABLE endpoint_operation_steps" in rendered
    assert "CONSTRAINT uq_endpoint_operation_steps_sequence UNIQUE (operation_id, sequence)" in rendered
    assert "CONSTRAINT uq_endpoint_operation_steps_recipe_key UNIQUE (operation_id, recipe_step_key)" in rendered
    assert "CONSTRAINT ck_endpoint_operation_steps_capability CHECK (capability IN ('dns.resolve', 'network.ping', 'tcp.connect'))" in rendered
    assert "endpoint.module.recipe" in rendered


def test_module_operation_expected_step_count_migration_is_bounded() -> None:
    output = io.StringIO()
    config = Config(REPOSITORY_ROOT / "alembic.ini", output_buffer=output)
    config.set_main_option(
        "sqlalchemy.url",
        "postgresql+asyncpg://unused@127.0.0.1/unused",
    )

    command.upgrade(
        config,
        "0017_module_operation_steps:0018_module_step_count",
        sql=True,
    )

    rendered = " ".join(output.getvalue().split())
    assert "ADD COLUMN expected_step_count BIGINT" in rendered
    assert (
        "CONSTRAINT ck_endpoint_operations_expected_step_count CHECK "
        "(expected_step_count IS NULL OR expected_step_count BETWEEN 1 AND 8)"
    ) in rendered
    assert "UPDATE endpoint_operations AS operation SET expected_step_count" in rendered
    assert "jsonb_array_length(version.recipe -> 'steps')" in rendered


def test_module_step_count_migration_backfills_a_populated_0017_operation(
    empty_database_url: str,
) -> None:
    """Historical immutable recipes, not remaining child rows, determine the count."""
    config = _alembic_config(empty_database_url)
    plain_url = (
        make_url(empty_database_url)
        .set(drivername="postgresql")
        .render_as_string(hide_password=False)
    )
    client_id = uuid4()
    device_id = uuid4()
    definition_id = uuid4()
    version_id = uuid4()
    operation_id = uuid4()
    first_step_id = uuid4()
    second_step_id = uuid4()
    command.upgrade(config, "0017_module_operation_steps")
    asyncio.run(
        _execute(
            plain_url,
            "INSERT INTO service_clients (id, client_identifier, display_name) "
            f"VALUES ('{client_id}', 'migration-client', 'Migration client'); "
            "INSERT INTO devices (id, device_identifier) "
            f"VALUES ('{device_id}', 'migration-device'); "
            "INSERT INTO module_definitions (id, module_key, display_name) "
            f"VALUES ('{definition_id}', 'network.migration.check', 'Migration'); "
            "INSERT INTO module_versions "
            "(id, module_definition_id, version, recipe, state) VALUES "
            f"('{version_id}', '{definition_id}', '1.0.0', "
            "'{\"schema_version\":\"endpoint_recipe_module_v1\",\"steps\":[{},{}]}'::jsonb, "
            "'published'); "
            "INSERT INTO endpoint_operations "
            "(id, requested_by_service_client_id, device_id, idempotency_key, capability, "
            "parameters, correlation, status, deadline_at, completed_at, context_collection_id, "
            "command_id, module_version_id, module_inputs) VALUES "
            f"('{operation_id}', '{client_id}', '{device_id}', 'migration-operation', "
            "'endpoint.module.recipe', '{\"execution_mode\":\"published\"}'::jsonb, "
            "NULL, 'queued', CURRENT_TIMESTAMP + INTERVAL '5 minutes', NULL, NULL, NULL, "
            f"'{version_id}', '{{\"target\":\"probe.example.test\"}}'::jsonb); "
            "INSERT INTO endpoint_operation_steps "
            "(id, operation_id, sequence, recipe_step_key, capability, status, command_id, "
            "safe_result_json, error_code, started_at, completed_at) VALUES "
            f"('{first_step_id}', '{operation_id}', 0, 'resolve', 'dns.resolve', 'queued', "
            "NULL, NULL, NULL, NULL, NULL), "
            f"('{second_step_id}', '{operation_id}', 1, 'ping', 'network.ping', 'queued', "
            "NULL, NULL, NULL, NULL, NULL)",
        )
    )
    command.upgrade(config, "0018_module_step_count")

    async def project() -> tuple[int, list[int]]:
        engine = create_async_engine(empty_database_url)
        provider = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with provider() as session:
                operation = await session.get(EndpointOperation, operation_id)
                assert operation is not None
                detail = await _project_module_operation(session, operation)
                return detail.expected_step_count, [step.sequence for step in detail.steps]
        finally:
            await engine.dispose()

    assert asyncio.run(project()) == (2, [0, 1])


def test_endpoint_operation_migration_enforces_scoped_one_to_one_ownership() -> None:
    """Nullable private links still need database-enforced unambiguous ownership."""
    output = io.StringIO()
    config = Config(REPOSITORY_ROOT / "alembic.ini", output_buffer=output)
    config.set_main_option(
        "sqlalchemy.url",
        "postgresql+asyncpg://unused@127.0.0.1/unused",
    )

    command.upgrade(
        config,
        "0013_runtime_session_heartbeat:0014_endpoint_operations",
        sql=True,
    )

    rendered = " ".join(output.getvalue().split())
    assert "CREATE TABLE endpoint_operations" in rendered
    assert (
        "CONSTRAINT uq_endpoint_operations_client_key UNIQUE "
        "(requested_by_service_client_id, idempotency_key)"
    ) in rendered
    assert (
        "CONSTRAINT uq_endpoint_operations_collection UNIQUE "
        "(context_collection_id)"
    ) in rendered
    assert "CONSTRAINT uq_endpoint_operations_command UNIQUE (command_id)" in rendered
    assert (
        "CONSTRAINT uq_context_collections_operation UNIQUE (operation_id)"
    ) in rendered
    assert (
        "CONSTRAINT uq_context_collections_operation_identity UNIQUE "
        "(operation_id, id)"
    ) in rendered
    assert (
        "CONSTRAINT fk_endpoint_operations_collection_identity FOREIGN KEY"
        "(id, context_collection_id) REFERENCES context_collections "
        "(operation_id, id) DEFERRABLE INITIALLY DEFERRED"
    ) in rendered
    assert (
        "CONSTRAINT fk_context_collections_operation_identity FOREIGN KEY"
        "(operation_id, id) REFERENCES endpoint_operations "
        "(id, context_collection_id) DEFERRABLE INITIALLY DEFERRED"
    ) in rendered


def test_device_session_last_seen_index_migration_is_additive_and_ordered() -> None:
    """The list API needs one deterministic latest-session lookup per device set."""
    output = io.StringIO()
    config = Config(REPOSITORY_ROOT / "alembic.ini", output_buffer=output)
    config.set_main_option(
        "sqlalchemy.url",
        "postgresql+asyncpg://unused@127.0.0.1/unused",
    )

    command.upgrade(
        config,
        "0009_context_snapshot_pins:0010_session_last_seen_index",
        sql=True,
    )

    rendered = " ".join(output.getvalue().split())
    assert (
        "CREATE INDEX ix_device_sessions_device_created_id_desc ON device_sessions "
        "(device_id, created_at DESC, id DESC);"
    ) in rendered


def test_device_session_model_declares_last_seen_index() -> None:
    """ORM metadata must match the additive index consumed by the list query."""
    indexes = {index.name: index for index in DeviceSession.__table__.indexes}

    rendered = " ".join(
        str(
            CreateIndex(indexes["ix_device_sessions_device_created_id_desc"]).compile(
                dialect=postgresql.dialect()
            )
        ).split()
    )

    assert rendered == (
        "CREATE INDEX ix_device_sessions_device_created_id_desc ON device_sessions "
        "(device_id, created_at DESC, id DESC)"
    )


def test_gateway_downgrade_guards_long_agent_versions_before_metadata_drop() -> None:
    """Valid V1 versions must not make a downgrade fail after partial teardown."""
    output = io.StringIO()
    config = Config(REPOSITORY_ROOT / "alembic.ini", output_buffer=output)
    config.set_main_option(
        "sqlalchemy.url",
        "postgresql+asyncpg://unused@127.0.0.1/unused",
    )

    command.downgrade(
        config,
        "0011_gateway_wss:0010_session_last_seen_index",
        sql=True,
    )

    rendered = " ".join(output.getvalue().split())
    guard = "IF EXISTS (SELECT 1 FROM device_instances WHERE length(agent_version) > 64)"
    metadata_drop = "ALTER TABLE command_results DROP COLUMN result_sequence;"
    narrowing = "ALTER TABLE device_instances ALTER COLUMN agent_version TYPE VARCHAR(64);"
    assert guard in rendered
    assert metadata_drop in rendered
    assert narrowing in rendered
    assert rendered.index(guard) < rendered.index(metadata_drop)
    assert rendered.index(guard) < rendered.index(narrowing)


def test_gateway_downgrade_rejects_valid_long_version_on_postgresql(
    empty_database_url: str,
) -> None:
    """The live migration must preserve metadata when narrowing is unsafe."""
    config = _alembic_config(empty_database_url)
    plain_url = (
        make_url(empty_database_url)
        .set(drivername="postgresql")
        .render_as_string(hide_password=False)
    )
    device_id = uuid4()
    instance_id = uuid4()
    command.upgrade(config, "head")
    asyncio.run(
        _execute(
            plain_url,
            "INSERT INTO devices (id, device_identifier) "
            f"VALUES ('{device_id}', 'gateway-downgrade-device'); "
            "INSERT INTO device_instances "
            "(id, device_id, instance_identifier, agent_version) "
            f"VALUES ('{instance_id}', '{device_id}', "
            f"'gateway-downgrade-instance', '{'v' * 65}')",
        )
    )

    with pytest.raises(DBAPIError, match="agent_version.*64"):
        command.downgrade(config, "0010_session_last_seen_index")

    revision_rows = asyncio.run(
        _fetch(plain_url, "SELECT version_num FROM alembic_version")
    )
    assert [row["version_num"] for row in revision_rows] == ["0011_gateway_wss"]
    columns = asyncio.run(
        _fetch(
            plain_url,
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_name = 'command_results' "
            "AND column_name = 'result_sequence'",
        )
    )
    assert len(columns) == 1

    asyncio.run(
        _execute(
            plain_url,
            f"DELETE FROM device_instances WHERE id = '{instance_id}'; "
            f"DELETE FROM devices WHERE id = '{device_id}'",
        )
    )
    command.downgrade(config, "base")


def test_device_context_migration_binds_current_pointer_to_snapshot_identity() -> None:
    """A snapshot-id-only FK would allow a cross-device/profile current row."""
    output = io.StringIO()
    config = Config(REPOSITORY_ROOT / "alembic.ini", output_buffer=output)
    config.set_main_option(
        "sqlalchemy.url",
        "postgresql+asyncpg://unused@127.0.0.1/unused",
    )

    command.upgrade(
        config,
        "0007_admin_update_scopes:0008_device_context_foundation",
        sql=True,
    )

    rendered = " ".join(output.getvalue().split())
    assert (
        "CONSTRAINT uq_context_snapshots_identity UNIQUE (id, device_id, profile)"
    ) in rendered
    assert (
        "CONSTRAINT fk_context_current_snapshot_identity FOREIGN KEY"
        "(snapshot_id, device_id, profile) REFERENCES context_snapshots "
        "(id, device_id, profile) ON DELETE CASCADE"
    ) in rendered
    assert (
        "CONSTRAINT uq_context_collections_request UNIQUE "
        "(device_id, profile, requested_by, idempotency_key)"
    ) in rendered


def test_device_context_pin_migration_adds_only_the_explicit_pin_column() -> None:
    """The final Device Context revision must retain its narrow schema delta."""
    output = io.StringIO()
    config = Config(REPOSITORY_ROOT / "alembic.ini", output_buffer=output)
    config.set_main_option(
        "sqlalchemy.url",
        "postgresql+asyncpg://unused@127.0.0.1/unused",
    )

    command.upgrade(
        config,
        "0008_device_context_foundation:0009_context_snapshot_pins",
        sql=True,
    )

    rendered = " ".join(output.getvalue().split())
    assert (
        "ALTER TABLE context_snapshots ADD COLUMN pinned_at TIMESTAMP WITH TIME ZONE;"
        in rendered
    )


def test_update_downgrade_sql_neutralizes_actionable_assignments() -> None:
    """Dropping rollout state must cancel assignments before their state is lost."""
    output = io.StringIO()
    config = Config(REPOSITORY_ROOT / "alembic.ini", output_buffer=output)
    config.set_main_option(
        "sqlalchemy.url",
        "postgresql+asyncpg://unused@127.0.0.1/unused",
    )

    command.downgrade(
        config,
        "0006_update_control_plane:0005_enrollment_campaigns",
        sql=True,
    )

    rendered = " ".join(output.getvalue().split())
    rollout_update = (
        "UPDATE update_rollouts SET status = 'cancelled', completed_at = "
        "COALESCE(completed_at, cancelled_at, paused_at, started_at, "
        "CURRENT_TIMESTAMP) WHERE status IN ('draft', 'active', 'paused');"
    )
    target_update = (
        "UPDATE update_targets SET status = 'cancelled', updated_at = "
        "COALESCE(terminal_at, scheduled_at, requested_at, assigned_at, "
        "updated_at, CURRENT_TIMESTAMP) WHERE status IN "
        "('assigned', 'requested', 'scheduled');"
    )
    assert rollout_update in rendered
    assert target_update in rendered
    assert rendered.index(rollout_update) < rendered.index("DROP COLUMN cancelled_at")
    assert rendered.index(target_update) < rendered.index("DROP COLUMN operation_id")


def test_admin_scope_migration_backfills_explicit_update_grant() -> None:
    """Existing interactive admins need a persisted grant, never a header fallback."""
    output = io.StringIO()
    config = Config(REPOSITORY_ROOT / "alembic.ini", output_buffer=output)
    config.set_main_option(
        "sqlalchemy.url",
        "postgresql+asyncpg://unused@127.0.0.1/unused",
    )

    command.upgrade(
        config,
        "0006_update_control_plane:0007_admin_update_scopes",
        sql=True,
    )

    rendered = " ".join(output.getvalue().split())
    add_column = "ALTER TABLE admin_users ADD COLUMN scopes VARCHAR(128)[];"
    backfill = "UPDATE admin_users SET scopes = ARRAY['updates:write']::varchar[];"
    not_null = "ALTER TABLE admin_users ALTER COLUMN scopes SET NOT NULL;"
    assert add_column in rendered
    assert backfill in rendered
    assert not_null in rendered
    assert rendered.index(add_column) < rendered.index(backfill)
    assert rendered.index(backfill) < rendered.index(not_null)


def test_enrollment_downgrade_sql_neutralizes_bounded_credentials() -> None:
    """Dropping Task 2 state must not revive revoked campaigns or active claims."""
    output = io.StringIO()
    config = Config(REPOSITORY_ROOT / "alembic.ini", output_buffer=output)
    config.set_main_option(
        "sqlalchemy.url",
        "postgresql+asyncpg://unused@127.0.0.1/unused",
    )

    command.downgrade(
        config,
        "0005_enrollment_campaigns:0004_device_credentials",
        sql=True,
    )

    rendered = " ".join(output.getvalue().split())
    assert (
        "UPDATE enrollment_campaigns SET disabled_at = "
        "COALESCE(disabled_at, CURRENT_TIMESTAMP) "
        "WHERE revoked_at IS NOT NULL OR use_count >= max_uses;"
    ) in rendered
    assert (
        "UPDATE enrollment_claims SET claimed_at = "
        "COALESCE(claimed_at, CURRENT_TIMESTAMP);"
    ) in rendered


def test_initial_revision_upgrades_and_downgrades_empty_postgresql(
    empty_database_url: str,
) -> None:
    config = _alembic_config(empty_database_url)
    plain_url = (
        make_url(empty_database_url)
        .set(drivername="postgresql")
        .render_as_string(hide_password=False)
    )
    client_id = uuid4()
    credential_id = uuid4()
    audit_id = uuid4()
    admin_user_id = uuid4()
    device_id = uuid4()
    device_credential_id = uuid4()
    campaign_id = uuid4()
    claim_id = uuid4()
    exhausted_campaign_id = uuid4()
    exhausted_claim_id = uuid4()

    command.upgrade(config, "0001_initial")
    asyncio.run(
        _execute(
            plain_url,
            "INSERT INTO admin_users "
            "(id, username, password_digest) "
            f"VALUES ('{admin_user_id}', 'legacy-admin', 'legacy-digest'); "
            "INSERT INTO service_clients "
            "(id, client_identifier, display_name) "
            f"VALUES ('{client_id}', 'legacy-client', 'Legacy client'); "
            "INSERT INTO service_credentials "
            "(id, service_client_id, credential_identifier, secret_digest) "
            f"VALUES ('{credential_id}', '{client_id}', "
            "'legacy-credential', 'legacy-digest'); "
            "INSERT INTO audit_events "
            "(id, actor_kind, action, object_kind) "
            f"VALUES ('{audit_id}', 'system', 'legacy.created', 'legacy')",
        )
    )

    command.upgrade(config, "0002_service_credentials")
    credential_rows = asyncio.run(
        _fetch(
            plain_url,
            "SELECT token_prefix, scopes FROM service_credentials "
            f"WHERE id = '{credential_id}'",
        )
    )
    assert len(credential_rows) == 1
    assert credential_rows[0]["token_prefix"] == (f"svc_migrated_{credential_id.hex}")
    assert credential_rows[0]["scopes"] == []

    command.upgrade(config, "0003_immutable_audit")
    asyncio.run(
        _execute(
            plain_url,
            "INSERT INTO devices "
            "(id, device_identifier, display_name) "
            f"VALUES ('{device_id}', 'legacy-device', 'Legacy device'); "
            "INSERT INTO device_credentials "
            "(id, device_id, credential_identifier, token_digest, expires_at) "
            f"VALUES ('{device_credential_id}', '{device_id}', "
            "'legacy-device-credential', 'legacy-device-token-digest', "
            "'2026-07-30T10:00:00+00:00')",
        )
    )

    command.upgrade(config, "0004_device_credentials")
    asyncio.run(
        _execute(
            plain_url,
            "INSERT INTO enrollment_campaigns "
            "(id, campaign_identifier, token_digest, expires_at) "
            f"VALUES ('{campaign_id}', 'legacy-campaign', "
            "'legacy-campaign-digest', '2026-07-30T10:00:00+00:00'), "
            f"('{exhausted_campaign_id}', 'legacy-exhausted-campaign', "
            "'legacy-exhausted-campaign-digest', "
            "'2026-07-30T10:00:00+00:00'); "
            "INSERT INTO enrollment_claims "
            "(id, campaign_id, claim_identifier) "
            f"VALUES ('{claim_id}', '{campaign_id}', 'legacy-claim'), "
            f"('{exhausted_claim_id}', '{exhausted_campaign_id}', "
            "'legacy-exhausted-claim')",
        )
    )

    command.upgrade(config, "head")
    admin_scope_rows = asyncio.run(
        _fetch(
            plain_url,
            f"SELECT scopes FROM admin_users WHERE id = '{admin_user_id}'",
        )
    )
    assert len(admin_scope_rows) == 1
    assert admin_scope_rows[0]["scopes"] == ["updates:write"]
    audit_rows = asyncio.run(
        _fetch(
            plain_url,
            "SELECT request_id, details::text AS details FROM audit_events "
            f"WHERE id = '{audit_id}'",
        )
    )
    assert len(audit_rows) == 1
    assert audit_rows[0]["request_id"] == f"legacy-{audit_id.hex}"
    assert audit_rows[0]["details"] == "{}"

    device_credential_rows = asyncio.run(
        _fetch(
            plain_url,
            "SELECT device_id, credential_identifier, token_digest, "
            "extract(epoch FROM expires_at)::bigint AS expires_epoch, "
            "pending_token_digest, rotation_overlap_expires_at "
            "FROM device_credentials "
            f"WHERE id = '{device_credential_id}'",
        )
    )
    assert len(device_credential_rows) == 1
    assert device_credential_rows[0]["device_id"] == device_id
    assert (
        device_credential_rows[0]["credential_identifier"] == "legacy-device-credential"
    )
    assert device_credential_rows[0]["token_digest"] == "legacy-device-token-digest"
    assert device_credential_rows[0]["expires_epoch"] == 1785405600
    assert device_credential_rows[0]["pending_token_digest"] is None
    assert device_credential_rows[0]["rotation_overlap_expires_at"] is None

    campaign_rows = asyncio.run(
        _fetch(
            plain_url,
            "SELECT max_uses, use_count, allowed_cidrs, target_platform, "
            "policy::text AS policy FROM enrollment_campaigns "
            f"WHERE id = '{campaign_id}'",
        )
    )
    assert len(campaign_rows) == 1
    assert campaign_rows[0]["max_uses"] == 1
    assert campaign_rows[0]["use_count"] == 0
    assert campaign_rows[0]["allowed_cidrs"] == ["0.0.0.0/0", "::/0"]
    assert campaign_rows[0]["target_platform"] == "legacy"
    assert campaign_rows[0]["policy"] == "{}"

    claim_rows = asyncio.run(
        _fetch(
            plain_url,
            "SELECT claim_digest, installation_session_digest, "
            "fingerprint_digest, expires_at = created_at AS expired_on_migration "
            "FROM enrollment_claims "
            f"WHERE id = '{claim_id}'",
        )
    )
    assert len(claim_rows) == 1
    assert claim_rows[0]["claim_digest"] == f"migrated-claim-{claim_id.hex}"
    assert claim_rows[0]["installation_session_digest"] == (
        f"migrated-session-{claim_id.hex}"
    )
    assert claim_rows[0]["fingerprint_digest"] == (
        f"migrated-fingerprint-{claim_id.hex}"
    )
    assert claim_rows[0]["expired_on_migration"]

    rows = asyncio.run(
        _fetch(
            plain_url,
            "SELECT tablename FROM pg_catalog.pg_tables "
            "WHERE schemaname = 'public' ORDER BY tablename",
        )
    )
    assert {row["tablename"] for row in rows} == APPLICATION_TABLES | {
        "alembic_version"
    }

    revision_rows = asyncio.run(
        _fetch(plain_url, "SELECT version_num FROM alembic_version")
    )
    assert [row["version_num"] for row in revision_rows] == [
        "0014_endpoint_operations"
    ]

    column_rows = asyncio.run(
        _fetch(
            plain_url,
            "SELECT table_name, column_name, data_type, character_maximum_length "
            "FROM information_schema.columns "
            "WHERE table_schema = 'public' "
            "ORDER BY table_name, ordinal_position",
        )
    )
    columns_by_table: dict[str, dict[str, asyncpg.Record]] = {
        table: {} for table in APPLICATION_TABLES
    }
    for row in column_rows:
        if row["table_name"] in columns_by_table:
            columns_by_table[row["table_name"]][row["column_name"]] = row

    for table_name, columns in columns_by_table.items():
        assert columns["id"]["data_type"] == "uuid", table_name
        assert columns["created_at"]["data_type"] == "timestamp with time zone", (
            table_name
        )
        for column in columns.values():
            if column["data_type"] == "character varying":
                assert 0 < column["character_maximum_length"] <= 256
        assert not FORBIDDEN_RAW_CREDENTIAL_COLUMNS.intersection(columns), table_name

    for table_name, digest_columns in CREDENTIAL_TABLE_COLUMNS.items():
        assert digest_columns <= columns_by_table[table_name].keys()

    assert {"token_prefix", "scopes"} <= columns_by_table["service_credentials"].keys()
    assert columns_by_table["service_credentials"]["scopes"]["data_type"] == "ARRAY"
    assert {"scopes"} <= columns_by_table["admin_users"].keys()
    assert columns_by_table["admin_users"]["scopes"]["data_type"] == "ARRAY"
    assert {"request_id", "details"} <= columns_by_table["audit_events"].keys()
    assert columns_by_table["audit_events"]["details"]["data_type"] == "jsonb"
    assert {
        "pending_token_digest",
        "rotation_overlap_expires_at",
    } <= columns_by_table["device_credentials"].keys()
    assert {
        "device_credential_id",
        "receipt_digest",
        "fingerprint_digest",
        "encrypted_token",
        "encryption_nonce",
        "expires_at",
    } <= columns_by_table["enrollment_retry_envelopes"].keys()
    assert "pinned_at" in columns_by_table["context_snapshots"]
    assert (
        columns_by_table["context_snapshots"]["pinned_at"]["data_type"]
        == "timestamp with time zone"
    )
    assert {
        "max_uses",
        "use_count",
        "allowed_cidrs",
        "target_platform",
        "policy",
        "label",
        "site",
        "revoked_at",
    } <= columns_by_table["enrollment_campaigns"].keys()
    assert (
        columns_by_table["enrollment_campaigns"]["allowed_cidrs"]["data_type"]
        == "ARRAY"
    )
    assert columns_by_table["enrollment_campaigns"]["policy"]["data_type"] == "jsonb"
    assert {
        "claim_digest",
        "installation_session_digest",
        "fingerprint_digest",
        "expires_at",
    } <= columns_by_table["enrollment_claims"].keys()

    for statement in (
        f"UPDATE audit_events SET action = 'changed' WHERE id = '{audit_id}'",
        f"DELETE FROM audit_events WHERE id = '{audit_id}'",
    ):
        with pytest.raises(asyncpg.PostgresError, match="append-only") as rejected:
            asyncio.run(_execute(plain_url, statement))
        assert rejected.value.sqlstate == "55000"

    asyncio.run(
        _execute(
            plain_url,
            "UPDATE enrollment_campaigns SET revoked_at = CURRENT_TIMESTAMP "
            f"WHERE id = '{campaign_id}'; "
            "UPDATE enrollment_campaigns SET use_count = max_uses "
            f"WHERE id = '{exhausted_campaign_id}'",
        )
    )
    command.downgrade(config, "0004_device_credentials")
    downgraded_campaign_rows = asyncio.run(
        _fetch(
            plain_url,
            "SELECT id, disabled_at IS NOT NULL AS disabled "
            "FROM enrollment_campaigns "
            f"WHERE id IN ('{campaign_id}', '{exhausted_campaign_id}') "
            "ORDER BY id",
        )
    )
    assert len(downgraded_campaign_rows) == 2
    assert all(row["disabled"] for row in downgraded_campaign_rows)
    downgraded_claim_rows = asyncio.run(
        _fetch(
            plain_url,
            "SELECT id, claimed_at IS NOT NULL AS neutralized "
            "FROM enrollment_claims "
            f"WHERE id IN ('{claim_id}', '{exhausted_claim_id}') "
            "ORDER BY id",
        )
    )
    assert len(downgraded_claim_rows) == 2
    assert all(row["neutralized"] for row in downgraded_claim_rows)
    removed_enrollment_columns = asyncio.run(
        _fetch(
            plain_url,
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_schema = 'public' "
            "AND table_name IN ('enrollment_campaigns', 'enrollment_claims') "
            "AND column_name IN "
            "('revoked_at', 'max_uses', 'use_count', 'claim_digest', "
            "'installation_session_digest', 'fingerprint_digest')",
        )
    )
    assert removed_enrollment_columns == []

    command.upgrade(config, "head")
    round_trip_campaign_rows = asyncio.run(
        _fetch(
            plain_url,
            "SELECT id, disabled_at IS NOT NULL AS disabled "
            "FROM enrollment_campaigns "
            f"WHERE id IN ('{campaign_id}', '{exhausted_campaign_id}') "
            "ORDER BY id",
        )
    )
    assert len(round_trip_campaign_rows) == 2
    assert all(row["disabled"] for row in round_trip_campaign_rows)
    round_trip_claim_rows = asyncio.run(
        _fetch(
            plain_url,
            "SELECT id, claimed_at IS NOT NULL AS neutralized "
            "FROM enrollment_claims "
            f"WHERE id IN ('{claim_id}', '{exhausted_claim_id}') "
            "ORDER BY id",
        )
    )
    assert len(round_trip_claim_rows) == 2
    assert all(row["neutralized"] for row in round_trip_claim_rows)

    command.downgrade(config, "base")

    rows = asyncio.run(
        _fetch(
            plain_url,
            "SELECT tablename FROM pg_catalog.pg_tables "
            "WHERE schemaname = 'public' ORDER BY tablename",
        )
    )
    assert APPLICATION_TABLES.isdisjoint(row["tablename"] for row in rows)
