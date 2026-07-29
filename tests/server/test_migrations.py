"""Integration tests for the initial Endpoint Platform PostgreSQL schema."""

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
from alembic.script import ScriptDirectory
from sqlalchemy.engine import make_url


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
APPLICATION_TABLES = {
    "admin_sessions",
    "admin_users",
    "audit_events",
    "command_deliveries",
    "command_results",
    "commands",
    "device_credentials",
    "device_instances",
    "device_sessions",
    "devices",
    "enrollment_campaigns",
    "enrollment_claims",
    "enrollment_events",
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

    assert script.get_heads() == ["0003_immutable_audit"]


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

    command.upgrade(config, "0001_initial")
    asyncio.run(
        _execute(
            plain_url,
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

    command.upgrade(config, "head")
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
    assert [row["version_num"] for row in revision_rows] == ["0003_immutable_audit"]

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

    assert {"token_prefix", "scopes"} <= columns_by_table[
        "service_credentials"
    ].keys()
    assert columns_by_table["service_credentials"]["scopes"]["data_type"] == "ARRAY"
    assert {"request_id", "details"} <= columns_by_table["audit_events"].keys()
    assert columns_by_table["audit_events"]["details"]["data_type"] == "jsonb"

    for statement in (
        f"UPDATE audit_events SET action = 'changed' WHERE id = '{audit_id}'",
        f"DELETE FROM audit_events WHERE id = '{audit_id}'",
    ):
        with pytest.raises(asyncpg.PostgresError, match="append-only") as rejected:
            asyncio.run(_execute(plain_url, statement))
        assert rejected.value.sqlstate == "55000"

    command.downgrade(config, "base")

    rows = asyncio.run(
        _fetch(
            plain_url,
            "SELECT tablename FROM pg_catalog.pg_tables "
            "WHERE schemaname = 'public' ORDER BY tablename",
        )
    )
    assert APPLICATION_TABLES.isdisjoint(row["tablename"] for row in rows)
