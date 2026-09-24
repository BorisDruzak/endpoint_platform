"""Shared UUID identifiers must round-trip on both database dialects."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import create_engine, select
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.orm import Session
from sqlalchemy.schema import CreateTable

from endpoint_server.db.models import ModuleDefinition, ModuleVersion


def test_ownership_uuid_uses_text_storage_in_sqlite() -> None:
    # SQLite gives a UUID column NUMERIC affinity; this valid UUID is numeric
    # notation and would otherwise be converted to an integer on insertion.
    identifier = UUID("61324605-7369-4523-e000-000000000000")
    engine = create_engine("sqlite+pysqlite:///:memory:")
    ModuleDefinition.metadata.create_all(
        engine, tables=(ModuleDefinition.__table__, ModuleVersion.__table__)
    )

    with Session(engine) as session:
        session.add(
            ModuleDefinition(
                id=identifier,
                module_key="uuid-storage-check",
                display_name="UUID storage check",
                created_at=datetime.now(UTC),
            )
        )
        session.flush()
        session.add(
            ModuleVersion(
                id=identifier,
                module_definition_id=identifier,
                version="1.0.0",
                recipe={},
                state="draft",
                created_at=datetime.now(UTC),
            )
        )
        session.commit()

    with engine.connect() as connection:
        assert connection.exec_driver_sql(
            "SELECT typeof(id) FROM module_definitions"
        ).scalar_one() == "text"
        assert connection.exec_driver_sql(
            "SELECT typeof(module_definition_id) FROM module_versions"
        ).scalar_one() == "text"
    with Session(engine) as session:
        version = session.scalar(
            select(ModuleVersion).where(ModuleVersion.id == identifier)
        )
        assert version is not None
        assert version.id == identifier


def test_ownership_uuid_remains_native_on_postgresql() -> None:
    for table in (ModuleDefinition.__table__, ModuleVersion.__table__):
        postgres_ddl = str(CreateTable(table).compile(dialect=postgresql.dialect()))
        sqlite_ddl = str(CreateTable(table).compile(dialect=sqlite.dialect()))
        assert "id UUID NOT NULL" in postgres_ddl
        assert "id CHAR(32) NOT NULL" in sqlite_ddl
