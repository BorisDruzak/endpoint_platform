"""The new SecurityEvent table is created and removable as a separate ledger."""

from __future__ import annotations

import importlib

from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import create_engine, inspect


def test_security_event_migration_has_identity_retention_and_safe_columns(
    monkeypatch,
) -> None:
    migration = importlib.import_module(
        "endpoint_server.db.migrations.versions.0032_security_events"
    )
    assert migration.down_revision == "0031_browser_sensor_release"
    engine = create_engine("sqlite:///:memory:")
    with engine.begin() as connection:
        monkeypatch.setattr(
            migration,
            "op",
            Operations(MigrationContext.configure(connection)),
        )
        migration.upgrade()
        inspector = inspect(connection)
        names = {column["name"] for column in inspector.get_columns("security_events")}
        assert names == {
            "id",
            "event_identifier",
            "device_id",
            "event_type",
            "channel",
            "severity",
            "occurred_at",
            "received_at",
            "user_login",
            "policy_id",
            "policy_version",
            "safe_metadata",
            "created_at",
            "expires_at",
        }
        assert "raw_payload" not in names
        assert "ix_security_events_expires" in {
            item["name"] for item in inspector.get_indexes("security_events")
        }
        assert "uq_security_events_device_identifier" in {
            item["name"] for item in inspector.get_unique_constraints("security_events")
        }
        migration.downgrade()
        assert "security_events" not in inspect(connection).get_table_names()
    engine.dispose()
