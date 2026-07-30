"""Runtime configuration shared by online and offline Alembic migrations."""

from __future__ import annotations

from collections.abc import Mapping

from alembic.config import Config


def configure_database_url(config: Config, environment: Mapping[str, str]) -> str:
    """Prefer the deployment database URL while preserving local Alembic defaults."""
    database_url = environment.get("DATABASE_URL", "").strip()
    if not database_url:
        database_url = config.get_main_option("sqlalchemy.url").strip()
    if not database_url:
        raise ValueError("Alembic database URL is required")
    config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    return database_url
