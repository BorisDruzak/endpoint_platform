from __future__ import annotations

from alembic.config import Config

from endpoint_server.db.migrations.runtime_config import configure_database_url


def test_runtime_database_url_overrides_alembic_ini_default() -> None:
    """The migration unit must use its protected service environment URL."""
    config = Config("alembic.ini")
    deployment_url = (
        "postgresql+asyncpg://endpoint_platform:deployment-secret@127.0.0.1:5432/"
        "endpoint_platform"
    )

    configured_url = configure_database_url(
        config,
        {"DATABASE_URL": deployment_url},
    )

    assert configured_url == deployment_url
    assert config.get_main_option("sqlalchemy.url") == deployment_url
