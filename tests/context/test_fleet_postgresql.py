"""Real PostgreSQL acceptance of the fleet window/current projection."""
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
import pytest

from tests.context.test_retention_postgresql import postgresql_url  # noqa: F401
from tests.context.test_service_api import (
    test_fleet_summary_keeps_devices_without_context_and_pages_exactly as _presence,
    test_fleet_inventory_is_bounded_fresh_and_bulk as _inventory,
)


@pytest.mark.asyncio
@pytest.mark.parametrize("scenario", ["presence", "inventory"])
async def test_fleet_postgresql_presence_and_current(postgresql_url, monkeypatch, scenario):
    engine = create_async_engine(postgresql_url)
    provider = async_sessionmaker(engine, expire_on_commit=False)
    try:
        if scenario == "presence":
            await _presence(provider, monkeypatch)
        else:
            await _inventory(provider, monkeypatch, False)
    finally:
        await engine.dispose()
