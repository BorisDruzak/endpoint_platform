"""PostgreSQL concurrency coverage for Device Context snapshot retention."""

from __future__ import annotations

import asyncio
import os
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import asyncpg
import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import select, text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from endpoint_server.context.models import ContextCollection, ContextCurrent, ContextSnapshot
from endpoint_server.context.retention import retain_context_snapshots
from endpoint_server.db.models import Device


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 7, 29, 12, 0, tzinfo=UTC)


def _admin_database_url() -> str:
    url = os.environ.get("ENDPOINT_TEST_POSTGRES_URL")
    if not url:
        pytest.skip("set ENDPOINT_TEST_POSTGRES_URL to a disposable local PostgreSQL server")
    if make_url(url).host not in {"127.0.0.1", "localhost", "::1"}:
        pytest.fail("PostgreSQL retention tests may only use a loopback server")
    return url


async def _execute(database_url: str, statement: str) -> None:
    connection = await asyncpg.connect(database_url)
    try:
        await connection.execute(statement)
    finally:
        await connection.close()


@pytest.fixture
def postgresql_url() -> Iterator[str]:
    """Create an isolated migration-backed database for a real lock test."""
    admin_url = _admin_database_url()
    database_name = f"endpoint_retention_{uuid4().hex}"
    asyncio.run(_execute(admin_url, f'CREATE DATABASE "{database_name}"'))
    database_url = (
        make_url(admin_url)
        .set(drivername="postgresql+asyncpg", database=database_name)
        .render_as_string(hide_password=False)
    )
    config = Config(REPOSITORY_ROOT / "alembic.ini")
    config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    command.upgrade(config, "head")
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


async def _seed(session: AsyncSession) -> tuple[Device, ContextSnapshot, ContextSnapshot]:
    device = Device(id=uuid4(), device_identifier=f"retention-pg-{uuid4().hex}", display_name="ALT")
    session.add(device)
    await session.flush()
    snapshots: list[ContextSnapshot] = []
    for offset in (3, 2, 1, 0):
        collected_at = NOW - timedelta(days=offset)
        collection = ContextCollection(
            id=uuid4(),
            device_id=device.id,
            profile="baseline_v1",
            requested_by="seed",
            idempotency_key=f"seed-{uuid4().hex}",
            status="completed",
            requested_at=collected_at,
            completed_at=collected_at,
        )
        snapshot = ContextSnapshot(
            id=uuid4(),
            collection_id=collection.id,
            device_id=device.id,
            profile="baseline_v1",
            collected_at=collected_at,
            raw_payload={},
            normalized_projection={},
        )
        session.add_all((collection, snapshot))
        snapshots.append(snapshot)
    await session.flush()
    session.add(
        ContextCurrent(
            id=uuid4(),
            device_id=device.id,
            profile="baseline_v1",
            snapshot_id=snapshots[-1].id,
            updated_at=NOW,
        )
    )
    await session.flush()
    return device, snapshots[-2], snapshots[-1]


@pytest.mark.asyncio
async def test_retention_waits_for_the_same_postgresql_profile_lock(
    postgresql_url: str,
) -> None:
    """A held ingestion lock cannot turn current/previous into missing rows."""
    engine = create_async_engine(postgresql_url)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with factory.begin() as seed_session:
            device, previous, current = await _seed(seed_session)

        holder = factory()
        retention_session = factory()
        try:
            await holder.begin()
            await holder.execute(
                text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
                {"key": f"context.current:{device.id}:baseline_v1"},
            )
            task = asyncio.create_task(retain_context_snapshots(retention_session))
            waiting = False
            for _ in range(20):
                waiting = bool(await holder.scalar(text(
                    "SELECT EXISTS (SELECT 1 FROM pg_stat_activity "
                    "WHERE datname = current_database() "
                    "AND pid <> pg_backend_pid() "
                    "AND wait_event_type = 'Lock' "
                    "AND query LIKE 'SELECT pg_advisory_xact_lock%')"
                )))
                if waiting:
                    break
                await asyncio.sleep(0.01)
            assert waiting
            assert not task.done()

            await holder.commit()
            assert await asyncio.wait_for(task, timeout=2) == 2
            await retention_session.commit()
        finally:
            if holder.in_transaction():
                await holder.rollback()
            await holder.close()
            await retention_session.close()

        async with factory() as verification_session:
            remaining = set(await verification_session.scalars(select(ContextSnapshot.id)))
        assert {previous.id, current.id} <= remaining
    finally:
        await engine.dispose()
