"""Opt-in PostgreSQL concurrency checks for enrollment campaign reservations."""

from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from uuid import uuid4

import asyncpg
import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from sqlalchemy import select
from sqlalchemy.engine import make_url

from endpoint_server.db.models import AuditEvent, EnrollmentCampaign
from endpoint_server.db.session import AsyncSessionProvider
from endpoint_server.enrollment.campaigns import (
    EnrollmentDenied,
    issue_campaign,
    reserve_campaign_use,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
PEPPER = b"postgres-concurrency-device-pepper"


async def _execute(database_url: str, statement: str) -> None:
    connection = await asyncpg.connect(database_url)
    try:
        await connection.execute(statement)
    finally:
        await connection.close()


@pytest.fixture(scope="module")
def enrollment_database_url() -> Iterator[str]:
    admin_url = os.environ.get("ENDPOINT_TEST_POSTGRES_URL")
    if not admin_url:
        pytest.skip(
            "set ENDPOINT_TEST_POSTGRES_URL to a disposable local PostgreSQL server"
        )
    parsed = make_url(admin_url)
    if parsed.host not in {"127.0.0.1", "localhost", "::1"}:
        pytest.fail("enrollment tests may only use a loopback PostgreSQL server")
    database_name = f"endpoint_enrollment_{uuid4().hex}"
    plain_admin_url = parsed.set(drivername="postgresql").render_as_string(
        hide_password=False
    )
    asyncio.run(_execute(plain_admin_url, f'CREATE DATABASE "{database_name}"'))
    database_url = parsed.set(
        drivername="postgresql+asyncpg", database=database_name
    ).render_as_string(hide_password=False)
    config = Config(REPOSITORY_ROOT / "alembic.ini")
    config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    command.upgrade(config, "head")
    try:
        yield database_url
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
async def enrollment_provider(
    enrollment_database_url: str,
) -> AsyncIterator[AsyncSessionProvider]:
    provider = AsyncSessionProvider(enrollment_database_url)
    try:
        yield provider
    finally:
        await provider.close()


@pytest.mark.asyncio
async def test_concurrent_final_campaign_use_is_reserved_exactly_once(
    enrollment_provider: AsyncSessionProvider,
) -> None:
    """Removing the row lock would let two transactions consume the final use."""
    from datetime import UTC, datetime, timedelta
    from ipaddress import ip_address

    now = datetime.now(UTC)
    issued = issue_campaign(
        PEPPER,
        expires_at=now + timedelta(hours=1),
        max_uses=1,
        allowed_cidrs=("192.168.100.0/24",),
        target_platform="linux",
        policy={},
        now=now,
    )
    async with enrollment_provider() as session:
        session.add(issued.record)
        await session.commit()

    async def reserve(request_id: str) -> bool:
        async with enrollment_provider() as session:
            try:
                await reserve_campaign_use(
                    session,
                    issued.token,
                    PEPPER,
                    source_address=ip_address("192.168.100.20"),
                    platform="linux",
                    actor_kind="agent",
                    actor_identifier=None,
                    request_id=request_id,
                    now=now,
                )
                await session.commit()
                return True
            except EnrollmentDenied:
                await session.rollback()
                return False

    outcomes = await asyncio.gather(reserve("race-a"), reserve("race-b"))
    assert sorted(outcomes) == [False, True]

    async with enrollment_provider() as session:
        campaign = await session.scalar(
            select(EnrollmentCampaign).where(EnrollmentCampaign.id == issued.record.id)
        )
        audits = (
            await session.scalars(
                select(AuditEvent).where(
                    AuditEvent.object_identifier == str(issued.record.id),
                    AuditEvent.action == "enrollment_campaign.use_reserved",
                )
            )
        ).all()
    assert campaign is not None
    assert campaign.use_count == 1
    assert len(audits) == 1
