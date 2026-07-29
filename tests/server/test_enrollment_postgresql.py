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

from endpoint_server.db.models import AuditEvent, EnrollmentCampaign, EnrollmentClaim
from endpoint_server.db.session import AsyncSessionProvider
from endpoint_server.enrollment.campaigns import (
    EnrollmentDenied,
    consume_install_claim,
    issue_campaign,
    issue_install_claim,
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


@pytest.mark.asyncio
async def test_concurrent_same_claim_is_consumed_exactly_once(
    enrollment_provider: AsyncSessionProvider,
) -> None:
    """Two transactions presenting one claim must not both consume it."""
    from datetime import UTC, datetime, timedelta
    from ipaddress import ip_address

    now = datetime.now(UTC)
    campaign = issue_campaign(
        PEPPER,
        expires_at=now + timedelta(hours=1),
        max_uses=2,
        allowed_cidrs=("192.168.100.0/24",),
        target_platform="linux",
        policy={},
        now=now,
    ).record
    claim = issue_install_claim(
        campaign,
        PEPPER,
        installation_session="same-claim-session",
        hardware_fingerprint="sha256:same-claim",
        expires_at=now + timedelta(minutes=10),
        now=now,
    )
    async with enrollment_provider() as session:
        session.add_all((campaign, claim.record))
        await session.commit()

    async def consume(request_id: str) -> bool:
        async with enrollment_provider() as session:
            try:
                await consume_install_claim(
                    session,
                    claim.token,
                    PEPPER,
                    installation_session="same-claim-session",
                    hardware_fingerprint="sha256:same-claim",
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

    assert sorted(await asyncio.gather(consume("same-a"), consume("same-b"))) == [
        False,
        True,
    ]
    async with enrollment_provider() as session:
        persisted_campaign = await session.get(EnrollmentCampaign, campaign.id)
        persisted_claim = await session.get(EnrollmentClaim, claim.record.id)
        audits = (
            await session.scalars(
                select(AuditEvent).where(
                    AuditEvent.object_identifier == str(claim.record.id),
                    AuditEvent.action == "enrollment_claim.consumed",
                )
            )
        ).all()
    assert persisted_campaign is not None
    assert persisted_campaign.use_count == 1
    assert persisted_claim is not None
    assert persisted_claim.claimed_at is not None
    assert len(audits) == 1


@pytest.mark.asyncio
async def test_different_claims_compete_for_final_campaign_quota(
    enrollment_provider: AsyncSessionProvider,
) -> None:
    """Claim locks alone must not let different claims exceed campaign quota."""
    from datetime import UTC, datetime, timedelta
    from ipaddress import ip_address

    now = datetime.now(UTC)
    campaign = issue_campaign(
        PEPPER,
        expires_at=now + timedelta(hours=1),
        max_uses=1,
        allowed_cidrs=("192.168.100.0/24",),
        target_platform="linux",
        policy={},
        now=now,
    ).record
    claims = [
        issue_install_claim(
            campaign,
            PEPPER,
            installation_session=f"quota-session-{suffix}",
            hardware_fingerprint=f"sha256:quota-{suffix}",
            expires_at=now + timedelta(minutes=10),
            now=now,
        )
        for suffix in ("a", "b")
    ]
    async with enrollment_provider() as session:
        session.add_all((campaign, *(issued.record for issued in claims)))
        await session.commit()

    async def consume(index: int) -> bool:
        issued = claims[index]
        suffix = ("a", "b")[index]
        async with enrollment_provider() as session:
            try:
                await consume_install_claim(
                    session,
                    issued.token,
                    PEPPER,
                    installation_session=f"quota-session-{suffix}",
                    hardware_fingerprint=f"sha256:quota-{suffix}",
                    source_address=ip_address("192.168.100.20"),
                    platform="linux",
                    actor_kind="agent",
                    actor_identifier=None,
                    request_id=f"quota-{suffix}",
                    now=now,
                )
                await session.commit()
                return True
            except EnrollmentDenied:
                await session.rollback()
                return False

    assert sorted(await asyncio.gather(consume(0), consume(1))) == [False, True]
    async with enrollment_provider() as session:
        persisted_campaign = await session.get(EnrollmentCampaign, campaign.id)
        claimed_count = len(
            (
                await session.scalars(
                    select(EnrollmentClaim).where(
                        EnrollmentClaim.campaign_id == campaign.id,
                        EnrollmentClaim.claimed_at.is_not(None),
                    )
                )
            ).all()
        )
    assert persisted_campaign is not None
    assert persisted_campaign.use_count == 1
    assert claimed_count == 1
