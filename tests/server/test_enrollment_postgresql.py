"""Opt-in PostgreSQL concurrency checks for enrollment campaign reservations."""

from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator, Iterator
from ipaddress import ip_network
from pathlib import Path
from uuid import uuid4

import asyncpg
import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.engine import make_url

from endpoint_server.config import Settings
from endpoint_server.db.models import (
    AuditEvent,
    Device,
    DeviceCredential,
    EnrollmentCampaign,
    EnrollmentClaim,
    EnrollmentRetryEnvelope,
)
from endpoint_server.db.session import AsyncSessionProvider
from endpoint_server.enrollment.campaigns import (
    EnrollmentDenied,
    consume_install_claim,
    issue_campaign,
    issue_install_claim,
    reserve_campaign_use,
)
from endpoint_server.main import create_app


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


@pytest.mark.asyncio
async def test_agent_enrollment_retry_ack_and_rotation_are_atomic_in_postgresql(
    enrollment_provider: AsyncSessionProvider,
) -> None:
    """Real SQL must preserve one identity, one quota use, and credential promotion."""
    from datetime import UTC, datetime, timedelta

    now = datetime.now(UTC)
    issued = issue_campaign(
        PEPPER,
        expires_at=now + timedelta(hours=1),
        max_uses=1,
        allowed_cidrs=("192.168.100.0/24",),
        target_platform="linux",
        policy={"policy_id": "postgres-e2e"},
        now=now,
    )
    async with enrollment_provider() as session:
        session.add(issued.record)
        await session.commit()

    app = create_app(
        Settings(
            database_url="postgresql+asyncpg://unused@localhost/unused",
            public_base_url="https://endpoint.sosnadmin.local",
            device_token_pepper=PEPPER,
            service_token_pepper=b"postgres-service-pepper",
            session_secret=b"postgres-enrollment-session-secret",
            allowed_agent_cidrs=(ip_network("192.168.100.0/24"),),
            allowed_admin_cidrs=(),
            artifact_root=Path("artifacts"),
        ),
        session_provider=enrollment_provider,
    )
    body = {
        "schema_version": "enrollment_request_v1",
        "platform": "linux",
        "hardware_fingerprint": "sha256:postgres-agent",
        "installation_id": "postgres-installation",
        "requested_at": now.isoformat(),
    }
    async with AsyncClient(
        transport=ASGITransport(
            app=app,
            client=("192.168.100.20", 43100),
        ),
        base_url="https://endpoint.sosnadmin.local",
    ) as client:
        enrolled = await client.post(
            "/agent/v1/enroll",
            headers={"Authorization": f"Bearer {issued.token}"},
            json=body,
        )
        duplicate = await client.post(
            "/agent/v1/enroll",
            headers={"Authorization": f"Bearer {issued.token}"},
            json=body,
        )
        delivery = enrolled.json()
        delivery_binding = {
            "receipt": delivery["enrollment_receipt"],
            "hardware_fingerprint": body["hardware_fingerprint"],
        }
        retried = await client.post(
            "/agent/v1/enroll/retry",
            json=delivery_binding,
        )
        acknowledged = await client.post(
            "/agent/v1/enroll/ack",
            json=delivery_binding,
        )
        replay = await client.post(
            "/agent/v1/enroll/retry",
            json=delivery_binding,
        )
        old_token = delivery["device_token"]
        rotated = await client.post(
            "/agent/v1/credentials/rotate",
            headers={"Authorization": f"Bearer {old_token}"},
        )
        pending_token = rotated.json()["device_token"]
        activated = await client.post(
            "/agent/v1/credentials/activate",
            headers={"Authorization": f"Bearer {pending_token}"},
        )
        retired_old_token = await client.post(
            "/agent/v1/credentials/rotate",
            headers={"Authorization": f"Bearer {old_token}"},
        )

    assert enrolled.status_code == 201
    assert duplicate.status_code == 409
    assert retried.status_code == 200
    assert retried.json() == delivery
    assert acknowledged.status_code == 204
    assert replay.status_code == 403
    assert rotated.status_code == 201
    assert activated.status_code == 204
    assert retired_old_token.status_code == 401

    async with enrollment_provider() as session:
        devices = (await session.scalars(select(Device))).all()
        credentials = (await session.scalars(select(DeviceCredential))).all()
        campaign = await session.get(EnrollmentCampaign, issued.record.id)
        envelopes = (await session.scalars(select(EnrollmentRetryEnvelope))).all()
        actions = [
            event.action
            for event in (
                await session.scalars(
                    select(AuditEvent).where(AuditEvent.actor_kind == "agent")
                )
            ).all()
        ]
    assert len(devices) == len(credentials) == 1
    assert campaign is not None
    assert campaign.use_count == 1
    assert envelopes == []
    assert sorted(actions) == sorted(
        [
            "enrollment_campaign.use_reserved",
            "device.enrolled",
            "enrollment.delivery_acknowledged",
            "device_credential.rotation_started",
            "device_credential.rotation_activated",
        ]
    )
