"""Opt-in PostgreSQL concurrency checks for enrollment campaign reservations."""

from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator, Iterator
from ipaddress import ip_network
from pathlib import Path
from uuid import UUID, uuid4

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
from endpoint_server.enrollment.delivery import cleanup_expired_retry_envelopes
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
    unrelated_agent_audit = AuditEvent(
        actor_kind="agent",
        actor_identifier=None,
        action="enrollment_campaign.use_reserved",
        object_kind="enrollment_campaign",
        object_identifier=str(uuid4()),
        request_id="preceding-postgres-enrollment-test",
        details={},
        created_at=now,
    )
    async with enrollment_provider() as session:
        session.add_all((issued.record, unrelated_agent_audit))
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
        "schema_version": "agent_enrollment_request_v1",
        "platform": "linux",
        "hardware_fingerprint": "sha256:postgres-agent",
        "installation_id": "postgres-installation",
        "delivery_nonce": "P" * 43,
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
            "schema_version": "enrollment_delivery_proof_v1",
            "enrollment_receipt": delivery["enrollment_receipt"],
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
    assert duplicate.status_code == 200
    assert duplicate.json() == delivery
    assert retried.status_code == 200
    assert retried.json() == delivery
    assert acknowledged.status_code == 204
    assert replay.status_code == 403
    assert rotated.status_code == 201
    assert activated.status_code == 204
    assert retired_old_token.status_code == 401

    device_id = UUID(delivery["device_id"])
    async with enrollment_provider() as session:
        device = await session.get(Device, device_id)
        assert device is not None
        credentials = (
            await session.scalars(
                select(DeviceCredential).where(DeviceCredential.device_id == device_id)
            )
        ).all()
        assert len(credentials) == 1
        credential = credentials[0]
        campaign = await session.get(EnrollmentCampaign, issued.record.id)
        envelopes = (
            await session.scalars(
                select(EnrollmentRetryEnvelope).where(
                    EnrollmentRetryEnvelope.device_credential_id == credential.id
                )
            )
        ).all()
        audit_facts = [
            (event.action, event.object_identifier)
            for event in (
                await session.scalars(
                    select(AuditEvent).where(
                        AuditEvent.actor_kind == "agent",
                        AuditEvent.object_identifier.in_(
                            (
                                str(issued.record.id),
                                str(device.id),
                                str(credential.id),
                            )
                        ),
                    )
                )
            ).all()
        ]
    assert campaign is not None
    assert campaign.use_count == 1
    assert envelopes == []
    assert sorted(audit_facts) == sorted(
        [
            ("enrollment_campaign.use_reserved", str(issued.record.id)),
            ("device.enrolled", str(device.id)),
            ("enrollment.delivery_acknowledged", str(device.id)),
            ("device_credential.rotation_started", str(credential.id)),
            ("device_credential.rotation_activated", str(credential.id)),
        ]
    )


@pytest.mark.asyncio
async def test_cleanup_skips_recovery_locked_envelope_then_cleans_after_release(
    enrollment_provider: AsyncSessionProvider,
) -> None:
    """Cleanup must not block or delete a row while recovery owns its lock."""
    from datetime import UTC, datetime, timedelta

    expired_at = datetime.now(UTC) - timedelta(minutes=1)
    device = Device(
        id=uuid4(),
        device_identifier=f"dev_{uuid4().hex}",
        display_name="Cleanup contention fixture",
        retired_at=None,
    )
    credential = DeviceCredential(
        id=uuid4(),
        device_id=device.id,
        credential_identifier=uuid4().hex,
        token_digest=uuid4().hex,
        pending_token_digest=None,
        rotation_overlap_expires_at=None,
        expires_at=None,
        revoked_at=None,
    )
    envelope = EnrollmentRetryEnvelope(
        id=uuid4(),
        device_credential_id=credential.id,
        receipt_digest=uuid4().hex,
        fingerprint_digest=uuid4().hex,
        encrypted_token=b"expired-ciphertext",
        encryption_nonce=b"012345678901",
        expires_at=expired_at,
    )
    async with enrollment_provider() as session:
        session.add_all((device, credential, envelope))
        await session.commit()

    async with enrollment_provider() as recovery_session:
        locked = await recovery_session.scalar(
            select(EnrollmentRetryEnvelope)
            .where(EnrollmentRetryEnvelope.id == envelope.id)
            .with_for_update()
        )
        assert locked is not None
        async with enrollment_provider() as cleanup_session:
            skipped = await cleanup_expired_retry_envelopes(
                cleanup_session,
                request_id="server_cleanup_locked",
                now=datetime.now(UTC),
            )
            await cleanup_session.commit()
        assert skipped == 0

    async with enrollment_provider() as cleanup_session:
        cleaned = await cleanup_expired_retry_envelopes(
            cleanup_session,
            request_id="server_cleanup_released",
            now=datetime.now(UTC),
        )
        await cleanup_session.commit()
    assert cleaned == 1

    async with enrollment_provider() as session:
        persisted = await session.get(EnrollmentRetryEnvelope, envelope.id)
        expiration_audits = (
            await session.scalars(
                select(AuditEvent).where(
                    AuditEvent.action == "enrollment.delivery_expired",
                    AuditEvent.object_identifier == str(envelope.id),
                )
            )
        ).all()
    assert persisted is None
    assert len(expiration_audits) == 1
