"""SecurityEvent replay is idempotent and ACK follows a caller-owned commit."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from endpoint_contracts.endpoint_policy import EndpointPolicyV1, policy_digest
from endpoint_contracts.gateway_ws import AgentHelloV1, EndpointPolicyAckV1
from endpoint_contracts.security_events import AgentSecurityEventBatchV1
from endpoint_server.db.base import Base
from endpoint_server.db.models import Device
from endpoint_server.policy.models import (
    PolicyApplication,
    PolicyAssignment,
    PolicyDefinition,
    PolicyDeviceState,
    PolicyVersion,
)
from endpoint_server.policy.delivery import prepare_policy_delivery, record_policy_ack
from endpoint_server.policy.service import assign_default_policy, create_policy_version
from endpoint_server.security.ingestion import (
    SecurityEventRejected,
    commit_and_ack_security_events,
    ingest_gateway_security_events,
)
from endpoint_server.security.models import SecurityEvent
from tests.contracts.test_endpoint_policy_v1 import POLICY_ID, _policy


NOW = datetime(2026, 9, 25, 12, tzinfo=UTC)


def _batch(
    *, event_identifier=None, policy_id=POLICY_ID, metadata=None, occurred_at=NOW
):
    return AgentSecurityEventBatchV1.model_validate(
        {
            "schema_version": "agent_security_event_batch_v1",
            "batch_id": uuid4(),
            "events": [
                {
                    "schema_version": "security_event_v1",
                    "event_identifier": event_identifier or uuid4(),
                    "event_type": "USB_DEVICE_CONNECTED",
                    "channel": "USB",
                    "severity": "INFO",
                    "occurred_at": occurred_at,
                    "user_login": "ivanova.aa",
                    "policy_id": policy_id,
                    "policy_version": 1,
                    "safe_metadata": metadata or {"removable": True},
                }
            ],
        }
    )


@pytest.fixture
async def provisioned():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    tables = [
        Device.__table__,
        PolicyDefinition.__table__,
        PolicyVersion.__table__,
        PolicyAssignment.__table__,
        PolicyDeviceState.__table__,
        PolicyApplication.__table__,
        SecurityEvent.__table__,
    ]
    async with engine.begin() as connection:
        await connection.run_sync(
            lambda sync: Base.metadata.create_all(sync, tables=tables)
        )
    factory = async_sessionmaker(engine, expire_on_commit=False)
    device_id, version_id = uuid4(), uuid4()
    policy = EndpointPolicyV1.model_validate(_policy())
    async with factory() as session:
        session.add_all(
            [
                Device(id=device_id, device_identifier="security-ingest"),
                PolicyDefinition(id=POLICY_ID, name="Security Test"),
                PolicyVersion(
                    id=version_id,
                    definition_id=POLICY_ID,
                    version=1,
                    digest=policy_digest(policy),
                    document=policy.model_dump(mode="json"),
                    created_by=uuid4(),
                ),
                PolicyAssignment(
                    scope="default",
                    policy_version_id=version_id,
                    assigned_by=uuid4(),
                    assigned_at=NOW,
                ),
                PolicyDeviceState(
                    device_id=device_id,
                    policy_version_id=version_id,
                    policy_digest=policy_digest(policy),
                    status="APPLIED",
                ),
                PolicyApplication(
                    device_id=device_id,
                    policy_version_id=version_id,
                    policy_digest=policy_digest(policy),
                    applied_at=NOW - timedelta(hours=1),
                    acknowledged_at=NOW - timedelta(hours=1),
                ),
            ]
        )
        await session.commit()
    yield factory, device_id
    await engine.dispose()


@pytest.mark.asyncio
async def test_replay_creates_one_event_and_acks_after_commit(provisioned) -> None:
    factory, device_id = provisioned
    event_id = uuid4()
    batch = _batch(event_identifier=event_id)
    async with factory() as session:
        ack = await ingest_gateway_security_events(
            session, device_id, batch, received_at=NOW
        )
        assert ack.event_identifiers == [event_id]
        await session.commit()
    async with factory() as session:
        replay = await ingest_gateway_security_events(
            session,
            device_id,
            _batch(event_identifier=event_id),
            received_at=NOW + timedelta(seconds=1),
        )
        await session.commit()
        assert replay.event_identifiers == [event_id]
        rows = (await session.scalars(select(SecurityEvent))).all()
        assert len(rows) == 1
        assert rows[0].expires_at.replace(tzinfo=UTC) == NOW + timedelta(days=30)


@pytest.mark.asyncio
async def test_same_identifier_with_changed_metadata_is_rejected(provisioned) -> None:
    factory, device_id = provisioned
    event_id = uuid4()
    async with factory() as session:
        await ingest_gateway_security_events(
            session, device_id, _batch(event_identifier=event_id), received_at=NOW
        )
        await session.commit()
    async with factory() as session:
        with pytest.raises(SecurityEventRejected):
            await ingest_gateway_security_events(
                session,
                device_id,
                _batch(event_identifier=event_id, metadata={"removable": False}),
                received_at=NOW,
            )


@pytest.mark.asyncio
async def test_missing_application_wrong_provenance_and_old_event_are_rejected(
    provisioned,
) -> None:
    factory, device_id = provisioned
    async with factory() as session:
        for batch in (
            _batch(policy_id=uuid4()),
            _batch(occurred_at=NOW - timedelta(hours=24, seconds=1)),
        ):
            with pytest.raises(SecurityEventRejected):
                await ingest_gateway_security_events(
                    session, device_id, batch, received_at=NOW
                )
        state = await session.scalar(
            select(PolicyDeviceState).where(PolicyDeviceState.device_id == device_id)
        )
        state.status = "STALE"
        await session.flush()
        await session.execute(
            delete(PolicyApplication).where(PolicyApplication.device_id == device_id)
        )
        with pytest.raises(SecurityEventRejected):
            await ingest_gateway_security_events(
                session, device_id, _batch(), received_at=NOW
            )
        assert (await session.scalars(select(SecurityEvent))).all() == []


@pytest.mark.asyncio
async def test_ack_is_sent_after_event_is_visible_in_committed_transaction(
    provisioned,
) -> None:
    factory, device_id = provisioned
    seen = []

    async def send(envelope):
        async with factory() as observer:
            rows = (await observer.scalars(select(SecurityEvent))).all()
            seen.append((envelope.kind, envelope.sequence, len(rows)))

    await commit_and_ack_security_events(
        factory, device_id, _batch(), sequence=9, send=send, received_at=NOW
    )
    assert seen == [("security_event_ack", 9, 1)]


@pytest.mark.asyncio
async def test_offline_event_from_prior_applied_policy_survives_rotation(provisioned) -> None:
    factory, device_id = provisioned
    first_applied = NOW - timedelta(minutes=30)
    async with factory() as session:
        first = await session.scalar(select(PolicyVersion).where(PolicyVersion.version == 1))
        assert first is not None
        await record_policy_ack(session, device_id, EndpointPolicyAckV1(
            schema_version="endpoint_policy_ack_v1", policy_id=POLICY_ID,
            policy_version=1, policy_digest=first.digest,
            received_at=first_applied, applied_at=first_applied, status="APPLIED",
        ))
        await session.commit()

    second_applied = NOW + timedelta(minutes=1)
    async with factory() as session:
        second = await create_policy_version(
            session, POLICY_ID, _policy(policy_version=2), actor_id=uuid4(),
        )
        await assign_default_policy(session, second.id, actor_id=uuid4())
        hello = AgentHelloV1.model_validate({
            "schema_version": "agent_hello_v1", "device_id": device_id,
            "agent_instance_id": uuid4(), "agent_version": "3.2.70",
            "launcher_version": "3.2.70", "platform": "windows_amd64",
            "boot_id": "offline-replay", "capabilities": [],
            "last_result_sequence": 0, "last_policy_revision": 0,
            "protocol_features": ["endpoint.policy.v1", "endpoint.security-events.v1"],
        })
        delivery = await prepare_policy_delivery(session, hello)
        assert delivery is not None
        await record_policy_ack(session, device_id, EndpointPolicyAckV1(
            schema_version="endpoint_policy_ack_v1", policy_id=POLICY_ID,
            policy_version=2, policy_digest=second.digest,
            received_at=second_applied, applied_at=second_applied, status="APPLIED",
        ))
        await session.commit()

    async with factory() as session:
        old_batch = _batch(occurred_at=NOW)
        new_event = old_batch.events[0].model_copy(update={
            "event_identifier": uuid4(),
            "occurred_at": NOW + timedelta(minutes=2),
            "policy_version": 2,
        })
        mixed_batch = AgentSecurityEventBatchV1(
            schema_version="agent_security_event_batch_v1",
            batch_id=uuid4(),
            events=[old_batch.events[0], new_event],
        )
        ack = await ingest_gateway_security_events(
            session, device_id, mixed_batch, received_at=NOW + timedelta(minutes=2),
        )
        assert ack.event_identifiers == [
            old_batch.events[0].event_identifier, new_event.event_identifier,
        ]
        await session.commit()
        assert {
            event.policy_version for event in (await session.scalars(select(SecurityEvent))).all()
        } == {1, 2}
    async with factory() as session:
        with pytest.raises(SecurityEventRejected):
            await ingest_gateway_security_events(
                session, device_id,
                _batch(occurred_at=NOW + timedelta(minutes=2)),
                received_at=NOW + timedelta(minutes=3),
            )
