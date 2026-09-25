"""Only negotiating Windows Agents receive effective Endpoint Policy frames."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from endpoint_contracts.endpoint_policy import policy_digest
from endpoint_contracts.gateway_ws import AgentHelloV1, EndpointPolicyAckV1
from endpoint_server.db.base import Base
import endpoint_server.db.models  # noqa: F401 - register FK targets
from endpoint_server.policy.delivery import (
    PolicyAcknowledgementRejected,
    prepare_policy_delivery,
    record_policy_ack,
)
from endpoint_server.policy.models import (
    PolicyApplication, PolicyAssignment, PolicyDefinition, PolicyDeviceState, PolicyVersion,
)
from endpoint_server.policy.service import assign_default_policy, create_policy_version
from tests.contracts.test_endpoint_policy_v1 import POLICY_ID, _policy


@pytest.fixture
async def policy_sessions():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(lambda sync: Base.metadata.create_all(sync, tables=[
            PolicyDefinition.__table__, PolicyVersion.__table__,
            PolicyAssignment.__table__, PolicyDeviceState.__table__,
            PolicyApplication.__table__,
        ]))
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    async with sessions() as session:
        session.add(PolicyDefinition(id=POLICY_ID, name="Municipal Default"))
        await session.flush()
        version = await create_policy_version(session, POLICY_ID, _policy(), actor_id=uuid4())
        await assign_default_policy(session, version.id, actor_id=uuid4())
        await session.commit()
    yield sessions
    await engine.dispose()


def _hello(device_id: UUID, *, version: str = "3.2.68", features: list[str] | None = None) -> AgentHelloV1:
    return AgentHelloV1.model_validate({
        "schema_version": "agent_hello_v1", "device_id": str(device_id),
        "agent_instance_id": str(uuid4()), "agent_version": version,
        "launcher_version": version, "platform": "windows_amd64",
        "boot_id": "policy-delivery-test", "capabilities": [],
        "last_result_sequence": 0, "last_policy_revision": 0,
        "protocol_features": features or [],
    })


@pytest.mark.asyncio
async def test_old_agent_remains_connected_and_is_marked_unsupported(policy_sessions) -> None:
    device_id = uuid4()
    async with policy_sessions() as session:
        delivery = await prepare_policy_delivery(session, _hello(device_id, version="3.2.67"))
        await session.commit()
        state = await session.scalar(select(PolicyDeviceState).where(PolicyDeviceState.device_id == device_id))
    assert delivery is None
    assert state is not None and state.status == "UNSUPPORTED"


@pytest.mark.asyncio
async def test_advertised_agent_receives_digest_bound_policy_and_ack(policy_sessions) -> None:
    device_id = uuid4()
    hello = _hello(device_id, features=["endpoint.policy.v1"])
    async with policy_sessions() as session:
        delivery = await prepare_policy_delivery(session, hello)
        await session.commit()
    assert delivery is not None
    assert delivery.kind == "endpoint_policy_delivery"
    assert delivery.payload.policy.policy_id == POLICY_ID
    assert delivery.payload.policy_digest == policy_digest(delivery.payload.policy)

    now = datetime.now(UTC)
    ack = EndpointPolicyAckV1(
        schema_version="endpoint_policy_ack_v1", policy_id=POLICY_ID,
        policy_version=1, policy_digest=delivery.payload.policy_digest,
        received_at=now, applied_at=now, status="APPLIED",
    )
    async with policy_sessions() as session:
        state = await record_policy_ack(session, device_id, ack)
        await session.commit()
        applications = (await session.scalars(select(PolicyApplication))).all()
    assert state.status == "APPLIED"
    assert state.acknowledged_at is not None
    assert len(applications) == 1
    assert applications[0].policy_digest == delivery.payload.policy_digest


@pytest.mark.asyncio
async def test_ack_for_wrong_digest_cannot_change_applied_state(policy_sessions) -> None:
    device_id = uuid4()
    now = datetime.now(UTC)
    wrong_ack = EndpointPolicyAckV1(
        schema_version="endpoint_policy_ack_v1", policy_id=POLICY_ID,
        policy_version=1, policy_digest="0" * 64,
        received_at=now, applied_at=now, status="APPLIED",
    )
    async with policy_sessions() as session:
        with pytest.raises(PolicyAcknowledgementRejected):
            await record_policy_ack(session, device_id, wrong_ack)
        await session.rollback()
        assert await session.scalar(select(PolicyDeviceState).where(PolicyDeviceState.device_id == device_id)) is None


@pytest.mark.asyncio
async def test_assignment_change_before_ack_keeps_connection_and_marks_old_ack_stale(policy_sessions) -> None:
    device_id = uuid4()
    hello = _hello(device_id, features=["endpoint.policy.v1"])
    async with policy_sessions() as session:
        first_delivery = await prepare_policy_delivery(session, hello)
        await session.commit()
    assert first_delivery is not None

    async with policy_sessions() as session:
        second = await create_policy_version(
            session, POLICY_ID, _policy(policy_version=2), actor_id=uuid4(),
        )
        await assign_default_policy(session, second.id, actor_id=uuid4())
        await session.commit()

    now = datetime.now(UTC)
    old_ack = EndpointPolicyAckV1(
        schema_version="endpoint_policy_ack_v1", policy_id=POLICY_ID,
        policy_version=1, policy_digest=first_delivery.payload.policy_digest,
        received_at=now, applied_at=now, status="APPLIED",
    )
    async with policy_sessions() as session:
        state = await record_policy_ack(session, device_id, old_ack)
        assert state.status == "STALE"
        assert len((await session.scalars(select(PolicyApplication))).all()) == 1
        second_delivery = await prepare_policy_delivery(session, hello, only_if_changed=True)
        await session.commit()
    assert second_delivery is not None
    assert second_delivery.payload.policy.policy_version == 2
