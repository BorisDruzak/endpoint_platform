"""Assigned and applied policy owns whether continuous activity may enter Context."""

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from endpoint_contracts.activity import ActivityObservationV1
from endpoint_contracts.endpoint_policy import EndpointPolicyV1, policy_digest
from endpoint_server.activity.ingestion import ingest_gateway_activity
from endpoint_server.context.models import ContextCollection, ContextCurrent, ContextSnapshot
from endpoint_server.context.service import ContextValidationError
from endpoint_server.db.models import Device
from endpoint_server.policy.models import PolicyAssignment, PolicyDefinition, PolicyDeviceState, PolicyVersion
from tests.contracts.test_endpoint_policy_v1 import _policy


@pytest.mark.asyncio
async def test_activity_requires_current_applied_enabled_policy() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    tables = (Device.__table__, ContextCollection.__table__, ContextSnapshot.__table__,
              ContextCurrent.__table__, PolicyDefinition.__table__, PolicyVersion.__table__,
              PolicyAssignment.__table__, PolicyDeviceState.__table__)
    async with engine.begin() as connection:
        await connection.run_sync(lambda sync: Device.metadata.create_all(sync, tables=tables))
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    device_id, actor_id, version_id, definition_id = (uuid4() for _ in range(4))
    policy = EndpointPolicyV1.model_validate(_policy())
    now = datetime.now(UTC)
    observation = ActivityObservationV1(
        schema_version="activity_observation_v1", observation_id=uuid4(),
        observed_at=now, user_login="user", session_state="ACTIVE", idle_seconds=5,
    )
    try:
        async with sessions() as session:
            session.add_all((
                Device(id=device_id, device_identifier="activity-policy-gate"),
                PolicyDefinition(id=definition_id, name="Activity"),
            ))
            await session.flush()
            session.add(PolicyVersion(
                id=version_id, definition_id=definition_id, version=1,
                digest=policy_digest(policy), document=policy.model_dump(mode="json"),
                created_by=actor_id,
            ))
            await session.flush()
            session.add_all((
                PolicyAssignment(scope="device", device_id=device_id,
                                 policy_version_id=version_id, assigned_by=actor_id, assigned_at=now),
                PolicyDeviceState(device_id=device_id, policy_version_id=version_id,
                                  policy_digest=policy_digest(policy), status="PENDING"),
            ))
            await session.flush()
            with pytest.raises(ContextValidationError):
                await ingest_gateway_activity(session, device_id, observation)
            state = await session.scalar(select(PolicyDeviceState).where(PolicyDeviceState.device_id == device_id))
            state.status = "APPLIED"
            assert await ingest_gateway_activity(session, device_id, observation) is not None
            state.policy_digest = "0" * 64
            with pytest.raises(ContextValidationError):
                await ingest_gateway_activity(session, device_id, observation)
    finally:
        await engine.dispose()
