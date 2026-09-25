"""Sensor health is current policy-scoped evidence, not Agent compliance."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from endpoint_contracts.endpoint_policy import EndpointPolicyV1, policy_digest
from endpoint_contracts.sensor_health import PolicySensorHealthReportV1
from endpoint_server.db.base import Base
import endpoint_server.db.models  # noqa: F401 - register FK targets
from endpoint_server.policy.models import (
    PolicyAssignment, PolicyDefinition, PolicyDeviceState, PolicySensorHealthCurrent,
    PolicyVersion,
)
from endpoint_server.policy.sensor_health import (
    SensorHealthRejected, ingest_sensor_health, load_sensor_health,
)
from tests.contracts.test_endpoint_policy_v1 import POLICY_ID, _policy


NOW = datetime(2026, 9, 25, 12, tzinfo=UTC)


@pytest.fixture
async def sensor_sessions():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(lambda sync: Base.metadata.create_all(sync, tables=[
            PolicyDefinition.__table__, PolicyVersion.__table__,
            PolicyAssignment.__table__, PolicyDeviceState.__table__,
            PolicySensorHealthCurrent.__table__,
        ]))
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    device_id, version_id = uuid4(), uuid4()
    document = _policy()
    digest = policy_digest(EndpointPolicyV1.model_validate(document))
    async with sessions() as session:
        session.add_all([
            PolicyDefinition(id=POLICY_ID, name="Sensor Default"),
            PolicyVersion(
                id=version_id, definition_id=POLICY_ID, version=1,
                digest=digest, document=document, created_by=uuid4(),
            ),
            PolicyAssignment(
                scope="default", policy_version_id=version_id,
                assigned_by=uuid4(), assigned_at=NOW,
            ),
            PolicyDeviceState(
                device_id=device_id, policy_version_id=version_id,
                policy_digest=digest, status="APPLIED", received_at=NOW,
                applied_at=NOW, acknowledged_at=NOW,
            ),
        ])
        await session.commit()
    yield sessions, device_id
    await engine.dispose()


def _report(*, observed_at: datetime = NOW) -> PolicySensorHealthReportV1:
    return PolicySensorHealthReportV1(
        schema_version="policy_sensor_health_report_v1",
        observation_id=uuid4(), policy_id=POLICY_ID, policy_version=1,
        observed_at=observed_at, activity_listener_state="READY",
        user_sensor_last_seen_at=observed_at - timedelta(seconds=15),
        security_spool_state="READY", usb_source_state="READY",
        print_source_state="UNAVAILABLE",
    )


@pytest.mark.asyncio
async def test_current_health_persists_and_replay_does_not_regress(sensor_sessions) -> None:
    sessions, device_id = sensor_sessions
    first = _report()
    async with sessions() as session:
        await ingest_sensor_health(session, device_id, first, received_at=NOW)
        await session.commit()
    older = _report(observed_at=NOW - timedelta(minutes=1))
    async with sessions() as session:
        await ingest_sensor_health(session, device_id, older, received_at=NOW)
        await ingest_sensor_health(session, device_id, first, received_at=NOW)
        await session.commit()
    async with sessions() as session:
        loaded = await load_sensor_health(session, device_id)
        rows = (await session.scalars(select(PolicySensorHealthCurrent))).all()
    assert len(rows) == 1
    assert loaded is not None
    assert loaded.observation_id == first.observation_id
    assert loaded.user_sensor_last_seen_at == first.user_sensor_last_seen_at
    assert loaded.print_source_state == "UNAVAILABLE"


@pytest.mark.asyncio
async def test_health_rejects_timestamp_conflict_and_wrong_policy(sensor_sessions) -> None:
    sessions, device_id = sensor_sessions
    first = _report()
    async with sessions() as session:
        await ingest_sensor_health(session, device_id, first, received_at=NOW)
        await session.commit()
    async with sessions() as session:
        with pytest.raises(SensorHealthRejected, match="timestamp"):
            await ingest_sensor_health(session, device_id, _report(), received_at=NOW)
        await session.rollback()
    wrong = first.model_copy(update={"policy_version": 2})
    async with sessions() as session:
        with pytest.raises(SensorHealthRejected, match="policy"):
            await ingest_sensor_health(session, device_id, wrong, received_at=NOW)
        await session.rollback()


@pytest.mark.asyncio
async def test_health_rejects_future_and_old_observations(sensor_sessions) -> None:
    sessions, device_id = sensor_sessions
    for observed in (NOW + timedelta(minutes=6), NOW - timedelta(hours=25)):
        async with sessions() as session:
            with pytest.raises(SensorHealthRejected, match="observation"):
                await ingest_sensor_health(
                    session, device_id, _report(observed_at=observed),
                    received_at=NOW,
                )
            await session.rollback()


@pytest.mark.asyncio
async def test_policy_rotation_replaces_old_health_even_if_clock_was_ahead(sensor_sessions) -> None:
    sessions, device_id = sensor_sessions
    first = _report(observed_at=NOW + timedelta(minutes=4))
    async with sessions() as session:
        await ingest_sensor_health(session, device_id, first, received_at=NOW)
        await session.commit()

    document = _policy()
    document["policy_version"] = 2
    digest = policy_digest(EndpointPolicyV1.model_validate(document))
    next_version_id = uuid4()
    async with sessions() as session:
        session.add(PolicyVersion(
            id=next_version_id, definition_id=POLICY_ID, version=2,
            digest=digest, document=document, created_by=uuid4(),
        ))
        assignment = await session.scalar(select(PolicyAssignment).where(
            PolicyAssignment.scope == "default",
        ))
        assignment.policy_version_id = next_version_id
        state = await session.scalar(select(PolicyDeviceState).where(
            PolicyDeviceState.device_id == device_id,
        ))
        state.policy_version_id = next_version_id
        state.policy_digest = digest
        await session.commit()

    second = _report().model_copy(update={
        "policy_version": 2,
        "user_sensor_last_seen_at": None,
    })
    async with sessions() as session:
        await ingest_sensor_health(session, device_id, second, received_at=NOW)
        await session.commit()
    async with sessions() as session:
        loaded = await load_sensor_health(session, device_id)
    assert loaded is not None
    assert loaded.policy_version == 2
    assert loaded.observation_id == second.observation_id
    assert loaded.user_sensor_last_seen_at is None

    async with sessions() as session:
        with pytest.raises(SensorHealthRejected, match="policy"):
            await ingest_sensor_health(session, device_id, first, received_at=NOW)
        await session.rollback()
