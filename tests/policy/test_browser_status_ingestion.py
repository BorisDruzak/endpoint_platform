"""Gateway browser reports follow the effective, acknowledged policy."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from endpoint_contracts.browser_status import BrowserStatusReportV1
from endpoint_contracts.endpoint_policy import policy_digest
from endpoint_server.db.base import Base
import endpoint_server.db.models  # noqa: F401 - register FK targets
from endpoint_server.policy.browser_status import (
    BrowserStatusRejected, ingest_browser_status, load_browser_status,
)
from endpoint_server.policy.models import (
    BrowserStatusCurrent, PolicyAssignment, PolicyDefinition, PolicyDeviceState,
    PolicyVersion,
)
from tests.contracts.test_browser_status_v1 import _report
from tests.contracts.test_endpoint_policy_v1 import POLICY_ID, _policy


NOW = datetime(2026, 9, 25, 12, tzinfo=UTC)


@pytest.fixture
async def browser_sessions():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(lambda sync: Base.metadata.create_all(sync, tables=[
            PolicyDefinition.__table__, PolicyVersion.__table__,
            PolicyAssignment.__table__, PolicyDeviceState.__table__,
            BrowserStatusCurrent.__table__,
        ]))
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    device_id = uuid4()
    version_id = uuid4()
    document = _policy()
    async with sessions() as session:
        session.add_all([
            PolicyDefinition(id=POLICY_ID, name="Municipal Default"),
            PolicyVersion(
                id=version_id, definition_id=POLICY_ID, version=1,
                digest=policy_digest_from_dict(document), document=document,
                created_by=uuid4(),
            ),
            PolicyAssignment(
                scope="default", policy_version_id=version_id,
                assigned_by=uuid4(), assigned_at=NOW,
            ),
            PolicyDeviceState(
                device_id=device_id, policy_version_id=version_id,
                policy_digest=policy_digest_from_dict(document), status="APPLIED",
                received_at=NOW, applied_at=NOW, acknowledged_at=NOW,
            ),
        ])
        await session.commit()
    yield sessions, device_id
    await engine.dispose()


def policy_digest_from_dict(document):
    from endpoint_contracts.endpoint_policy import EndpointPolicyV1

    return policy_digest(EndpointPolicyV1.model_validate(document))


def _browser_report() -> BrowserStatusReportV1:
    value = _report()
    value["policy_id"] = POLICY_ID
    value["browsers"][0].update({
        "running_state": "RUNNING", "last_running_at": NOW,
        "extension_version": "0.1.0", "extension_last_seen_at": NOW,
    })
    return BrowserStatusReportV1.model_validate(value)


@pytest.mark.asyncio
async def test_report_persists_families_and_preserves_last_heartbeat(browser_sessions) -> None:
    sessions, device_id = browser_sessions
    first = _browser_report()
    async with sessions() as session:
        await ingest_browser_status(session, device_id, first, received_at=NOW)
        await session.commit()
    async with sessions() as session:
        loaded = await load_browser_status(session, device_id)
    assert loaded is not None
    assert [item.browser_family for item in loaded.browsers] == ["chrome", "yandex"]
    assert loaded.browsers[0].extension_version == "0.1.0"

    second = first.model_dump(mode="python")
    second["observation_id"] = uuid4()
    second["observed_at"] = NOW + timedelta(minutes=1)
    second["browsers"][0].update({
        "running_state": "CLOSED", "extension_version": None,
        "extension_last_seen_at": None,
    })
    async with sessions() as session:
        await ingest_browser_status(
            session, device_id, BrowserStatusReportV1.model_validate(second),
            received_at=NOW + timedelta(minutes=1),
        )
        await session.commit()
    async with sessions() as session:
        loaded = await load_browser_status(session, device_id)
    assert loaded.browsers[0].running_state == "CLOSED"
    assert loaded.browsers[0].extension_version == "0.1.0"
    assert loaded.browsers[0].extension_last_seen_at == NOW


@pytest.mark.asyncio
async def test_out_of_order_and_duplicate_report_do_not_regress_current(browser_sessions) -> None:
    sessions, device_id = browser_sessions
    first = _browser_report()
    async with sessions() as session:
        await ingest_browser_status(session, device_id, first, received_at=NOW)
        await session.commit()
    older = first.model_dump(mode="python")
    older["observed_at"] = NOW - timedelta(minutes=1)
    older["observation_id"] = uuid4()
    older["browsers"][0]["browser_state"] = "ABSENT"
    older["browsers"][0]["running_state"] = "CLOSED"
    older["browsers"][0]["last_running_at"] = None
    async with sessions() as session:
        await ingest_browser_status(
            session, device_id, BrowserStatusReportV1.model_validate(older),
            received_at=NOW,
        )
        await ingest_browser_status(session, device_id, first, received_at=NOW)
        await session.commit()
    async with sessions() as session:
        rows = (await session.scalars(select(BrowserStatusCurrent))).all()
    assert len(rows) == 2
    assert next(row for row in rows if row.browser_family == "chrome").browser_state == "DETECTED"


@pytest.mark.asyncio
async def test_same_timestamp_with_different_observation_is_rejected(browser_sessions) -> None:
    sessions, device_id = browser_sessions
    first = _browser_report()
    async with sessions() as session:
        await ingest_browser_status(session, device_id, first, received_at=NOW)
        await session.commit()
    conflict = first.model_dump(mode="python")
    conflict["observation_id"] = uuid4()
    conflict["browsers"][0]["browser_state"] = "UNKNOWN"
    conflict["browsers"][0]["running_state"] = "UNKNOWN"
    async with sessions() as session:
        with pytest.raises(BrowserStatusRejected, match="timestamp"):
            await ingest_browser_status(
                session, device_id, BrowserStatusReportV1.model_validate(conflict),
                received_at=NOW,
            )
        await session.rollback()


@pytest.mark.asyncio
async def test_wrong_policy_is_rejected_but_failed_application_can_report_conflict(browser_sessions) -> None:
    sessions, device_id = browser_sessions
    value = _browser_report().model_dump(mode="python")
    value["policy_version"] = 2
    async with sessions() as session:
        with pytest.raises(BrowserStatusRejected, match="policy"):
            await ingest_browser_status(
                session, device_id, BrowserStatusReportV1.model_validate(value),
                received_at=NOW,
            )
        await session.rollback()
    async with sessions() as session:
        state = await session.scalar(select(PolicyDeviceState).where(
            PolicyDeviceState.device_id == device_id,
        ))
        state.status = "ERROR"
        await session.commit()
    async with sessions() as session:
        conflict = _browser_report().model_dump(mode="python")
        conflict["browsers"][0].update({
            "policy_owner": "CONFLICT", "installation_policy_state": "CONFLICT",
        })
        await ingest_browser_status(
            session, device_id, BrowserStatusReportV1.model_validate(conflict),
            received_at=NOW,
        )
        await session.commit()
    async with sessions() as session:
        loaded = await load_browser_status(session, device_id)
    assert loaded.browsers[0].policy_owner == "CONFLICT"


@pytest.mark.asyncio
async def test_projection_does_not_combine_different_browser_observations(browser_sessions) -> None:
    sessions, device_id = browser_sessions
    async with sessions() as session:
        await ingest_browser_status(session, device_id, _browser_report(), received_at=NOW)
        await session.commit()
    async with sessions() as session:
        row = await session.scalar(select(BrowserStatusCurrent).where(
            BrowserStatusCurrent.device_id == device_id,
            BrowserStatusCurrent.browser_family == "yandex",
        ))
        row.observation_id = uuid4()
        await session.commit()
    async with sessions() as session:
        assert await load_browser_status(session, device_id) is None
