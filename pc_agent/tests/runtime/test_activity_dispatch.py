"""Activity observations survive transient WSS reconnect in bounded memory."""

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from endpoint_contracts.activity import ActivityObservationV1
from pc_agent.activity_dispatch import ActivityDispatch, ActivityQueueFull


def observation() -> ActivityObservationV1:
    return ActivityObservationV1(
        schema_version="activity_observation_v1", observation_id=uuid4(),
        observed_at=datetime(2026, 9, 25, tzinfo=UTC),
        session_state="ACTIVE", idle_seconds=2,
    )


def test_queue_rejects_new_observation_when_full() -> None:
    dispatch = ActivityDispatch(max_pending=1)
    first = observation()
    dispatch.enqueue(first)
    with pytest.raises(ActivityQueueFull):
        dispatch.enqueue(observation())
    assert dispatch.pending_count == 1


@pytest.mark.asyncio
async def test_send_failure_retains_same_observation_for_reconnect() -> None:
    dispatch = ActivityDispatch(max_pending=2)
    first = observation()
    dispatch.enqueue(first)

    class Transport:
        def __init__(self) -> None:
            self.sent = []
            self.fail = True

        async def send_activity_observation(self, item):
            self.sent.append(item)
            if self.fail:
                raise OSError("WSS unavailable")

    transport = Transport()
    with pytest.raises(OSError):
        await dispatch.flush_one(transport)
    assert dispatch.pending_count == 1
    transport.fail = False
    await dispatch.flush_one(transport)
    assert transport.sent == [first, first]
    assert dispatch.pending_count == 0
