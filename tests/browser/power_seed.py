"""Content-free synthetic power evidence for the disposable Console provider."""

from datetime import timedelta
from uuid import uuid4

from endpoint_contracts.power_events import (
    PowerEventBatchV1,
    PowerEventV1,
    PowerSourceStatusV1,
)
from endpoint_server.db.models import DeviceSession
from endpoint_server.power.ingestion import ingest_gateway_power_events


async def seed_power_history(session, device_id, lab_device_id, now):
    # Fresh presence deliberately coexists with historical shutdown evidence.
    session.add(
        DeviceSession(
            device_id=lab_device_id,
            session_identifier="synthetic-power-presence",
            created_at=now - timedelta(minutes=2),
            last_seen_at=now,
            expires_at=now + timedelta(seconds=90),
        )
    )
    for target, availability in ((device_id, "UNAVAILABLE"), (lab_device_id, "READY")):
        events = [
            PowerEventV1(
                schema_version="power_event_v1",
                event_identifier=uuid4(),
                event_kind="OS_SHUTDOWN_STARTED" if index == 0 else "OS_SLEEP_STARTED",
                occurred_at=now - timedelta(minutes=15 + index),
                observed_at=now,
                boot_id="synthetic-boot",
                source="synthetic-native",
                native_record_id=f"synthetic-{index}",
                evidence="transition",
            )
            for index in range(23)
        ]
        result = await ingest_gateway_power_events(
            session,
            target,
            PowerEventBatchV1(
                schema_version="power_event_batch_v1",
                batch_id=uuid4(),
                events=events,
                source_status=PowerSourceStatusV1(
                    schema_version="power_source_status_v1",
                    source="synthetic-native",
                    availability=availability,
                    reported_at=now,
                    coverage_started_at=now - timedelta(days=2),
                    loss_count=2,
                    reset_count=1,
                ),
            ),
            received_at=now,
        )
        assert all(row.disposition == "accepted" for row in result.results)
