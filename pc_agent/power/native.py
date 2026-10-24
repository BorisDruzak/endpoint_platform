"""Bounded metadata-only boundary shared by the two native sources."""

from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
from uuid import NAMESPACE_URL, uuid5

from endpoint_contracts.power_events import PowerEventV1, PowerSourceStatusV1


@dataclass(frozen=True, slots=True)
class NativePage:
    events: tuple[PowerEventV1, ...]
    checkpoint: str | None
    status: PowerSourceStatusV1
    loss_count: int = 0
    reset_count: int = 0


def opaque_id(value: str) -> str:
    return sha256(value.encode("utf-8")).hexdigest()


def native_event(
    *,
    source: str,
    boot_id: str,
    native_record_id: str,
    event_kind: str,
    occurred_at: datetime,
    observed_at: datetime,
    evidence: str = "transition",
    sleep_subtype: str | None = None,
) -> PowerEventV1:
    identity = f"{source}\0{boot_id}\0{native_record_id}"
    return PowerEventV1(
        schema_version="power_event_v1",
        event_identifier=uuid5(NAMESPACE_URL, identity),
        source=source,
        boot_id=boot_id,
        native_record_id=native_record_id,
        event_kind=event_kind,
        occurred_at=occurred_at,
        observed_at=observed_at,
        evidence=evidence,
        sleep_subtype=sleep_subtype,
    )
