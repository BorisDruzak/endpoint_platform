"""Persist latest policy-scoped sensor health without trusting Agent compliance."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from endpoint_contracts.endpoint_policy import EndpointPolicyV1
from endpoint_contracts.sensor_health import PolicySensorHealthReportV1
from endpoint_server.context.ingestion import _advisory_lock

from .models import PolicyDeviceState, PolicySensorHealthCurrent
from .service import resolve_effective_policy


class SensorHealthRejected(ValueError):
    """A sensor report cannot safely advance the current device projection."""


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


async def ingest_sensor_health(
    session: AsyncSession,
    device_id: UUID,
    report: PolicySensorHealthReportV1,
    *,
    received_at: datetime | None = None,
) -> None:
    when = received_at or datetime.now(UTC)
    if when.tzinfo is None or when.utcoffset() is None:
        raise SensorHealthRejected("receipt time must be timezone-aware")
    when = when.astimezone(UTC)
    observed = report.observed_at.astimezone(UTC)
    if observed > when + timedelta(minutes=5):
        raise SensorHealthRejected("sensor observation is in the future")
    if observed < when - timedelta(hours=24):
        raise SensorHealthRejected("sensor observation is too old")

    version = await resolve_effective_policy(session, device_id)
    state = await session.scalar(select(PolicyDeviceState).where(
        PolicyDeviceState.device_id == device_id,
    ))
    if (
        version is None or state is None
        or state.status not in {"PENDING", "APPLIED", "ERROR"}
        or state.policy_version_id != version.id
        or state.policy_digest != version.digest
    ):
        raise SensorHealthRejected("sensor policy is not current")
    policy = EndpointPolicyV1.model_validate(version.document)
    if report.policy_id != policy.policy_id or report.policy_version != policy.policy_version:
        raise SensorHealthRejected("sensor report policy does not match assignment")

    await _advisory_lock(session, f"policy.sensor.health:{device_id}")
    row = await session.scalar(select(PolicySensorHealthCurrent).where(
        PolicySensorHealthCurrent.device_id == device_id,
    ).with_for_update())
    if row is None:
        row = PolicySensorHealthCurrent(device_id=device_id)
        session.add(row)
        same_policy = False
    else:
        same_policy = (
            row.policy_id == report.policy_id
            and row.policy_version == report.policy_version
        )
        if same_policy:
            prior_at = _utc(row.observed_at)
            if observed == prior_at and row.observation_id != report.observation_id:
                raise SensorHealthRejected("sensor observation timestamp conflicts")
            if observed <= prior_at:
                return
    prior_seen = (
        _utc(row.user_sensor_last_seen_at)
        if same_policy and row.user_sensor_last_seen_at is not None else None
    )
    incoming_seen = report.user_sensor_last_seen_at
    row.observation_id = report.observation_id
    row.policy_id = report.policy_id
    row.policy_version = report.policy_version
    row.observed_at = observed
    row.received_at = when
    row.activity_listener_state = report.activity_listener_state
    row.user_sensor_last_seen_at = max(
        [item for item in (prior_seen, incoming_seen) if item is not None],
        default=None,
    )
    row.security_spool_state = report.security_spool_state
    row.usb_source_state = report.usb_source_state
    row.print_source_state = report.print_source_state
    await session.flush()


async def load_sensor_health(
    session: AsyncSession,
    device_id: UUID,
) -> PolicySensorHealthReportV1 | None:
    row = await session.scalar(select(PolicySensorHealthCurrent).where(
        PolicySensorHealthCurrent.device_id == device_id,
    ))
    return sensor_health_from_row(row)


def sensor_health_from_row(
    row: PolicySensorHealthCurrent | None,
) -> PolicySensorHealthReportV1 | None:
    """Reconstruct a strict report from one current database row."""
    if row is None:
        return None
    return PolicySensorHealthReportV1(
        schema_version="policy_sensor_health_report_v1",
        observation_id=row.observation_id,
        policy_id=row.policy_id,
        policy_version=row.policy_version,
        observed_at=_utc(row.observed_at),
        activity_listener_state=row.activity_listener_state,
        user_sensor_last_seen_at=(
            _utc(row.user_sensor_last_seen_at) if row.user_sensor_last_seen_at else None
        ),
        security_spool_state=row.security_spool_state,
        usb_source_state=row.usb_source_state,
        print_source_state=row.print_source_state,
    )


__all__ = ["SensorHealthRejected", "ingest_sensor_health", "load_sensor_health"]
