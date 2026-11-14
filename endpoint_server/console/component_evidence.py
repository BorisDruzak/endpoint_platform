"""Read independently dated agent component observations for one device."""

from datetime import UTC, datetime, timedelta
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, TypeAdapter, ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from endpoint_contracts.updates import SemanticVersionV1
from endpoint_contracts.context import HealthSectionsV1
from endpoint_server.console.fleet import PRESENCE_TTL
from endpoint_server.context.models import ContextCurrent
from endpoint_server.db.models import Device, DeviceInstance, DeviceSession
from endpoint_server.policy.models import PolicySensorHealthCurrent
from endpoint_server.setup_updates.models import SetupClientPresence
from endpoint_server.support_access.models import SupportAccess


_VERSION = TypeAdapter(SemanticVersionV1)
_OBSERVER_UI_TTL = timedelta(seconds=150)
_SENSOR_TTL = timedelta(seconds=150)
# The health profile is scheduled every five minutes.
_UPDATER_TTL = timedelta(minutes=10)


class ComponentObservation(BaseModel):
    observed_at: datetime
    fresh: bool


class ComponentVersion(ComponentObservation):
    version: str | None = None


class ObserverObservation(ComponentVersion):
    reported_ready: bool


UpdaterStatus = Literal["active", "inactive", "failed", "unknown"]


class UpdaterObservation(ComponentObservation):
    status: UpdaterStatus
    watcher_status: UpdaterStatus | None = None


class SupportEvidence(BaseModel):
    component: ComponentVersion | None = None
    access_verified_at: datetime | None = None


class DeviceComponentEvidence(BaseModel):
    core: ComponentVersion | None = None
    foundation: ComponentVersion | None = None
    updater: UpdaterObservation | None = None
    observer: ObserverObservation | None = None
    user_sensor: ComponentObservation | None = None
    support: SupportEvidence


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _version(value: str | None) -> str | None:
    try:
        return _VERSION.validate_python(value)
    except ValidationError:
        return None


def updater_evidence(
    sections: HealthSectionsV1, collected_at: datetime, now: datetime,
) -> UpdaterObservation | None:
    names = {"EndpointAgentUpdater", "endpoint-agent-update.service", "endpoint-agent-update.path"}
    facts: dict[str, UpdaterStatus] = {}
    for item in sections.services:
        if item.name in names:
            if item.name in facts:
                return None
            facts[item.name] = item.status
    if not facts or ("EndpointAgentUpdater" in facts and len(facts) != 1):
        return None
    observed = _utc(collected_at)
    return UpdaterObservation(
        observed_at=observed, fresh=now - _UPDATER_TTL <= observed <= now,
        status=facts.get("EndpointAgentUpdater", facts.get("endpoint-agent-update.service", "unknown")),
        watcher_status=facts.get("endpoint-agent-update.path"),
    )


async def device_component_evidence(
    session: AsyncSession, device_id: UUID, now: datetime,
) -> DeviceComponentEvidence:
    wss = aliased(DeviceSession)
    health = PolicySensorHealthCurrent
    setup = SetupClientPresence
    support = SupportAccess
    latest_wss = (
        select(DeviceSession.id)
        .where(DeviceSession.device_id == Device.id, DeviceSession.session_identifier.startswith("gateway-"))
        .order_by(DeviceSession.created_at.desc(), DeviceSession.id.desc())
        .limit(1).correlate(Device).scalar_subquery()
    )
    row = (await session.execute(
        select(wss.last_seen_at.label("wss_seen"), wss.closed_at, wss.expires_at,
               DeviceInstance.agent_version, setup.foundation_version, setup.client_version,
               setup.ready, setup.last_seen_at.label("observer_seen"),
               health.user_sensor_last_seen_at, health.received_at, health.observed_at, health.activity_listener_state,
               ContextCurrent.last_observed_at.label("activity_seen"),
               support.component_version, support.reported_at, support.access_verified_at)
        .select_from(Device)
        .outerjoin(wss, wss.id == latest_wss)
        .outerjoin(DeviceInstance, DeviceInstance.id == wss.device_instance_id)
        .outerjoin(setup, setup.device_id == Device.id)
        .outerjoin(health, health.device_id == Device.id)
        .outerjoin(ContextCurrent, (ContextCurrent.device_id == Device.id) & (ContextCurrent.profile == "activity_v1"))
        .outerjoin(support, support.device_id == Device.id)
        .where(Device.id == device_id)
    )).one_or_none()
    if row is None:
        return DeviceComponentEvidence(support=SupportEvidence())

    core = None
    if row.wss_seen is not None:
        observed = _utc(row.wss_seen)
        core = ComponentVersion(version=_version(row.agent_version), observed_at=observed, fresh=(
            row.closed_at is None and _utc(row.expires_at) > now and now - PRESENCE_TTL <= observed <= now
        ))
    foundation = observer = None
    if row.observer_seen is not None:
        observed = _utc(row.observer_seen)
        fresh = now - _OBSERVER_UI_TTL <= observed <= now
        observer = ObserverObservation(version=_version(row.client_version), observed_at=observed,
                                       fresh=fresh, reported_ready=row.ready)
        foundation_version = _version(row.foundation_version)
        if foundation_version is not None:
            foundation = ComponentVersion(version=foundation_version, observed_at=observed, fresh=fresh)
    sensor = None
    if row.user_sensor_last_seen_at is not None:
        observed = _utc(row.user_sensor_last_seen_at)
        sensor = ComponentObservation(observed_at=observed, fresh=(
            row.activity_listener_state == "READY" and row.activity_seen is not None
            and now - _SENSOR_TTL <= observed <= _utc(row.activity_seen) <= now
            and now - _SENSOR_TTL <= _utc(row.received_at) <= now
            and now - _SENSOR_TTL <= _utc(row.observed_at) <= now
        ))
    support_component = None
    if row.reported_at is not None:
        observed = _utc(row.reported_at)
        support_component = ComponentVersion(version=_version(row.component_version), observed_at=observed,
                                             fresh=now - PRESENCE_TTL <= observed <= now)
    return DeviceComponentEvidence(
        core=core, foundation=foundation, observer=observer, user_sensor=sensor,
        support=SupportEvidence(
            component=support_component,
            access_verified_at=_utc(row.access_verified_at) if row.access_verified_at else None,
        ),
    )
