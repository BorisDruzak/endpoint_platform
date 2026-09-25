"""Bounded-page Policy fleet projection with server-derived compliance."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Literal
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from endpoint_contracts.activity import ActivitySectionsV1
from endpoint_contracts.endpoint_policy import EndpointPolicyV1
from endpoint_server.context.models import ContextCurrent
from endpoint_server.context.projection import activity_current_projection
from endpoint_server.db.models import Device, DeviceInstance
from endpoint_server.gateway.connection_registry import GatewayConnection

from .browser_status import browser_status_from_rows
from .device_compliance import ActivityEvidence, derive_device_compliance
from .models import (
    BrowserStatusCurrent, PolicyAssignment, PolicyDefinition, PolicyDeviceState,
    PolicySensorHealthCurrent, PolicyVersion,
)
from .sensor_health import sensor_health_from_row


ComplianceFilter = Literal["COMPLIANT", "PARTIAL", "NON_COMPLIANT", "STALE", "UNSUPPORTED"]
_BATCH_SIZE = 100


def _aware(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


async def _project_batch(
    session: AsyncSession,
    devices: Sequence[tuple[UUID, str, str | None]],
    *,
    default: tuple[PolicyVersion, str] | None,
    connections: Mapping[UUID, GatewayConnection],
    now: datetime,
) -> list[dict[str, object]]:
    ids = [row[0] for row in devices]
    if not ids:
        return []
    overrides = {
        device_id: (version, name)
        for device_id, version, name in (await session.execute(
            select(PolicyAssignment.device_id, PolicyVersion, PolicyDefinition.name)
            .join(PolicyVersion, PolicyAssignment.policy_version_id == PolicyVersion.id)
            .join(PolicyDefinition, PolicyVersion.definition_id == PolicyDefinition.id)
            .where(PolicyAssignment.scope == "device", PolicyAssignment.device_id.in_(ids))
        )).all()
    }
    states = {
        row.device_id: row for row in (await session.scalars(
            select(PolicyDeviceState).where(PolicyDeviceState.device_id.in_(ids))
        )).all()
    }
    version_ids = [row.policy_version_id for row in states.values() if row.policy_version_id]
    applied_versions = {
        version_id: number for version_id, number in (await session.execute(
            select(PolicyVersion.id, PolicyVersion.version).where(PolicyVersion.id.in_(version_ids))
        )).all()
    } if version_ids else {}
    health = {
        row.device_id: row for row in (await session.scalars(
            select(PolicySensorHealthCurrent).where(PolicySensorHealthCurrent.device_id.in_(ids))
        )).all()
    }
    browser_rows: dict[UUID, list[BrowserStatusCurrent]] = defaultdict(list)
    for row in (await session.scalars(
        select(BrowserStatusCurrent).where(BrowserStatusCurrent.device_id.in_(ids))
    )).all():
        browser_rows[row.device_id].append(row)
    activities = {
        row.device_id: row for row in (await session.scalars(
            select(ContextCurrent).where(
                ContextCurrent.device_id.in_(ids), ContextCurrent.profile == "activity_v1",
            )
        )).all()
    }
    latest_instance = select(
        DeviceInstance.device_id.label("device_id"),
        DeviceInstance.agent_version.label("agent_version"),
        func.row_number().over(
            partition_by=DeviceInstance.device_id,
            order_by=(
                DeviceInstance.last_seen_at.desc(),
                DeviceInstance.created_at.desc(), DeviceInstance.id.desc(),
            ),
        ).label("rank"),
    ).where(DeviceInstance.device_id.in_(ids)).subquery()
    agent_versions = {
        device_id: version for device_id, version in (await session.execute(
            select(latest_instance.c.device_id, latest_instance.c.agent_version)
            .where(latest_instance.c.rank == 1)
        )).all()
    }

    policies: dict[UUID, EndpointPolicyV1] = {}
    data: list[dict[str, object]] = []
    for device_id, identifier, display_name in devices:
        connection = connections.get(device_id)
        state = states.get(device_id)
        base: dict[str, object] = {
            "id": device_id,
            "device_identifier": identifier,
            "display_name": display_name or identifier,
            "agent_version": connection.agent_version if connection else agent_versions.get(device_id),
            "online": connection is not None,
            "policy_name": None,
            "policy_version": None,
            "applied_version": applied_versions.get(state.policy_version_id) if state else None,
            "delivery_status": None,
            "compliance": None,
            "acknowledged_at": _aware(state.acknowledged_at) if state and state.acknowledged_at else None,
            "activity_sensor": "NOT_APPLICABLE",
            "browser_sensor": "NOT_APPLICABLE",
            "dlp_sensor": "NOT_APPLICABLE",
        }
        assigned = overrides.get(device_id, default)
        if assigned is None:
            data.append(base)
            continue
        version, policy_name = assigned
        policy = policies.get(version.id)
        if policy is None:
            policy = EndpointPolicyV1.model_validate(version.document)
            policies[version.id] = policy
        delivery_status = state.status if state is not None else "PENDING"
        if state is not None and (
            state.policy_version_id != version.id or state.policy_digest != version.digest
        ):
            delivery_status = "STALE"
        browser_report = browser_status_from_rows(browser_rows.get(device_id, []))
        health_report = sensor_health_from_row(health.get(device_id))
        projection = activity_current_projection(activities[device_id]) if device_id in activities else None
        activity_evidence = None
        if projection is not None:
            observed_at = projection["last_observed_at"]
            if isinstance(observed_at, datetime):
                sections = ActivitySectionsV1.model_validate(projection["sections"])
                activity_evidence = ActivityEvidence(
                    last_observed_at=_aware(observed_at), session_state=sections.session_state,
                )
        derived = derive_device_compliance(
            policy, delivery_status, health_report, browser_report, activity_evidence,
            online=connection is not None,
            protocol_features=connection.protocol_features if connection else frozenset(),
            now=now,
        )
        base.update({
            "policy_name": policy_name,
            "policy_version": policy.policy_version,
            "delivery_status": delivery_status,
            "compliance": derived.overall,
            "activity_sensor": derived.activity,
            "browser_sensor": derived.browser,
            "dlp_sensor": derived.dlp,
        })
        data.append(base)
    return data


async def list_policy_fleet(
    session: AsyncSession,
    connections: Mapping[UUID, GatewayConnection],
    *,
    limit: int = 50,
    offset: int = 0,
    compliance: ComplianceFilter | None = None,
    search: str | None = None,
) -> dict[str, object]:
    """Filter before pagination; read current facts in fixed-size device batches."""
    if not 1 <= limit <= 100 or not 0 <= offset <= 100_000:
        raise ValueError("Invalid policy fleet pagination")
    now = datetime.now(UTC)
    default = (await session.execute(
        select(PolicyVersion, PolicyDefinition.name)
        .select_from(PolicyAssignment)
        .join(PolicyVersion, PolicyAssignment.policy_version_id == PolicyVersion.id)
        .join(PolicyDefinition, PolicyVersion.definition_id == PolicyDefinition.id)
        .where(PolicyAssignment.scope == "default")
    )).one_or_none()
    base = select(Device.id, Device.device_identifier, Device.display_name).where(
        Device.retired_at.is_(None)
    )
    if search:
        literal = search.strip()[:128].replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        term = f"%{literal}%"
        base = base.where(
            Device.device_identifier.ilike(term, escape="\\")
            | Device.display_name.ilike(term, escape="\\")
        )
    if compliance is None:
        total = (await session.scalar(select(func.count()).select_from(base.subquery()))) or 0
        devices = (await session.execute(
            base.order_by(Device.device_identifier).limit(limit).offset(offset)
        )).all()
        data = await _project_batch(
            session, devices, default=default, connections=connections, now=now,
        )
        return {"data": data, "total": total, "limit": limit, "offset": offset}

    # A status filter depends on live WSS capabilities and expiring sensor facts,
    # so SQL-only filtering or post-page filtering would return a false total.
    cursor: str | None = None
    total = 0
    page: list[dict[str, object]] = []
    while True:
        query = base
        if cursor is not None:
            query = query.where(Device.device_identifier > cursor)
        devices = (await session.execute(
            query.order_by(Device.device_identifier).limit(_BATCH_SIZE)
        )).all()
        if not devices:
            break
        cursor = devices[-1].device_identifier
        for item in await _project_batch(
            session, devices, default=default, connections=connections, now=now,
        ):
            if item["compliance"] == compliance:
                if total >= offset and len(page) < limit:
                    page.append(item)
                total += 1
    return {"data": page, "total": total, "limit": limit, "offset": offset}


__all__ = ["ComplianceFilter", "list_policy_fleet"]
