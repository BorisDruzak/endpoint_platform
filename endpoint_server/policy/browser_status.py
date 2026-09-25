"""Validate and persist the current per-family Browser Sensor observation."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from endpoint_contracts.browser_status import (
    BrowserFamilyStatusV1, BrowserStatusReportV1,
)
from endpoint_contracts.endpoint_policy import EndpointPolicyV1
from endpoint_server.context.ingestion import _advisory_lock

from .models import BrowserStatusCurrent, PolicyDeviceState
from .service import resolve_effective_policy


class BrowserStatusRejected(ValueError):
    """An observation does not belong to the current applied device policy."""


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


async def ingest_browser_status(
    session: AsyncSession,
    device_id: UUID,
    report: BrowserStatusReportV1,
    *,
    received_at: datetime | None = None,
) -> None:
    """Advance both browser rows atomically, never overwriting newer facts."""
    when = received_at or datetime.now(UTC)
    if when.tzinfo is None or when.utcoffset() is None:
        raise BrowserStatusRejected("browser receipt time must be timezone-aware")
    when = when.astimezone(UTC)
    observed = report.observed_at.astimezone(UTC)
    if not timedelta(0) <= when - observed <= timedelta(hours=24):
        if observed > when + timedelta(minutes=5):
            raise BrowserStatusRejected("browser observation is in the future")
        if observed < when - timedelta(hours=24):
            raise BrowserStatusRejected("browser observation is too old")
    version = await resolve_effective_policy(session, device_id)
    state = await session.scalar(select(PolicyDeviceState).where(
        PolicyDeviceState.device_id == device_id,
    ))
    if (
        version is None or state is None or state.status not in {"PENDING", "APPLIED", "ERROR"}
        or state.policy_version_id != version.id or state.policy_digest != version.digest
    ):
        raise BrowserStatusRejected("browser policy is not applied")
    policy = EndpointPolicyV1.model_validate(version.document)
    if report.policy_id != policy.policy_id or report.policy_version != policy.policy_version:
        raise BrowserStatusRejected("browser report policy does not match assignment")
    await _advisory_lock(session, f"browser.status:{device_id}")
    rows = (await session.scalars(select(BrowserStatusCurrent).where(
        BrowserStatusCurrent.device_id == device_id,
    ).with_for_update())).all()
    by_family = {row.browser_family: row for row in rows}
    for item in report.browsers:
        row = by_family.get(item.browser_family)
        if row is None:
            row = BrowserStatusCurrent(
                device_id=device_id, browser_family=item.browser_family,
            )
            session.add(row)
        else:
            prior_at = _utc(row.observed_at)
            if observed == prior_at and row.observation_id != report.observation_id:
                raise BrowserStatusRejected("browser observation timestamp conflicts")
            if observed <= prior_at:
                continue
        same_policy = (
            row.policy_id == report.policy_id and row.policy_version == report.policy_version
            if row.observed_at is not None else False
        )
        prior_seen = _utc(row.extension_last_seen_at) if same_policy and row.extension_last_seen_at else None
        prior_running = _utc(row.last_running_at) if same_policy and row.last_running_at else None
        row.observation_id = report.observation_id
        row.policy_id = report.policy_id
        row.policy_version = report.policy_version
        row.observed_at = observed
        row.received_at = when
        row.browser_state = item.browser_state
        row.running_state = item.running_state
        row.policy_owner = item.policy_owner
        row.installation_policy_state = item.installation_policy_state
        row.native_host_state = item.native_host_state
        incoming_seen = item.extension_last_seen_at
        if incoming_seen is not None and (prior_seen is None or incoming_seen > prior_seen):
            row.extension_last_seen_at = incoming_seen
            row.extension_version = item.extension_version
        else:
            row.extension_last_seen_at = prior_seen
            row.extension_version = row.extension_version if prior_seen is not None else None
        incoming_running = item.last_running_at
        row.last_running_at = max(
            [value for value in (prior_running, incoming_running) if value is not None],
            default=None,
        )
    await session.flush()


async def load_browser_status(
    session: AsyncSession,
    device_id: UUID,
) -> BrowserStatusReportV1 | None:
    """Return the last complete two-browser projection for Console/compliance."""
    rows = (await session.scalars(select(BrowserStatusCurrent).where(
        BrowserStatusCurrent.device_id == device_id,
    ))).all()
    if len(rows) != 2 or {row.browser_family for row in rows} != {"chrome", "yandex"}:
        return None
    by_family = {row.browser_family: row for row in rows}
    newest = max(rows, key=lambda row: _utc(row.observed_at))
    if any(
        row.observation_id != newest.observation_id
        or row.policy_id != newest.policy_id
        or row.policy_version != newest.policy_version
        or _utc(row.observed_at) != _utc(newest.observed_at)
        for row in rows
    ):
        return None
    return BrowserStatusReportV1(
        schema_version="browser_status_report_v1",
        observation_id=newest.observation_id,
        policy_id=newest.policy_id,
        policy_version=newest.policy_version,
        observed_at=_utc(newest.observed_at),
        browsers=[
            BrowserFamilyStatusV1(
                browser_family=row.browser_family,
                browser_state=row.browser_state,
                running_state=row.running_state,
                policy_owner=row.policy_owner,
                installation_policy_state=row.installation_policy_state,
                native_host_state=row.native_host_state,
                extension_version=row.extension_version,
                extension_last_seen_at=(
                    _utc(row.extension_last_seen_at) if row.extension_last_seen_at else None
                ),
                last_running_at=_utc(row.last_running_at) if row.last_running_at else None,
            )
            for row in (by_family["chrome"], by_family["yandex"])
        ],
    )
