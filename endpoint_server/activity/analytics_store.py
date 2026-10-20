"""Transactional append/extend path and bounded worker jobs for Activity history."""
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4
from zoneinfo import ZoneInfo

from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.ext.asyncio import AsyncSession

from endpoint_contracts.activity import ActivityObservationV1
from endpoint_server.context.ingestion import _advisory_lock
from .analytics_math import day_bounds, normalize_login, summarize, utc
from .analytics_models import ActivityCursor, ActivityDaily, ActivityInterval
from .analytics_policy import AnalyticsPolicy


async def _dirty(session, user_key, start, end, policy):
    if user_key is None:
        return
    values = []
    for timezone in policy.timezones:
        zone = ZoneInfo(timezone)
        day, last = start.astimezone(zone).date(), end.astimezone(zone).date()
        while day <= last:
            values.append(dict(id=uuid4(), user_key=user_key, timezone=timezone, day=day,
                               dirty=True, updated_at=start, payload={}))
            day += timedelta(days=1)
    insert = pg_insert if session.bind.dialect.name == 'postgresql' else sqlite_insert
    statement = insert(ActivityDaily).values(values)
    # Preserve the last completed payload and its timestamp until the worker
    # publishes the replacement. Locking this row prevents lost dirty marks.
    await session.execute(statement.on_conflict_do_update(
        index_elements=['user_key', 'timezone', 'day'], set_={'dirty': True},
    ))


def _new_interval(device_id, user_key, login, start, end, state, foreground, browser, version):
    return ActivityInterval(
        id=uuid4(), device_id=device_id, user_key=user_key, user_login=login,
        started_at=start, ended_at=end, last_observed_at=end, session_state=state,
        process_name=foreground.process_name.lower() if foreground else None,
        application_category=foreground.application_category if foreground else None,
        browser_family=browser.browser_family if browser else None, policy_version_id=version,
    )


async def record_observation(
    session: AsyncSession, device_id: UUID, observation: ActivityObservationV1, *,
    state: str, policy_version_id: UUID | None, policy: AnalyticsPolicy,
) -> None:
    """Only invoked after Activity validation and the applied-policy gate.

    Hold the device cursor lock through the caller's Context transaction. A
    sample has zero duration until another sample brackets it. A long gap is
    wholly UNKNOWN, with no 45-second optimistic ACTIVE tail.
    """
    await _advisory_lock(session, f'activity.analytics:{device_id}')
    cursor = await session.scalar(select(ActivityCursor).where(
        ActivityCursor.device_id == device_id).with_for_update())
    when = utc(observation.observed_at)
    if cursor and (when <= utc(cursor.last_observed_at) or observation.observation_id == cursor.observation_id):
        return
    user_key = normalize_login(observation.user_login, device_id)
    previous = await session.get(ActivityInterval, cursor.interval_id) if cursor and cursor.interval_id else None
    if previous is not None:
        start = utc(cursor.last_observed_at)
        gap = (when - start).total_seconds() > policy.max_gap_seconds
        # A different account after a gap does not establish who owned it.
        # Very long absences also have no defensible employee attribution.
        attributable_gap = previous.user_key == user_key and when - start <= timedelta(hours=24)
        if gap:
            start = max(start, when - timedelta(days=policy.detail_days))
        # Split at every supported report calendar boundary. Retention can
        # remove whole completed intervals without truncating retained days.
        while start < when:
            boundary = min(day_bounds(start.astimezone(ZoneInfo(zone)).date(), zone)[1]
                           for zone in policy.timezones)
            end = min(when, boundary)
            if gap:
                unknown = _new_interval(device_id,
                    previous.user_key if attributable_gap else None,
                    previous.user_login if attributable_gap else None,
                    start, end, 'UNKNOWN', None, None, previous.policy_version_id)
                session.add(unknown)
            elif utc(previous.ended_at) == start and utc(previous.started_at) < boundary:
                previous.ended_at = end
            else:
                # Same old state continuing after a calendar boundary.
                continued = ActivityInterval(
                    id=uuid4(), device_id=device_id, user_key=previous.user_key, user_login=previous.user_login,
                    started_at=start, ended_at=end, last_observed_at=previous.last_observed_at, session_state=previous.session_state,
                    process_name=previous.process_name, application_category=previous.application_category,
                    browser_family=previous.browser_family, policy_version_id=previous.policy_version_id,
                )
                session.add(continued)
                previous = continued
            await _dirty(session, (previous.user_key if not gap or attributable_gap else None), start, end, policy)
            start = end
            if start == boundary and start < when and not gap:
                # Force a fresh row on the next day.
                previous = ActivityInterval(
                    id=uuid4(), device_id=device_id, user_key=previous.user_key, user_login=previous.user_login,
                    started_at=start, ended_at=start, last_observed_at=previous.last_observed_at, session_state=previous.session_state,
                    process_name=previous.process_name, application_category=previous.application_category,
                    browser_family=previous.browser_family, policy_version_id=previous.policy_version_id,
                )
                session.add(previous)
    foreground = observation.foreground if state == 'ACTIVE' else None
    browser = observation.browser if foreground else None
    same = previous is not None and (
        previous.user_key == user_key and previous.session_state == state
        and previous.process_name == (foreground.process_name.lower() if foreground else None)
        and previous.application_category == (foreground.application_category if foreground else None)
        and previous.browser_family == (browser.browser_family if browser else None)
        and previous.policy_version_id == policy_version_id
        and (when - utc(cursor.last_observed_at)).total_seconds() <= policy.max_gap_seconds
        and all(utc(previous.started_at).astimezone(ZoneInfo(z)).date() == when.astimezone(ZoneInfo(z)).date()
                for z in policy.timezones)
    )
    if not same:
        previous = _new_interval(device_id, user_key, observation.user_login, when, when,
                                 state, foreground, browser, policy_version_id)
        session.add(previous)
    else:
        previous.last_observed_at = when
    await session.flush()
    if cursor is None:
        cursor = ActivityCursor(device_id=device_id)
        session.add(cursor)
    cursor.user_key, cursor.user_login = user_key, observation.user_login
    cursor.interval_id, cursor.observation_id = previous.id, observation.observation_id
    cursor.last_observed_at, cursor.session_state = when, state
    await _dirty(session, user_key, when, when, policy)
    await session.flush()


async def rebuild_daily(session: AsyncSession, *, policy: AnalyticsPolicy,
                        now: datetime | None = None, batch_size: int = 16) -> int:
    """Publish at most 16 dirty user-days per transaction; reports read rollups.

    Select the dirty row before reading intervals. Ingestion's upsert then
    either precedes this read or leaves the row dirty after our commit.
    """
    if not 1 <= batch_size <= 256:
        raise ValueError('aggregate batch must be between 1 and 256')
    when = utc(now or datetime.now(UTC))
    daily = list((await session.scalars(select(ActivityDaily).where(
        ActivityDaily.dirty.is_(True), ActivityDaily.timezone.in_(policy.timezones),
    ).order_by(ActivityDaily.updated_at, ActivityDaily.day, ActivityDaily.user_key)
        .limit(batch_size).with_for_update(skip_locked=True))).all())
    for row in daily:
        start, end = day_bounds(row.day, row.timezone)
        intervals = list((await session.scalars(select(ActivityInterval).where(
            ActivityInterval.user_key == row.user_key, ActivityInterval.started_at < end,
            ActivityInterval.ended_at >= start,
        ).order_by(ActivityInterval.started_at).limit(20_001))).all())
        if len(intervals) > 20_000:
            # Do not publish a plausible partial total or delete its source.
            row.updated_at = when
            continue
        row.payload = summarize(intervals, start, min(end, when))
        row.updated_at, row.dirty = when, False
    await session.flush()
    return len(daily)


async def retain_analytics(session: AsyncSession, *, policy: AnalyticsPolicy,
                           now: datetime | None = None, batch_size: int = 500) -> int:
    if not 1 <= batch_size <= 1000:
        raise ValueError('retention batch must be between 1 and 1000')
    when = utc(now or datetime.now(UTC))
    # Whole calendar days are retained in every supported report timezone.
    cutoff = min(day_bounds((when.astimezone(ZoneInfo(z)) - timedelta(days=policy.detail_days)).date(), z)[0]
                 for z in policy.timezones)
    # Never delete unaggregated evidence. This also covers worker downtime.
    dirty_users = select(ActivityDaily.user_key).where(ActivityDaily.dirty.is_(True))
    eligible = select(ActivityInterval.id).where(
        ActivityInterval.ended_at < cutoff,
        (ActivityInterval.user_key.is_(None) | ActivityInterval.user_key.not_in(dirty_users)),
    ).order_by(ActivityInterval.ended_at).limit(batch_size)
    result = await session.execute(delete(ActivityInterval).where(ActivityInterval.id.in_(eligible)))
    stale = select(ActivityDaily.id).where(
        ActivityDaily.day < (when - timedelta(days=policy.aggregate_days)).date(),
    ).order_by(ActivityDaily.day).limit(batch_size)
    await session.execute(delete(ActivityDaily).where(ActivityDaily.id.in_(stale)))
    cursors = select(ActivityCursor.id).where(
        ActivityCursor.last_observed_at < when - timedelta(days=policy.aggregate_days),
    ).limit(batch_size)
    await session.execute(delete(ActivityCursor).where(ActivityCursor.id.in_(cursors)))
    return result.rowcount
