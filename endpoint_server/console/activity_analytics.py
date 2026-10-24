"""Read-only, session-protected employee analytics with audited detail access."""
from datetime import UTC, date, datetime, timedelta
import hashlib
from typing import Annotated, Literal
from uuid import UUID
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from sqlalchemy import func, or_, select

from endpoint_server.activity.analytics_math import day_bounds, merged_segments, utc
from endpoint_server.activity.analytics_models import ActivityInterval
from endpoint_server.activity.analytics_reports import combine_daily, employees, report_rows
from endpoint_server.activity.analytics_schemas import Meta, Overview, ReportQuery, Timeline, UserReport
from endpoint_server.audit.request_ids import audit_request_id
from endpoint_server.audit.service import append_audit_event
from endpoint_server.auth.admin_sessions import AdminPrincipal, require_admin
from endpoint_server.db.models import Device, DeviceSession
from endpoint_server.power.projection import power_timeline_markers

router = APIRouter(prefix='/api/admin/console/activity-analytics', tags=['admin-activity-analytics'])


def now_utc():
    return datetime.now(UTC)


def _safe_text(value):
    if value is not None and any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise HTTPException(422, 'Недопустимые символы фильтра')
    return value.strip().casefold() if value else ''


def _meta(request, query, now):
    policy = request.app.state.settings.activity_analytics
    timezone = query.timezone or policy.organization_timezone
    if timezone not in policy.timezones:
        raise HTTPException(422, 'Выберите часовой пояс организации или UTC')
    today = now.astimezone(ZoneInfo(timezone)).date()
    earliest = today - timedelta(days=policy.aggregate_days - 1)
    if query.period == 'custom':
        if query.since is None or query.until is None:
            raise HTTPException(422, 'Укажите обе даты произвольного периода')
        since, until = query.since, query.until
    else:
        until = today - timedelta(days=query.period == 'yesterday')
        since = until - timedelta(days={'today': 0, 'yesterday': 0, '7d': 6, '30d': 29}[query.period])
    if since < earliest or since > until or until > today:
        raise HTTPException(422, 'Период выходит за доступную историю')
    return Meta(since=since, until=until, timezone=timezone, timezones=list(policy.timezones),
        today=today,
        detail_available_from=today - timedelta(days=policy.detail_days - 1),
        aggregate_available_from=earliest, max_gap_seconds=policy.max_gap_seconds,
        generated_at=now, collection_enabled=request.app.state.settings.endpoint_policy_enabled)


async def _audit(session, request, principal, user_key, kind):
    await append_audit_event(session, actor_kind='admin', actor_identifier=principal.user.username,
        action='activity.analytics.read', object_kind='activity_user',
        object_identifier='sha256:' + hashlib.sha256(user_key.encode('utf-8')).hexdigest(),
        request_id=audit_request_id(request), details={'view': kind})
    await session.commit()


@router.get('/overview', response_model=Overview)
async def overview(
    request: Request, response: Response,
    _: Annotated[AdminPrincipal, Depends(require_admin)],
    query: Annotated[ReportQuery, Depends()],
    search: Annotated[str, Query(max_length=256)] = '',
    sort: Literal['active', 'last_observed', 'state', 'user'] = 'active',
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
):
    response.headers['Cache-Control'] = 'no-store'
    now = now_utc()
    meta, needle = _meta(request, query, now), _safe_text(search)
    async with request.app.state.session_provider() as session:
        daily = await report_rows(session, meta)
        data = await employees(session, daily, now, meta.max_gap_seconds)
    summary = dict(fresh=sum(bool(r['fresh']) and r['state'] != 'UNKNOWN' for r in data),
        active=sum(r['state'] == 'ACTIVE' for r in data), idle=sum(r['state'] == 'IDLE' for r in data),
        locked_disconnected=sum(r['state'] in {'LOCKED', 'DISCONNECTED'} for r in data),
        unknown=sum(r['state'] == 'UNKNOWN' for r in data),
        unknown_devices=sum(r['user_key'] is None for r in data))
    if needle:
        data = [r for r in data if needle in (r['user_login'] or '').casefold()
                or any(needle in d['name'].casefold() for d in r['devices'])]
    def order(row):
        identity = row['user_key'] or row['devices'][0]['id']
        if sort == 'active':
            return (-(row['metrics']['seconds']['ACTIVE'] if row['metrics'] else -1), identity)
        if sort == 'last_observed':
            return (-(row['last_observed_at'].timestamp() if row['last_observed_at'] else 0), identity)
        if sort == 'state':
            return (['ACTIVE', 'IDLE', 'LOCKED', 'DISCONNECTED', 'UNKNOWN'].index(row['state']), identity)
        return ((row['user_login'] or '\uffff').casefold(), identity)
    data.sort(key=order)
    return Overview(data=data[offset:offset + limit], total=len(data), offset=offset, limit=limit, summary=summary, meta=meta)


@router.get('/user', response_model=UserReport)
async def user_report(
    request: Request, response: Response,
    principal: Annotated[AdminPrincipal, Depends(require_admin)],
    query: Annotated[ReportQuery, Depends()],
    user_key: Annotated[str, Query(min_length=1, max_length=300)],
):
    response.headers['Cache-Control'] = 'no-store'
    now, key = now_utc(), _safe_text(user_key)
    meta = _meta(request, query, now)
    async with request.app.state.session_provider() as session:
        rows = await report_rows(session, meta, user_key=key)
        data = next((r for r in await employees(session, rows, now, meta.max_gap_seconds) if r['user_key'] == key), None)
        if data is None:
            raise HTTPException(404, 'Учётная запись не найдена в доступной истории')
        days, day = [], meta.since
        by_day = {r.day: r for r in rows}
        while day <= meta.until:
            days.append(dict(day=day, metrics=combine_daily([by_day[day]]) if day in by_day else None,
                             timeline_available=day >= meta.detail_available_from))
            day += timedelta(days=1)
        await _audit(session, request, principal, key, 'user')
    return UserReport(data=data, daily=days, meta=meta)


def _unknown(start, end):
    return dict(started_at=start, ended_at=end, seconds=(end - start).total_seconds(),
        state='UNKNOWN', process_name=None, application_category=None, device_id=None,
        overlap=False, attributed=False)


async def _connection_gaps(session, device_ids, start, end, now):
    if not device_ids:
        return []
    preceding = select(DeviceSession.id, func.row_number().over(partition_by=DeviceSession.device_id,
        order_by=DeviceSession.created_at.desc()).label('rank')).where(
            DeviceSession.device_id.in_(device_ids), DeviceSession.created_at < start,
            DeviceSession.session_identifier.like('gateway-%')).subquery()
    rows = list((await session.scalars(select(DeviceSession).where(
        DeviceSession.device_id.in_(device_ids), DeviceSession.created_at < end,
        DeviceSession.session_identifier.like('gateway-%'),
        or_(DeviceSession.created_at >= start, DeviceSession.id.in_(select(preceding.c.id).where(preceding.c.rank == 1))),
    ).order_by(DeviceSession.created_at).limit(2001))).all())
    if len(rows) > 2000:
        raise HTTPException(422, 'Слишком много переподключений за день')
    result = []
    for device_id in device_ids:
        device_rows = [r for r in rows if r.device_id == device_id]
        for index, row in enumerate(device_rows):
            # Closed/expired Gateway session proves transport unavailability,
            # never that this employee was absent or the computer powered off.
            left = max(start, utc(row.closed_at or row.expires_at))
            right = min(end, now, utc(device_rows[index + 1].created_at) if index + 1 < len(device_rows) else end)
            if left < right:
                result.append(dict(device_id=str(device_id), started_at=left, ended_at=right))
    return result


@router.get('/timeline', response_model=Timeline)
async def timeline(
    request: Request, response: Response,
    principal: Annotated[AdminPrincipal, Depends(require_admin)],
    user_key: Annotated[str, Query(min_length=1, max_length=300)],
    day: date,
    timezone: Annotated[str | None, Query(max_length=64)] = None,
    include_power: bool = False,
):
    response.headers['Cache-Control'] = 'no-store'
    now, key = now_utc(), _safe_text(user_key)
    # Validate retention separately so an expired timeline has an explicit 410.
    meta = _meta(request, ReportQuery(timezone=timezone), now)
    if day < meta.detail_available_from:
        raise HTTPException(410, 'Подробные интервалы удалены по retention; доступны дневные итоги')
    if day > meta.until:
        raise HTTPException(422, 'Будущий день недоступен')
    start, end = day_bounds(day, meta.timezone)
    async with request.app.state.session_provider() as session:
        rows = list((await session.scalars(select(ActivityInterval).where(
            ActivityInterval.user_key == key, ActivityInterval.started_at < end,
            ActivityInterval.ended_at >= start,
        ).order_by(ActivityInterval.started_at).limit(20_001))).all())
        if len(rows) > 20_000:
            raise HTTPException(422, 'Слишком много интервалов за день')
        ids = {r.device_id for r in rows}
        known = await employees(session, [], now, meta.max_gap_seconds)
        employee = next((r for r in known if r['user_key'] == key), None)
        if employee:
            ids.update(UUID(d['id']) for d in employee['devices'])
        device_rows = (await session.scalars(select(Device).where(Device.id.in_(ids)))).all() if ids else []
        online_devices = {d['id'] for r in known for d in r['devices'] if d['online']}
        devices = {str(d.id): dict(id=str(d.id), name=d.display_name or d.device_identifier,
                                  online=str(d.id) in online_devices) for d in device_rows}
        segments, position = [], start
        for segment in merged_segments(rows, start, min(end, now)):
            left = datetime.fromisoformat(segment['started_at'])
            if left > position:
                segments.append(_unknown(position, left))
            segments.append(segment)
            position = datetime.fromisoformat(segment['ended_at'])
        if position < min(end, now):
            segments.append(_unknown(position, min(end, now)))
        gaps = await _connection_gaps(session, ids, start, end, now)
        power_events, power_events_truncated = (
            await power_timeline_markers(session, ids, start, end, now=now)
        ) if include_power else ([], False)
        await _audit(session, request, principal, key, 'timeline')
    return Timeline(day=day, timezone=meta.timezone, started_at=start, ended_at=end, data=segments,
        connection_gaps=gaps, power_events=power_events, power_events_truncated=power_events_truncated,
        devices=[devices.get(str(id), dict(id=str(id), name=str(id), online=False)) for id in sorted(ids, key=str)])
