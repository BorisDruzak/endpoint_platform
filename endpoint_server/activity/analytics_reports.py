"""Batch report projections: overview never scans raw Activity observations."""
from collections import defaultdict
from datetime import datetime, timedelta

from fastapi import HTTPException
from sqlalchemy import select

from endpoint_server.db.models import Device, DeviceSession
from .analytics_math import STATES, utc
from .analytics_models import ActivityCursor, ActivityDaily


def combine_daily(rows):
    if not rows:
        return None
    seconds, apps, categories = dict.fromkeys(STATES, 0.0), defaultdict(float), defaultdict(float)
    span, overlap, updates = 0.0, 0.0, []
    for row in rows:
        payload = row.payload
        if not payload:
            continue
        for state in STATES:
            seconds[state] += payload['seconds'][state]
        span += payload['observed_span_seconds']
        overlap += payload['overlap_seconds']
        for app in payload['applications']:
            apps[(app['label'], app['category'])] += app['seconds']
        for category, duration in payload['categories'].items():
            categories[category] += duration
        updates.append(utc(row.updated_at))
    return dict(seconds=seconds, observed_span_seconds=span,
        coverage=(span - seconds['UNKNOWN']) / span if span else None,
        applications=[dict(label=label, category=category, seconds=duration)
                      for (label, category), duration in sorted(apps.items(), key=lambda p: (-p[1], p[0]))],
        categories=dict(categories), overlap_seconds=overlap,
        pending=any(row.dirty for row in rows), updated_at=min(updates) if updates else None)


async def report_rows(session, meta, *, user_key=None):
    query = select(ActivityDaily).where(ActivityDaily.timezone == meta.timezone,
        ActivityDaily.day >= meta.since, ActivityDaily.day <= meta.until)
    if user_key is not None:
        query = query.where(ActivityDaily.user_key == user_key)
    rows = list((await session.scalars(query.limit(100_001))).all())
    if len(rows) > 100_000:
        raise HTTPException(422, 'Слишком большой отчёт. Сузьте период.')
    return rows


async def employees(session, daily, now: datetime, max_gap: int):
    devices = list((await session.scalars(select(Device).limit(5001))).all())
    if len(devices) > 5000:
        raise HTTPException(422, 'Превышен предел устройств для этого отчёта')
    cursors = list((await session.scalars(select(ActivityCursor))).all())
    online = set((await session.scalars(select(DeviceSession.device_id).where(
        DeviceSession.closed_at.is_(None), DeviceSession.expires_at > now,
        DeviceSession.last_seen_at >= now - timedelta(seconds=90),
    ).distinct())).all())
    device_map = {str(d.id): dict(id=str(d.id), name=d.display_name or d.device_identifier,
                                online=d.id in online) for d in devices}
    live_devices = {str(d.id) for d in devices if d.retired_at is None}
    groups, current = defaultdict(list), defaultdict(list)
    seen_devices = set()
    for row in daily:
        groups[row.user_key].append(row)
        seen_devices.update(row.payload.get('devices', []))
    for cursor in cursors:
        if cursor.user_key is not None and str(cursor.device_id) in live_devices:
            current[cursor.user_key].append(cursor)
            seen_devices.add(str(cursor.device_id))
    result = []
    for key in sorted(groups.keys() | current.keys()):
        rows, latest = groups[key], current[key]
        fresh = [c for c in latest if 0 <= (now - utc(c.last_observed_at)).total_seconds() <= max_gap]
        state = min((c.session_state for c in fresh), key=STATES.index, default='UNKNOWN')
        ids = {str(c.device_id) for c in latest}
        for row in rows:
            ids.update(row.payload.get('devices', []))
        timestamps = [utc(c.last_observed_at) for c in latest]
        timestamps.extend(datetime.fromisoformat(r.payload['last_observed_at']) for r in rows if r.payload.get('last_observed_at'))
        login = max(latest, key=lambda c: utc(c.last_observed_at)).user_login if latest else next(
            (r.payload.get('user_login') for r in rows if r.payload.get('user_login')), key)
        metrics = combine_daily(rows)
        result.append(dict(user_key=key, user_login=login, devices=[device_map.get(id, dict(id=id, name=id, online=False)) for id in sorted(ids)],
            state=state, fresh=bool(fresh), last_observed_at=max(timestamps) if timestamps else None,
            metrics=metrics, reason='Телеметрия отсутствует или устарела' if not fresh else
            'Сенсор не смог определить состояние сеанса' if state == 'UNKNOWN' else None))
    for device in devices:
        if str(device.id) in live_devices and str(device.id) not in seen_devices:
            result.append(dict(user_key=None, user_login=None, devices=[device_map[str(device.id)]],
                state='UNKNOWN', fresh=False, last_observed_at=None, metrics=None,
                reason='Нет подтверждённой учётной записи Activity. Проверьте поддержку и включение Activity Sensor и применение политики.'))
    return result
