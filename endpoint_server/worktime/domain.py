"""UTC half-open personnel intervals; telemetry never confirms working time."""
from datetime import UTC, date, datetime, time, timedelta
from zoneinfo import ZoneInfo

TIMEZONE = 'Asia/Yekaterinburg'
STATUSES = ('WORKING', 'BREAK', 'OFF_PC', 'ENDED')
_TRANSITIONS = {
    'ENDED': {'start': 'WORKING'},
    'WORKING': {'end': 'ENDED', 'break': 'BREAK', 'off_pc': 'OFF_PC'},
    'BREAK': {'end': 'ENDED', 'resume': 'WORKING'},
    'OFF_PC': {'end': 'ENDED', 'resume': 'WORKING', 'break': 'BREAK'},
}


def utc(value):
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def next_status(current, action):
    try:
        return _TRANSITIONS[current][action]
    except KeyError:
        raise ValueError('Invalid work status transition') from None


def schedule_windows(schedule, day: date, *, shift_days=None):
    """Clip today's and yesterday's shifts, including explicit holiday overrides."""
    zone = ZoneInfo(TIMEZONE)
    start = datetime.combine(day, time.min, zone).astimezone(UTC)
    end = start + timedelta(days=1)
    result = []
    for shift_day in shift_days if shift_days is not None else (day - timedelta(days=1), day):
        override = schedule.get('overrides', {}).get(shift_day.isoformat(), 'default')
        if override is None or (override == 'default' and shift_day.weekday() not in schedule['weekdays']):
            continue
        shift = schedule if override == 'default' else override
        left_time, right_time = time.fromisoformat(shift['start']), time.fromisoformat(shift['end'])
        left = datetime.combine(shift_day, left_time, zone).astimezone(UTC)
        right_day = shift_day + timedelta(days=right_time <= left_time)
        right = datetime.combine(right_day, right_time, zone).astimezone(UTC)
        left, right = max(start, left), min(end, right)
        if left < right:
            result.append((left, right))
    return result


def project_work(events, corrections, start, end, now):
    """Replay original events and overlay approved corrections without rewriting history."""
    end = min(end, now)
    if start >= end:
        return [], dict(work_seconds=0, off_pc_seconds=0, break_seconds=0)
    events = sorted(events, key=lambda e: utc(e.occurred_at))
    corrections = sorted(corrections, key=lambda c: utc(c.approved_at))
    points = {start, end}
    points.update(utc(e.occurred_at) for e in events if start < utc(e.occurred_at) < end)
    for correction in corrections:
        points.update(p for p in (utc(correction.started_at), utc(correction.ended_at)) if start < p < end)
    intervals = []
    totals = dict(work_seconds=0, off_pc_seconds=0, break_seconds=0)
    for left, right in zip(sorted(points), sorted(points)[1:]):
        prior = [e for e in events if utc(e.occurred_at) <= left]
        status, source, record_id = (prior[-1].status, 'employee', str(prior[-1].id)) if prior else ('ENDED', 'unrecorded', None)
        for correction in corrections:
            if utc(correction.started_at) <= left < utc(correction.ended_at):
                status, source, record_id = correction.status, 'approved_correction', str(correction.id)
        seconds = int((right - left).total_seconds())
        if status in ('WORKING', 'OFF_PC'):
            totals['work_seconds'] += seconds
        if status == 'OFF_PC':
            totals['off_pc_seconds'] += seconds
        if status == 'BREAK':
            totals['break_seconds'] += seconds
        intervals.append(dict(id=record_id, started_at=left.isoformat(), ended_at=right.isoformat(), status=status, source=source))
    return intervals, totals


def fully_covered(start, end, windows):
    cursor = start
    for left, right in sorted(windows):
        if left <= cursor < right:
            cursor = max(cursor, right)
    return cursor >= end


def union_windows(windows):
    result = []
    for left,right in sorted(windows):
        if result and left <= result[-1][1]:
            result[-1] = (result[-1][0],max(right,result[-1][1]))
        else:
            result.append((left,right))
    return result


def subtract_coverage(start, end, covered):
    """Subtract the union; overlapping explanations cannot double-subtract time."""
    result, cursor = [], start
    for left,right in sorted(covered):
        if right <= cursor or left >= end:
            continue
        if cursor < left:
            result.append((cursor,min(left,end)))
        cursor = max(cursor,right)
        if cursor >= end:
            break
    if cursor < end:
        result.append((cursor,end))
    return result


def notification_candidates(segments, scheduled, covered, threshold=1200):
    """A contiguous measured IDLE/LOCKED run followed by ACTIVE, never a gap."""
    result, beginning, previous_end = [], None, None
    for segment in segments:
        left, right = datetime.fromisoformat(segment['started_at']), datetime.fromisoformat(segment['ended_at'])
        state = segment['state'] if segment.get('attributed') else 'UNKNOWN'
        if previous_end != left:
            beginning = None
        if state in ('IDLE', 'LOCKED'):
            beginning = left if beginning is None else beginning
        elif state == 'ACTIVE':
            if beginning is not None and fully_covered(beginning,left,scheduled):
                remaining = subtract_coverage(beginning,left,covered)
                if sum((b-a).total_seconds() for a,b in remaining) >= threshold:
                    result.extend(remaining)
            beginning = None
        else:
            beginning = None
        previous_end = right
    return result
