"""Half-open interval algebra shared by rollups and the day timeline."""
from collections import defaultdict
from datetime import UTC, date, datetime, time, timedelta
from heapq import heappop, heappush
from uuid import UUID
from zoneinfo import ZoneInfo

STATES = ('ACTIVE', 'IDLE', 'LOCKED', 'DISCONNECTED', 'UNKNOWN')
_PRIORITY = {state: i for i, state in enumerate(STATES)}
_APPS = {
    'winword.exe': ('Microsoft Word', 'office'), 'excel.exe': ('Microsoft Excel', 'office'),
    'powerpnt.exe': ('PowerPoint', 'office'), 'outlook.exe': ('Microsoft Outlook', 'office'),
    'soffice.bin': ('LibreOffice', 'office'), 'chrome.exe': ('Google Chrome', 'browser'),
    'browser.exe': ('Яндекс Браузер', 'browser'), 'yandex.exe': ('Яндекс Браузер', 'browser'),
    'msedge.exe': ('Microsoft Edge', 'browser'), 'firefox.exe': ('Firefox', 'browser'),
    'opera.exe': ('Opera', 'browser'),
}


def utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def normalize_login(login: str | None, device_id: UUID) -> str | None:
    if login is None or not login.strip():
        return None
    value = login.strip().casefold()
    if any(ord(c) < 32 or ord(c) == 127 for c in value) or len(value) > 256:
        raise ValueError('Invalid OS account')
    # A bare login has no globally trustworthy domain; scope it to this device.
    return value if '\\' in value or '@' in value else f'local:{device_id}\\{value}'


def day_bounds(day: date, timezone: str) -> tuple[datetime, datetime]:
    zone = ZoneInfo(timezone)
    return (datetime.combine(day, time.min, zone).astimezone(UTC),
            datetime.combine(day + timedelta(days=1), time.min, zone).astimezone(UTC))


def application(process: str | None, category: str | None) -> tuple[str, str]:
    return _APPS.get((process or '').lower(), (process or 'Приложение неизвестно', category or 'other'))


def merged_segments(intervals, start: datetime, end: datetime) -> list[dict]:
    """Sweep endpoints once. ACTIVE wins overlaps; stable device order allocates apps.

    This is a reporting precedence, not proof of concurrent human input. Every
    overlap is measured separately and disclosed. Gaps have no user attribution.
    """
    events = defaultdict(list)
    for index, row in enumerate(intervals):
        left, right = max(start, utc(row.started_at)), min(end, utc(row.ended_at))
        if left >= right:
            continue
        events[left].append((1, index, row))
        events[right].append((-1, index, row))
    active, heap, result = {}, [], []
    previous = None
    for point in sorted(events):
        if previous is not None and previous < point and active:
            while heap and heap[0][-1] not in active:
                heappop(heap)
            winner = active[heap[0][-1]]
            result.append({
                'started_at': previous.isoformat(), 'ended_at': point.isoformat(),
                'seconds': (point - previous).total_seconds(),
                'state': winner.session_state, 'process_name': winner.process_name,
                'application_category': winner.application_category,
                'device_id': str(winner.device_id), 'overlap': len(active) > 1,
                'attributed': True,
            })
        for direction, index, row in events[point]:
            if direction == -1:
                active.pop(index, None)
            else:
                active[index] = row
                heappush(heap, (_PRIORITY[row.session_state], str(row.device_id), index))
        previous = point
    return result


def summarize(intervals, start: datetime, end: datetime) -> dict:
    seconds = dict.fromkeys(STATES, 0.0)
    apps, categories = defaultdict(float), defaultdict(float)
    overlap = 0.0
    segments = merged_segments(intervals, start, end)
    for segment in segments:
        duration, state = segment['seconds'], segment['state']
        seconds[state] += duration
        if segment['overlap']:
            overlap += duration
        if state == 'ACTIVE':
            label, category = application(segment['process_name'], segment['application_category'])
            apps[(label, category)] += duration
            categories[category] += duration
    # The observation horizon includes interior gaps, never a presumed workday.
    horizon = (datetime.fromisoformat(segments[-1]['ended_at']) -
               datetime.fromisoformat(segments[0]['started_at'])).total_seconds() if segments else 0
    seconds['UNKNOWN'] += max(0, horizon - sum(seconds.values()))
    return {
        'seconds': seconds, 'observed_span_seconds': horizon,
        'coverage': (horizon - seconds['UNKNOWN']) / horizon if horizon else None,
        'applications': [{'label': label, 'category': category, 'seconds': value}
                         for (label, category), value in sorted(apps.items(), key=lambda item: (-item[1], item[0]))],
        'categories': dict(categories), 'overlap_seconds': overlap,
        'devices': sorted({str(row.device_id) for row in intervals}),
        'user_login': next((row.user_login for row in intervals if row.user_login), None),
        'last_observed_at': max((utc(row.last_observed_at).isoformat() for row in intervals), default=None),
    }
