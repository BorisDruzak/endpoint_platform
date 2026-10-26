from datetime import UTC, date, datetime
from types import SimpleNamespace

import pytest

from endpoint_server.worktime.domain import next_status, project_work, schedule_windows, notification_candidates


def at(hour, minute=0):
    return datetime(2026, 10, 26, hour, minute, tzinfo=UTC)


def test_fsm_rejects_two_device_start_and_invalid_resume():
    assert next_status('ENDED', 'start') == 'WORKING'
    with pytest.raises(ValueError):
        next_status('WORKING', 'start')
    with pytest.raises(ValueError):
        next_status('ENDED', 'resume')
    assert next_status('WORKING', 'off_pc') == 'OFF_PC'
    assert next_status('OFF_PC', 'resume') == 'WORKING'


def test_midnight_projection_clips_without_double_count():
    events = [SimpleNamespace(occurred_at=at(17), status='WORKING', id='a'),
              SimpleNamespace(occurred_at=at(20), status='BREAK', id='b')]
    intervals, totals = project_work(events, [], at(19), at(23), at(22))
    assert totals == {'work_seconds': 3600, 'off_pc_seconds': 0, 'break_seconds': 7200}
    assert intervals[0]['started_at'] == at(19).isoformat()


def test_overnight_shift_and_holiday_override():
    schedule = dict(weekdays=[0, 1, 2, 3, 4], start='22:00', end='06:00', overrides={})
    windows = schedule_windows(schedule, date(2026, 10, 27))
    assert windows[0] == (at(19), datetime(2026, 10, 27, 1, tzinfo=UTC))
    schedule['overrides'] = {'2026-10-26': None}
    assert schedule_windows(schedule, date(2026, 10, 27))[0][0].day == 27


def test_measured_return_only_threshold_no_unknown_or_predeclared():
    def seg(left, right, state):
        return dict(started_at=left.isoformat(), ended_at=right.isoformat(), state=state, attributed=True)
    timeline = [seg(at(4), at(4, 20), 'IDLE'), seg(at(4, 20), at(5), 'ACTIVE')]
    assert len(notification_candidates(timeline, [(at(3), at(13))], [], 1200)) == 1
    timeline[0]['state'] = 'UNKNOWN'
    assert notification_candidates(timeline, [(at(3), at(13))], [], 1200) == []


def test_partial_cover_subtracts_union_without_suppressing_remaining_measured_time():
    timeline = [dict(started_at=at(4).isoformat(),ended_at=at(4,30).isoformat(),state='IDLE',attributed=True),
        dict(started_at=at(4,30).isoformat(),ended_at=at(5).isoformat(),state='ACTIVE',attributed=True)]
    # Overlapping declarations cover the same one minute, not two minutes.
    covered = [(at(4),at(4,1)),(at(4),at(4,1))]
    assert notification_candidates(timeline,[(at(3),at(13))],covered) == [(at(4,1),at(4,30))]
    assert notification_candidates(timeline,[(at(3),at(13))],[(at(4,10),at(4,11))]) == [
        (at(4),at(4,10)),(at(4,11),at(4,30))]
    assert notification_candidates(timeline,[(at(3),at(13))],[(at(4),at(4,11))]) == []
    timeline[0]['state'] = 'LOCKED'
    assert notification_candidates(timeline, [(at(3), at(13))], [(at(4), at(4, 20))], 1200) == []
    timeline[0]['ended_at'] = at(4, 19).isoformat()
    assert notification_candidates(timeline, [(at(3), at(13))], [], 1200) == []
