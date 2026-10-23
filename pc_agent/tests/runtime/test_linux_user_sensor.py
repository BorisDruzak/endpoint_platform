"""Content-free KDE probe records never become an invented ACTIVE observation."""
import json

import pytest

from pc_agent.platform.linux.sessions import LinuxSession


def _session(active=True, locked=False):
    return LinuxSession('6', 2000, 'worker', 'wayland', active, locked, 'active')


def test_kde_record_uses_milliseconds_and_only_same_uid_process_name():
    from pc_agent.platform.linux.user_sensor import sample_record

    record = b'{"probe_v":1,"idle_ms":61000,"locked":false,"pid":123,"backend":"wayland"}'
    seen = []
    def process_name(pid):
        seen.append(pid)
        return 'chromium'
    sample = sample_record(record, session=_session(), process_name=process_name)
    assert sample.desktop_state == 'UNLOCKED' and sample.idle_seconds == 61
    assert sample.foreground.process_name == 'chromium' and sample.foreground.application_category == 'browser'
    assert seen == [123]


@pytest.mark.parametrize('record', [
    b'{"probe_v":1,"idle_ms":null,"locked":false,"pid":null,"backend":"wayland"}',
    b'{"probe_v":1,"idle_ms":false,"locked":false,"pid":null,"backend":"xcb"}',
    b'{"probe_v":1,"idle_ms":10,"locked":null,"pid":null,"backend":"xcb"}',
    b'{"probe_v":1,"idle_ms":0,"locked":false,"pid":null,"backend":"offscreen"}',
    b'{"probe_v":1,"idle_ms":0,"locked":false,"pid":null,"backend":"wayland","title":"forbidden"}',
    b'{"probe_v":1,"idle_ms":0,"idle_ms":100,"locked":false,"pid":null,"backend":"xcb"}',
])
def test_missing_idle_backend_or_unknown_fields_stay_unknown(record):
    from pc_agent.platform.linux.user_sensor import sample_record

    sample = sample_record(record, session=_session(), process_name=lambda pid: 'chromium')
    assert sample.desktop_state == 'UNKNOWN' and sample.idle_seconds is None and sample.foreground is None


@pytest.mark.parametrize('active,locked,state', [(False, False, 'DISCONNECTED'), (True, True, 'LOCKED')])
def test_logind_restrictions_win_even_when_probe_is_missing(active, locked, state):
    from pc_agent.platform.linux.user_sensor import sample_record

    assert sample_record(b'', session=_session(active, locked)).desktop_state == state


def test_wayland_startup_null_idle_remains_unknown_until_backend_observes_input():
    from pc_agent.platform.linux.user_sensor import sample_record

    record = dict(probe_v=1, idle_ms=None, locked=False, pid=123, backend='wayland')
    assert sample_record(json.dumps(record).encode(), session=_session()).desktop_state == 'UNKNOWN'
    record['idle_ms'] = 0
    assert sample_record(json.dumps(record).encode(), session=_session()).desktop_state == 'UNLOCKED'
