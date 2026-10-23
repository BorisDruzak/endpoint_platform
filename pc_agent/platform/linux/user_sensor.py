"""Unprivileged KDE observations; no titles, paths, contents or credentials."""
from __future__ import annotations

from collections.abc import Callable
import json
import os

from endpoint_contracts.activity import ForegroundApplicationV1
from pc_agent.local_sensor_protocol import UserSessionSampleV1, _unique_object
from .sessions import LinuxSession

_BROWSERS = {'chromium', 'chromium-browser', 'chrome', 'google-chrome', 'yandex_browser', 'browser', 'firefox', 'msedge'}
_OFFICE = {'soffice', 'soffice.bin', 'libreoffice', 'onlyoffice-desktopeditors', 'desktopeditors', 'okular'}
_REMOTE = {'remmina', 'xfreerdp', 'krdc', 'anydesk', 'teamviewer'}
_SYSTEM = {'plasmashell', 'dolphin', 'konsole', 'systemsettings', 'ksysguard'}


def foreground_process(pid: int) -> str | None:
    import psutil

    try:
        process = psutil.Process(pid)
        if process.uids().real != os.getuid() or process.uids().effective != os.getuid():
            return None
        return process.name()
    except (psutil.Error, OSError):
        return None


def _foreground(name: str | None):
    if not isinstance(name, str) or '/' in name or '\\' in name:
        return None
    name = name.casefold()
    category = ('browser' if name in _BROWSERS else 'office' if name in _OFFICE
                else 'remote_access' if name in _REMOTE else 'system' if name in _SYSTEM else 'other')
    try:
        return ForegroundApplicationV1(process_name=name, application_category=category)
    except ValueError:
        return None


def sample_record(record: bytes, *, session: LinuxSession | None,
                  process_name: Callable[[int], str | None] = foreground_process) -> UserSessionSampleV1:
    def state(value):
        return UserSessionSampleV1(schema_version='user_session_sample_v1', desktop_state=value)
    if session is None:
        return state('UNKNOWN')
    if not session.active:
        return state('DISCONNECTED')
    if session.locked:
        return state('LOCKED')
    try:
        if not isinstance(record, bytes) or not 1 <= len(record) <= 1024:
            raise ValueError('invalid probe length')
        data = json.loads(record, object_pairs_hook=_unique_object)
        if not isinstance(data, dict) or set(data) != {'probe_v', 'idle_ms', 'locked', 'pid', 'backend'}:
            raise ValueError('invalid probe fields')
        if type(data['probe_v']) is not int or data['probe_v'] != 1 or data['backend'] not in {'xcb', 'wayland'}:
            raise ValueError('invalid probe version/backend')
        if data['locked'] is True:
            return state('LOCKED')
        if data['locked'] is not False or type(data['idle_ms']) is not int or not 0 <= data['idle_ms'] <= 2**63 - 1:
            raise ValueError('idle/lock unavailable')
        pid = data['pid']
        name = process_name(pid) if type(pid) is int and 0 < pid < 2**31 else None
        return UserSessionSampleV1(schema_version='user_session_sample_v1', desktop_state='UNLOCKED',
                                   idle_seconds=min(data['idle_ms'] // 1000, 86400), foreground=_foreground(name))
    except (ValueError, OSError, TypeError):
        return state('UNKNOWN')
