"""Interactive sampling emits only bounded session and process-name metadata."""

import os

import pytest
from pydantic import ValidationError

from pc_agent.platform.windows.user_sensor import (
    UserSessionSampleV1,
    WindowsSessionProbe,
    sample_user_session,
)


class Probe:
    connected = True
    desktop = "Default"
    ticks = 1_234_000
    last_input = 1_200_000
    process = "chrome.exe"

    def session_connected(self) -> bool:
        return self.connected

    def input_desktop_name(self) -> str | None:
        return self.desktop

    def tick_count_ms(self) -> int:
        return self.ticks

    def last_input_ms(self) -> int:
        return self.last_input

    def foreground_process_name(self) -> str | None:
        return self.process


def test_unlocked_session_reports_idle_and_process_basename_only() -> None:
    sample = sample_user_session(Probe())
    assert sample.model_dump() == {
        "schema_version": "user_session_sample_v1", "desktop_state": "UNLOCKED",
        "idle_seconds": 34,
        "foreground": {"process_name": "chrome.exe", "application_category": "browser"},
    }
    assert "user_login" not in sample.model_dump_json()


@pytest.mark.parametrize("connected,desktop,expected", [
    (False, "Default", "DISCONNECTED"),
    (True, "Winlogon", "LOCKED"),
    (True, None, "UNKNOWN"),
    (True, "UnexpectedDesktop", "UNKNOWN"),
])
def test_noninteractive_state_has_no_idle_or_foreground(
    connected: bool, desktop: str | None, expected: str,
) -> None:
    probe = Probe()
    probe.connected = connected
    probe.desktop = desktop
    sample = sample_user_session(probe)
    assert sample.desktop_state == expected
    assert sample.idle_seconds is None
    assert sample.foreground is None


def test_tick_wraparound_is_bounded_and_process_path_is_dropped() -> None:
    probe = Probe()
    probe.ticks = (1 << 32) + 3000
    probe.last_input = (1 << 32) - 2000
    probe.process = r"C:\Private\document.exe"
    sample = sample_user_session(probe)
    assert sample.idle_seconds == 5
    assert sample.foreground is None


def test_sample_rejects_extra_content_and_invalid_state_shape() -> None:
    with pytest.raises(ValidationError):
        UserSessionSampleV1.model_validate({
            "schema_version": "user_session_sample_v1", "desktop_state": "UNLOCKED",
            "idle_seconds": 1, "window_title": "secret",
        })
    with pytest.raises(ValidationError):
        UserSessionSampleV1.model_validate({
            "schema_version": "user_session_sample_v1", "desktop_state": "LOCKED",
            "idle_seconds": 1,
        })


@pytest.mark.skipif(os.name != "nt", reason="live Windows session probe")
def test_live_windows_probe_emits_only_contract_fields() -> None:
    sample = sample_user_session(WindowsSessionProbe())
    assert set(sample.model_dump()) == {
        "schema_version", "desktop_state", "idle_seconds", "foreground",
    }
