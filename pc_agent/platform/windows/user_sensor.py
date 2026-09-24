"""Content-free observation from an unprivileged interactive Windows session.

The probe reads OS session state, last-input ticks and the foreground process
*name*. It never reads window titles, command lines or browser profiles.
"""

from __future__ import annotations

import ctypes
from typing import Annotated, Literal, Protocol
import ntpath

from pydantic import Field, model_validator

from endpoint_contracts.activity import ForegroundApplicationV1
from endpoint_contracts.base import ContractModelV1


DesktopState = Literal["UNLOCKED", "LOCKED", "DISCONNECTED", "UNKNOWN"]
_MAX_IDLE_SECONDS = 86400
_BROWSERS = frozenset({"chrome.exe", "browser.exe", "yandex.exe", "msedge.exe", "firefox.exe", "opera.exe"})
_OFFICE = frozenset({"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "soffice.bin"})
_REMOTE_ACCESS = frozenset({"mstsc.exe", "msra.exe", "anydesk.exe", "teamviewer.exe"})
_SYSTEM = frozenset({"explorer.exe", "taskmgr.exe", "powershell.exe", "pwsh.exe", "cmd.exe", "dwm.exe"})


class UserSessionSampleV1(ContractModelV1):
    schema_version: Literal["user_session_sample_v1"]
    desktop_state: DesktopState
    idle_seconds: Annotated[int | None, Field(strict=True, ge=0, le=_MAX_IDLE_SECONDS)] = None
    foreground: ForegroundApplicationV1 | None = None

    @model_validator(mode="after")
    def validate_state(self) -> "UserSessionSampleV1":
        if self.desktop_state == "UNLOCKED":
            if self.idle_seconds is None:
                raise ValueError("unlocked session needs idle time")
        elif self.idle_seconds is not None or self.foreground is not None:
            raise ValueError("noninteractive session cannot expose idle or foreground")
        return self


class SessionProbe(Protocol):
    def session_connected(self) -> bool | None: ...
    def input_desktop_name(self) -> str | None: ...
    def tick_count_ms(self) -> int: ...
    def last_input_ms(self) -> int: ...
    def foreground_process_name(self) -> str | None: ...


def _foreground(name: str | None) -> ForegroundApplicationV1 | None:
    if not isinstance(name, str) or name != ntpath.basename(name):
        return None
    normalized = name.lower()
    category = (
        "browser" if normalized in _BROWSERS
        else "office" if normalized in _OFFICE
        else "remote_access" if normalized in _REMOTE_ACCESS
        else "system" if normalized in _SYSTEM
        else "other"
    )
    try:
        return ForegroundApplicationV1(
            process_name=normalized, application_category=category,
        )
    except ValueError:
        return None


def sample_user_session(probe: SessionProbe) -> UserSessionSampleV1:
    """Derive a bounded, content-free sample; keep ambiguous OS state unknown."""
    try:
        connected = probe.session_connected()
        if connected is False:
            return UserSessionSampleV1(
                schema_version="user_session_sample_v1", desktop_state="DISCONNECTED",
            )
        if connected is not True:
            raise ValueError("session state unavailable")
        desktop = probe.input_desktop_name()
        if desktop == "Winlogon":
            return UserSessionSampleV1(
                schema_version="user_session_sample_v1", desktop_state="LOCKED",
            )
        if desktop != "Default":
            raise ValueError("input desktop unavailable")
        ticks = probe.tick_count_ms()
        last_input = probe.last_input_ms()
        idle_ms = ((ticks & 0xFFFFFFFF) - (last_input & 0xFFFFFFFF)) & 0xFFFFFFFF
        return UserSessionSampleV1(
            schema_version="user_session_sample_v1",
            desktop_state="UNLOCKED",
            idle_seconds=min(idle_ms // 1000, _MAX_IDLE_SECONDS),
            foreground=_foreground(probe.foreground_process_name()),
        )
    except (OSError, ValueError):
        return UserSessionSampleV1(
            schema_version="user_session_sample_v1", desktop_state="UNKNOWN",
        )


class WindowsSessionProbe:
    """Win32-backed probe used only inside the logged-in user's process."""

    def session_connected(self) -> bool | None:
        import win32api
        import win32con
        import win32security
        import win32ts

        try:
            token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
            try:
                session_id = win32security.GetTokenInformation(token, win32security.TokenSessionId)
            finally:
                token.Close()
            return win32ts.WTSQuerySessionInformation(
                win32ts.WTS_CURRENT_SERVER_HANDLE, session_id, win32ts.WTSConnectState,
            ) == win32ts.WTSActive
        except Exception:
            return None

    def input_desktop_name(self) -> str | None:
        import win32con
        import win32service

        try:
            desktop = win32service.OpenInputDesktop(
                0, False, win32con.DESKTOP_READOBJECTS,
            )
            try:
                return win32service.GetUserObjectInformation(desktop, win32con.UOI_NAME)
            finally:
                desktop.CloseDesktop()
        except Exception:
            return None

    def tick_count_ms(self) -> int:
        clock = ctypes.windll.kernel32.GetTickCount64
        clock.restype = ctypes.c_ulonglong
        clock.argtypes = []
        return clock()

    def last_input_ms(self) -> int:
        import win32api

        return win32api.GetLastInputInfo()

    def foreground_process_name(self) -> str | None:
        import psutil
        import win32gui
        import win32process

        try:
            hwnd = win32gui.GetForegroundWindow()
            if not hwnd:
                return None
            _thread_id, process_id = win32process.GetWindowThreadProcessId(hwnd)
            return psutil.Process(process_id).name()
        except (OSError, psutil.Error):
            return None
