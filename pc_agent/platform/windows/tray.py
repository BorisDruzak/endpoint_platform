"""Unprivileged, local-only Windows notification-area companion."""

from __future__ import annotations

import ctypes
import os
from ctypes import wintypes
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pc_agent.platform.windows.tray_status import (
    TrayStatus,
    TrayStatusError,
    read_tray_status,
)


TrayIcon = Literal["green", "yellow", "blue", "red", "grey"]
_WM_APP = 0x8000
_WM_COMMAND = 0x0111
_WM_DESTROY = 0x0002
_WM_RBUTTONUP = 0x0205
_WM_CONTEXTMENU = 0x007B
_WM_TIMER = 0x0113
_TRAY_CALLBACK = _WM_APP + 31
_REFRESH_TIMER = 31
_DETAILS_COMMAND = 1001
_REFRESH_COMMAND = 1002
_EXIT_COMMAND = 1003
_NIM_ADD = 0x00000000
_NIM_MODIFY = 0x00000001
_NIM_DELETE = 0x00000002
_NIF_MESSAGE = 0x00000001
_NIF_ICON = 0x00000002
_NIF_TIP = 0x00000004
_MF_STRING = 0x00000000
_MF_SEPARATOR = 0x00000800
_MF_GRAYED = 0x00000001
_TPM_RIGHTBUTTON = 0x0002
_TPM_RETURNCMD = 0x0100
_IDI_APPLICATION = 32512
_ERROR_ALREADY_EXISTS = 183


def _configure_menu_api(user32: object) -> None:
    """Declare pointer-width menu signatures before passing text to user32."""
    user32.CreatePopupMenu.restype = wintypes.HMENU
    user32.AppendMenuW.argtypes = [
        wintypes.HMENU,
        wintypes.UINT,
        ctypes.c_size_t,
        wintypes.LPCWSTR,
    ]
    user32.AppendMenuW.restype = wintypes.BOOL


@dataclass(frozen=True, slots=True)
class TrayView:
    """The complete non-sensitive view available to the interactive user."""

    icon: TrayIcon
    tooltip: str
    menu_labels: tuple[str, str, str]


def status_to_view(status: TrayStatus | None, now: datetime) -> TrayView:
    """Map a validated fresh projection to a bounded tray representation."""
    if now.tzinfo is None:
        raise ValueError("tray display time must be timezone-aware")
    if status is None:
        return _view("grey", "unknown", "unknown", "unknown")

    agent_state = status.agent_state
    if status.agent_state == "error" or status.update_state == "failed":
        return _view("red", "error", status.endpoint_state, status.update_state)
    if status.update_state in {"pending", "applying"}:
        return _view("blue", agent_state, status.endpoint_state, status.update_state)
    if (
        status.agent_state == "running"
        and status.endpoint_state == "connected"
        and status.update_state == "up_to_date"
    ):
        return _view("green", agent_state, status.endpoint_state, status.update_state)
    if status.agent_state in {"starting", "running"}:
        return _view("yellow", agent_state, status.endpoint_state, status.update_state)
    return _view("grey", agent_state, status.endpoint_state, status.update_state)


def _view(
    icon: TrayIcon, agent_state: str, endpoint_state: str, update_state: str
) -> TrayView:
    labels = (
        f"Endpoint Agent: {agent_state}",
        f"Endpoint: {endpoint_state}",
        f"Update: {update_state}",
    )
    return TrayView(icon=icon, tooltip="; ".join(labels), menu_labels=labels)


def default_windows_data_root() -> Path:
    """Return the fixed service data root without reading user configuration."""
    program_data = os.environ.get("PROGRAMDATA", r"C:\\ProgramData")
    return Path(program_data) / "Endpoint Platform" / "Agent"


def _load_view(data_root: Path) -> tuple[TrayView, TrayStatus | None]:
    now = datetime.now(UTC)
    try:
        status = read_tray_status(data_root, now=now)
    except (OSError, TrayStatusError):
        status = None
    return status_to_view(status, now), status


def run_tray(data_root: Path) -> int:
    """Run an interactive notification icon without network or service-control access."""
    if os.name != "nt":
        return 1
    return _WindowsTray(data_root).run()


class _WindowsTray:
    def __init__(self, data_root: Path) -> None:
        self._data_root = data_root
        self._view, self._status = _load_view(data_root)
        self._hwnd: int | None = None
        self._icon: int | None = None
        self._notify_added = False
        self._window_proc = None

    def run(self) -> int:
        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32
        shell32 = ctypes.windll.shell32
        instance_mutex = kernel32.CreateMutexW(None, False, r"Local\EndpointAgentTray")
        if not instance_mutex or kernel32.GetLastError() == _ERROR_ALREADY_EXISTS:
            if instance_mutex:
                kernel32.CloseHandle(instance_mutex)
            return 0
        hinstance = kernel32.GetModuleHandleW(None)

        class WNDCLASSW(ctypes.Structure):
            _fields_ = [
                ("style", wintypes.UINT),
                ("lpfnWndProc", ctypes.c_void_p),
                ("cbClsExtra", ctypes.c_int),
                ("cbWndExtra", ctypes.c_int),
                ("hInstance", wintypes.HINSTANCE),
                ("hIcon", wintypes.HICON),
                ("hCursor", wintypes.HCURSOR),
                ("hbrBackground", wintypes.HBRUSH),
                ("lpszMenuName", wintypes.LPCWSTR),
                ("lpszClassName", wintypes.LPCWSTR),
            ]

        wndproc_type = ctypes.WINFUNCTYPE(
            ctypes.c_ssize_t,
            wintypes.HWND,
            wintypes.UINT,
            wintypes.WPARAM,
            wintypes.LPARAM,
        )
        self._window_proc = wndproc_type(self._window_callback)
        class_name = "EndpointAgentTrayWindow"
        window_class = WNDCLASSW()
        window_class.lpfnWndProc = ctypes.cast(self._window_proc, ctypes.c_void_p)
        window_class.hInstance = hinstance
        window_class.lpszClassName = class_name
        try:
            atom = user32.RegisterClassW(ctypes.byref(window_class))
            if not atom:
                return 1
            hwnd = user32.CreateWindowExW(
                0, class_name, "Endpoint Agent Tray", 0, 0, 0, 0, 0, None, None, hinstance, None
            )
            if not hwnd:
                return 1
            self._hwnd = hwnd
            self._icon = _create_colored_icon(self._view.icon)
            self._notify(shell32, _NIM_ADD)
            user32.SetTimer(hwnd, _REFRESH_TIMER, 15000, None)
            message = wintypes.MSG()
            while user32.GetMessageW(ctypes.byref(message), None, 0, 0) > 0:
                user32.TranslateMessage(ctypes.byref(message))
                user32.DispatchMessageW(ctypes.byref(message))
            return 0
        finally:
            kernel32.CloseHandle(instance_mutex)

    def _window_callback(self, hwnd: int, message: int, wparam: int, lparam: int) -> int:
        user32 = ctypes.windll.user32
        if message == _TRAY_CALLBACK and lparam in {_WM_RBUTTONUP, _WM_CONTEXTMENU}:
            self._show_menu(user32, hwnd)
            return 0
        if message == _WM_TIMER and wparam == _REFRESH_TIMER:
            self._refresh()
            return 0
        if message == _WM_COMMAND:
            command = wparam & 0xFFFF
            if command == _DETAILS_COMMAND:
                self._show_details(user32, hwnd)
            elif command == _REFRESH_COMMAND:
                self._refresh()
            elif command == _EXIT_COMMAND:
                user32.DestroyWindow(hwnd)
            return 0
        if message == _WM_DESTROY:
            user32.KillTimer(hwnd, _REFRESH_TIMER)
            self._notify(ctypes.windll.shell32, _NIM_DELETE)
            if self._icon:
                user32.DestroyIcon(self._icon)
                self._icon = None
            user32.PostQuitMessage(0)
            return 0
        return user32.DefWindowProcW(hwnd, message, wparam, lparam)

    def _refresh(self) -> None:
        new_view, new_status = _load_view(self._data_root)
        if new_view == self._view:
            self._status = new_status
            return
        old_icon = self._icon
        self._view, self._status = new_view, new_status
        self._icon = _create_colored_icon(new_view.icon)
        self._notify(ctypes.windll.shell32, _NIM_MODIFY)
        if old_icon:
            ctypes.windll.user32.DestroyIcon(old_icon)

    def _show_menu(self, user32: object, hwnd: int) -> None:
        _configure_menu_api(user32)
        menu = user32.CreatePopupMenu()
        if not menu:
            return
        try:
            for label in self._view.menu_labels:
                user32.AppendMenuW(menu, _MF_STRING | _MF_GRAYED, 0, label)
            user32.AppendMenuW(menu, _MF_SEPARATOR, 0, None)
            user32.AppendMenuW(menu, _MF_STRING, _DETAILS_COMMAND, "Details")
            user32.AppendMenuW(menu, _MF_STRING, _REFRESH_COMMAND, "Refresh")
            user32.AppendMenuW(menu, _MF_STRING, _EXIT_COMMAND, "Exit tray icon")
            point = wintypes.POINT()
            user32.GetCursorPos(ctypes.byref(point))
            user32.SetForegroundWindow(hwnd)
            command = user32.TrackPopupMenu(
                menu, _TPM_RIGHTBUTTON | _TPM_RETURNCMD, point.x, point.y, 0, hwnd, None
            )
            if command:
                user32.PostMessageW(hwnd, _WM_COMMAND, command, 0)
        finally:
            user32.DestroyMenu(menu)

    def _show_details(self, user32: object, hwnd: int) -> None:
        details = self._view.tooltip
        if self._status is not None:
            details += "\nObserved: " + self._status.observed_at.isoformat()
            if self._status.reason_code:
                details += "\nReason: " + self._status.reason_code
        user32.MessageBoxW(hwnd, details, "Endpoint Agent", 0)

    def _notify(self, shell32: object, action: int) -> None:
        if self._hwnd is None:
            return

        class NOTIFYICONDATAW(ctypes.Structure):
            _fields_ = [
                ("cbSize", wintypes.DWORD),
                ("hWnd", wintypes.HWND),
                ("uID", wintypes.UINT),
                ("uFlags", wintypes.UINT),
                ("uCallbackMessage", wintypes.UINT),
                ("hIcon", wintypes.HICON),
                ("szTip", wintypes.WCHAR * 128),
            ]

        data = NOTIFYICONDATAW()
        data.cbSize = ctypes.sizeof(data)
        data.hWnd = self._hwnd
        data.uID = 1
        data.uFlags = _NIF_MESSAGE | _NIF_ICON | _NIF_TIP
        data.uCallbackMessage = _TRAY_CALLBACK
        data.hIcon = self._icon
        data.szTip = self._view.tooltip[:127]
        self._notify_added = bool(shell32.Shell_NotifyIconW(action, ctypes.byref(data)))


def _create_colored_icon(color: TrayIcon) -> int:
    """Create a compact coloured native icon; fall back to the Windows app icon."""
    user32 = ctypes.windll.user32
    gdi32 = ctypes.windll.gdi32
    colours = {
        "green": (38, 166, 91),
        "yellow": (219, 166, 21),
        "blue": (43, 114, 198),
        "red": (201, 57, 57),
        "grey": (119, 119, 119),
    }
    red, green, blue = colours[color]
    pixels = bytes([blue, green, red, 255] * (16 * 16))
    color_buffer = ctypes.create_string_buffer(pixels)
    mask_buffer = ctypes.create_string_buffer(bytes(32))
    color_bitmap = gdi32.CreateBitmap(16, 16, 1, 32, color_buffer)
    mask_bitmap = gdi32.CreateBitmap(16, 16, 1, 1, mask_buffer)

    class ICONINFO(ctypes.Structure):
        _fields_ = [
            ("fIcon", wintypes.BOOL),
            ("xHotspot", wintypes.DWORD),
            ("yHotspot", wintypes.DWORD),
            ("hbmMask", wintypes.HBITMAP),
            ("hbmColor", wintypes.HBITMAP),
        ]

    try:
        if color_bitmap and mask_bitmap:
            icon = user32.CreateIconIndirect(
                ctypes.byref(ICONINFO(True, 0, 0, mask_bitmap, color_bitmap))
            )
            if icon:
                return icon
    finally:
        if color_bitmap:
            gdi32.DeleteObject(color_bitmap)
        if mask_bitmap:
            gdi32.DeleteObject(mask_bitmap)
    return user32.LoadIconW(None, _IDI_APPLICATION)


def main() -> int:
    return run_tray(default_windows_data_root())


if __name__ == "__main__":
    raise SystemExit(main())
