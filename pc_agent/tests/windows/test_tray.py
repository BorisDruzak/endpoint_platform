"""Unit tests for the unprivileged Windows tray companion."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from pc_agent.platform.windows.tray import _WindowsTray, status_to_view
from pc_agent.platform.windows.tray_status import TrayStatus
from pc_agent.version import AGENT_VERSION


NOW = datetime(2026, 9, 21, 10, 0, tzinfo=UTC)


def _status(
    *,
    agent_state: str = "running",
    endpoint_state: str = "connected",
    update_state: str = "up_to_date",
    reason_code: str | None = None,
) -> TrayStatus:
    return TrayStatus(
        version="3.2.51",
        agent_state=agent_state,  # type: ignore[arg-type]
        endpoint_state=endpoint_state,  # type: ignore[arg-type]
        update_state=update_state,  # type: ignore[arg-type]
        observed_at=NOW,
        reason_code=reason_code,
    )


def test_update_failure_precedes_connected_icon() -> None:
    view = status_to_view(_status(update_state="failed", reason_code="UPDATE_VALIDATION"), NOW)

    assert view.icon == "red"
    assert view.tooltip == (
        "Агент Endpoint: ошибка; Endpoint: подключён; Обновление: ошибка; Версия: 3.2.51"
    )


def test_pending_precedes_fresh_connected_icon() -> None:
    view = status_to_view(_status(update_state="applying"), NOW)

    assert view.icon == "blue"
    assert view.tooltip == (
        "Агент Endpoint: работает; Endpoint: подключён; Обновление: устанавливается; Версия: 3.2.51"
    )


def test_connected_running_agent_is_green_with_exact_status_labels() -> None:
    view = status_to_view(_status(), NOW)

    assert view.icon == "green"
    assert view.menu_labels == (
        "Агент Endpoint: работает",
        "Endpoint: подключён",
        "Обновление: актуально",
        "Версия: 3.2.51",
    )


def test_running_disconnected_agent_is_yellow() -> None:
    assert status_to_view(_status(endpoint_state="disconnected"), NOW).icon == "yellow"


def test_missing_or_invalid_projection_is_grey() -> None:
    view = status_to_view(None, NOW)

    assert view.icon == "grey"
    assert view.tooltip == (
        "Агент Endpoint: неизвестно; Endpoint: неизвестно; Обновление: неизвестно; "
        f"Версия: {AGENT_VERSION}"
    )


@pytest.mark.parametrize(("agent", "label"), [
    ("starting", "запускается"), ("stopped", "остановлен"),
])
def test_agent_states_have_russian_labels(agent: str, label: str) -> None:
    assert status_to_view(_status(agent_state=agent), NOW).menu_labels[0] == f"Агент Endpoint: {label}"


@pytest.mark.parametrize(("endpoint", "label"), [
    ("connecting", "подключается"), ("disconnected", "нет соединения"),
    ("unknown", "неизвестно"),
])
def test_endpoint_states_have_russian_labels(endpoint: str, label: str) -> None:
    assert status_to_view(_status(endpoint_state=endpoint), NOW).menu_labels[1] == f"Endpoint: {label}"


@pytest.mark.parametrize(("update", "label"), [
    ("pending", "ожидает"), ("applying", "устанавливается"),
    ("failed", "ошибка"), ("unknown", "неизвестно"),
])
def test_update_states_have_russian_labels(update: str, label: str) -> None:
    assert status_to_view(_status(update_state=update), NOW).menu_labels[2] == f"Обновление: {label}"


def test_tray_actions_and_details_are_russian() -> None:
    from pc_agent.platform.windows.tray import _DETAILS_COMMAND, _EXIT_COMMAND, _REFRESH_COMMAND

    tray = _WindowsTray(Path("C:/ProgramData/Endpoint Platform/Agent"))
    assert tray._menu_label(_DETAILS_COMMAND) == "Сведения"
    assert tray._menu_label(_REFRESH_COMMAND) == "Обновить"
    assert tray._menu_label(_EXIT_COMMAND) == "Закрыть значок"
    tray._view = status_to_view(_status(reason_code="UPDATE_VALIDATION"), NOW)
    tray._status = _status(reason_code="UPDATE_VALIDATION")
    calls: list[tuple[object, ...]] = []
    user32 = SimpleNamespace(MessageBoxW=lambda *args: calls.append(args))
    tray._show_details(user32, 101)
    assert calls[0][2] == "Агент Endpoint"
    assert "Наблюдалось:" in str(calls[0][1])
    assert "Причина: UPDATE_VALIDATION" in str(calls[0][1])


def test_tray_module_has_no_transport_or_service_control_imports() -> None:
    source = (Path(__file__).parents[2] / "platform" / "windows" / "tray.py").read_text(
        encoding="utf-8"
    )

    assert "aiohttp" not in source
    assert "win32service" not in source
    assert "endpoint_gateway" not in source


def test_tray_entrypoint_uses_an_absolute_package_import() -> None:
    """PyInstaller executes the tray entrypoint without a package parent."""
    source = (Path(__file__).parents[2] / "platform" / "windows" / "tray.py").read_text(
        encoding="utf-8"
    )

    assert "from pc_agent.platform.windows.tray_status import" in source
    assert "from .tray_status import" not in source


def test_tray_companion_uses_one_notification_icon_per_user_session() -> None:
    """A repair or upgrade must not leave duplicate icons in the user's tray."""
    source = (Path(__file__).parents[2] / "platform" / "windows" / "tray.py").read_text(
        encoding="utf-8"
    )

    assert 'CreateMutexW(None, False, r"Local\\EndpointAgentTray")' in source
    assert "_ERROR_ALREADY_EXISTS" in source


def test_tray_declares_wide_menu_api_and_opaque_coloured_icon_pixels() -> None:
    """The Windows shell must receive actual text and a visible custom icon."""
    source = (Path(__file__).parents[2] / "platform" / "windows" / "tray.py").read_text(
        encoding="utf-8"
    )

    assert "AppendMenuW.argtypes" in source
    assert "AppendMenuW.restype" in source
    assert "bytes([blue, green, red, 255]" in source


class _FakeWinApi:
    def __init__(self, result: int = 0) -> None:
        self.result = result
        self.calls: list[tuple[object, ...]] = []

    def __call__(self, *args: object) -> int:
        self.calls.append(args)
        return self.result


def test_tray_uses_owner_drawn_status_items_for_visible_text() -> None:
    """Status text must not depend on the shell's broken disabled-text colour."""
    append_menu = _FakeWinApi(result=1)
    user32 = SimpleNamespace(
        CreatePopupMenu=_FakeWinApi(result=1),
        AppendMenuW=append_menu,
        GetCursorPos=_FakeWinApi(result=1),
        SetForegroundWindow=_FakeWinApi(result=1),
        TrackPopupMenu=_FakeWinApi(result=0),
        DestroyMenu=_FakeWinApi(result=1),
    )
    tray = _WindowsTray(Path("C:/ProgramData/Endpoint Platform/Agent"))

    tray._show_menu(user32, 101)  # type: ignore[arg-type]

    status_calls = append_menu.calls[:4]
    assert all(call[1] & 0x0100 for call in status_calls)
    assert [call[3] for call in status_calls] == [None, None, None, None]


def test_tray_spec_is_windowed_companion_executable() -> None:
    source = (Path(__file__).parents[2] / "pyinstaller_windows_tray.spec").read_text(
        encoding="utf-8"
    )

    assert 'name="EndpointAgentTray"' in source
    assert "console=False" in source
