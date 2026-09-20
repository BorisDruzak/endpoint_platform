"""Unit tests for the unprivileged Windows tray companion."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from pc_agent.platform.windows.tray import status_to_view
from pc_agent.platform.windows.tray_status import TrayStatus


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
    assert view.tooltip == "Endpoint Agent: error; Endpoint: connected; Update: failed"


def test_pending_precedes_fresh_connected_icon() -> None:
    view = status_to_view(_status(update_state="applying"), NOW)

    assert view.icon == "blue"
    assert view.tooltip == "Endpoint Agent: running; Endpoint: connected; Update: applying"


def test_connected_running_agent_is_green_with_exact_status_labels() -> None:
    view = status_to_view(_status(), NOW)

    assert view.icon == "green"
    assert view.menu_labels == (
        "Endpoint Agent: running",
        "Endpoint: connected",
        "Update: up_to_date",
    )


def test_running_disconnected_agent_is_yellow() -> None:
    assert status_to_view(_status(endpoint_state="disconnected"), NOW).icon == "yellow"


def test_missing_or_invalid_projection_is_grey() -> None:
    view = status_to_view(None, NOW)

    assert view.icon == "grey"
    assert view.tooltip == "Endpoint Agent: unknown; Endpoint: unknown; Update: unknown"


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


def test_tray_spec_is_windowed_companion_executable() -> None:
    source = (Path(__file__).parents[2] / "pyinstaller_windows_tray.spec").read_text(
        encoding="utf-8"
    )

    assert 'name="EndpointAgentTray"' in source
    assert "console=False" in source
