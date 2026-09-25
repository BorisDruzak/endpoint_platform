"""MSI-owned LocalSystem service for fixed Browser Sensor machine policy."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from threading import Event

from pc_agent.platform.windows.browser_policy import (
    APPROVED_UPDATE_URL,
    BrowserPolicyApplicator,
    WindowsPolicyRegistry,
)
from pc_agent.platform.windows.browser_policy_helper import (
    HELPER_SERVICE_NAME,
    authorize_agent_pipe_client,
    create_helper_server_pipe,
    handle_policy_frame,
    publish_helper_identity_acl,
)
from pc_agent.platform.windows.sensor_pipe_listener import LocalSensorPipeListener


def load_packaged_extension_id() -> str:
    """Load the release-pinned public ID from the signed executable bundle."""
    bundle_root = (
        Path(sys._MEIPASS)
        if getattr(sys, "frozen", False)
        else Path(__file__).resolve().parents[3]
    )
    extension_id = (
        (bundle_root / "browser_sensor" / "extension-id.txt")
        .read_text(encoding="ascii")
        .strip()
    )
    if not re.fullmatch(r"[a-p]{32}", extension_id):
        raise ValueError("invalid packaged Browser Sensor identity")
    return extension_id


def make_policy_listener() -> LocalSensorPipeListener:
    applicator = BrowserPolicyApplicator(
        WindowsPolicyRegistry(),
        extension_id=load_packaged_extension_id(),
        update_url=APPROVED_UPDATE_URL,
    )
    return LocalSensorPipeListener(
        lambda handle, payload: handle_policy_frame(
            handle,
            payload,
            applicator,
            authorize=authorize_agent_pipe_client,
        ),
        server_factory=create_helper_server_pipe,
        frame_timeout_seconds=5.0,
    )


def run_browser_policy_service() -> int:
    """Run the fixed helper as its own Windows service, never as Agent child."""
    try:
        import servicemanager  # type: ignore[import-not-found]
        import win32service  # type: ignore[import-not-found]
        import win32serviceutil  # type: ignore[import-not-found]
    except ImportError as error:
        raise RuntimeError("pywin32 is required for Browser Policy service") from error

    publish_helper_identity_acl()

    class BrowserPolicyWindowsService(win32serviceutil.ServiceFramework):
        _svc_name_ = HELPER_SERVICE_NAME
        _svc_display_name_ = "Endpoint Browser Policy"
        _svc_description_ = "Fixed Browser Sensor enterprise policy applicator"

        def __init__(self, args) -> None:
            super().__init__(args)
            self._listener = make_policy_listener()
            self._stop = Event()

        def SvcDoRun(self) -> None:
            self._listener.start()
            try:
                self._stop.wait()
            finally:
                self._listener.stop()

        def SvcStop(self) -> None:
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            self._stop.set()

        def SvcShutdown(self) -> None:
            self.SvcStop()

    servicemanager.Initialize()
    servicemanager.PrepareToHostSingle(BrowserPolicyWindowsService)
    servicemanager.StartServiceCtrlDispatcher()
    return 0


if __name__ == "__main__":
    raise SystemExit(run_browser_policy_service())
