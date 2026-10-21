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
    verified = {}
    _assert_installer_allows_policy(verified)
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
            authorize=lambda handle: _authorize_installer_safe_client(handle, verified),
        ),
        server_factory=create_helper_server_pipe,
        frame_timeout_seconds=5.0,
    )


def _assert_installer_allows_policy(verified=None) -> None:
    from pc_agent.platform.windows.installer_fence import assert_launch_allowed
    from pc_agent.platform.windows.update_paths import WindowsUpdatePaths
    paths = WindowsUpdatePaths.production()
    assert_launch_allowed(paths)
    from pc_agent.platform.windows.staged_update_state import read_staged_update
    record = read_staged_update(paths)
    if record is not None and record.phase not in {'accepted', 'rolled-back'}:
        if record.phase not in {'preparing', 'prepared', 'trial'}:
            from pc_agent.platform.windows.update_transaction import UpdateInProgress
            raise UpdateInProgress('STAGED_UPDATE_IN_PROGRESS')
        from pc_agent.platform.windows.service_launcher import _verify_selected_runtime
        from pc_agent.platform.windows.staged_update_state import assert_staged_update_allowed
        from pc_agent.platform.windows.installer_fence import assert_state_security
        import json
        assert_state_security(paths.current_path)
        raw = paths.current_path.read_bytes()
        key = (record.binding, raw)
        # Core payloads are protected from service writes. Validate the full tree
        # once per exact binding/selection in this service lifetime; repeating it
        # inside the five-second pipe request makes every trial policy time out.
        if verified is None or verified.get('key') != key:
            _verify_selected_runtime(paths, json.loads(raw))
            if verified is not None:
                verified['key'] = key
        tree = (record.binding.candidate_tree_sha256 if record.phase == 'trial'
                else record.binding.selected_tree_sha256_before)
        assert_staged_update_allowed(paths, purpose='launch', runtime_tree_sha256=tree)
    elif verified is not None:
        verified.clear()


def _authorize_installer_safe_client(handle, verified=None) -> None:
    authorize_agent_pipe_client(handle)
    _assert_installer_allows_policy(verified)


def run_browser_policy_service() -> int:
    """Run the fixed helper as its own Windows service, never as Agent child."""
    try:
        import servicemanager  # type: ignore[import-not-found]
        import win32service  # type: ignore[import-not-found]
        import win32serviceutil  # type: ignore[import-not-found]
    except ImportError as error:
        raise RuntimeError("pywin32 is required for Browser Policy service") from error

    _assert_installer_allows_policy()
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
