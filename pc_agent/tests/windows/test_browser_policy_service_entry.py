"""The privileged browser-policy service loads one packaged extension ID."""

from __future__ import annotations

import json
import runpy
import sys
from pathlib import Path

from pc_agent.platform.windows.browser_policy import CHROME_POLICY_PATH
from pc_agent.platform.windows.browser_policy_service_entry import (
    load_packaged_extension_id,
    make_policy_listener,
)
from pc_agent.tests.windows.test_browser_policy import EXTENSION_ID, MemoryRegistry


def test_service_entry_imports_when_run_as_frozen_main_script() -> None:
    """PyInstaller executes its Analysis script without a package context."""
    entry = Path(__file__).resolve().parents[2] / "platform/windows/browser_policy_service_entry.py"
    namespace = runpy.run_path(str(entry), run_name="frozen_main_import_smoke")
    assert callable(namespace["run_browser_policy_service"])


def test_service_entry_loads_only_packaged_extension_identity(
    monkeypatch, tmp_path
) -> None:
    bundle = tmp_path / "bundle"
    identity = bundle / "browser_sensor" / "extension-id.txt"
    identity.parent.mkdir(parents=True)
    identity.write_text(EXTENSION_ID, encoding="ascii")
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", str(bundle), raising=False)
    assert load_packaged_extension_id() == EXTENSION_ID
    identity.write_text("malformed", encoding="ascii")
    try:
        load_packaged_extension_id()
    except ValueError:
        pass
    else:
        raise AssertionError("malformed packaged extension identity accepted")


def test_service_listener_authenticates_then_applies_only_packaged_id(
    monkeypatch,
) -> None:
    registry = MemoryRegistry()
    calls: list[str] = []
    monkeypatch.setattr(
        "pc_agent.platform.windows.browser_policy_service_entry.WindowsPolicyRegistry",
        lambda: registry,
    )
    monkeypatch.setattr(
        "pc_agent.platform.windows.browser_policy_service_entry.load_packaged_extension_id",
        lambda: EXTENSION_ID,
    )
    monkeypatch.setattr(
        "pc_agent.platform.windows.browser_policy_service_entry.authorize_agent_pipe_client",
        lambda _handle: calls.append("authorized"),
    )
    listener = make_policy_listener()
    reply = listener._on_frame(
        object(),
        b'{"schema_version":"endpoint_browser_policy_request_v1","operation":"apply","browser_family":"chrome"}',
    )
    assert calls == ["authorized"]
    assert json.loads(reply)["status"] == "APPLIED"
    assert EXTENSION_ID in json.loads(
        registry.read(CHROME_POLICY_PATH, "ExtensionSettings")
    )


def test_service_listener_places_yandex_file_beside_helper(
    monkeypatch, tmp_path: Path,
) -> None:
    registry = MemoryRegistry()
    monkeypatch.setattr(sys, "executable", str(tmp_path / "EndpointBrowserPolicy.exe"))
    monkeypatch.setattr(
        "pc_agent.platform.windows.browser_policy_service_entry.WindowsPolicyRegistry",
        lambda: registry,
    )
    monkeypatch.setattr(
        "pc_agent.platform.windows.browser_policy_service_entry.load_packaged_extension_id",
        lambda: EXTENSION_ID,
    )
    monkeypatch.setattr(
        "pc_agent.platform.windows.browser_policy_service_entry.authorize_agent_pipe_client",
        lambda _handle: None,
    )
    listener = make_policy_listener()
    reply = listener._on_frame(
        object(),
        b'{"schema_version":"endpoint_browser_policy_request_v1","operation":"apply","browser_family":"yandex"}',
    )
    assert json.loads(reply)["status"] == "APPLIED"
    assert json.loads((tmp_path / "yandex-forcelist.json").read_text(encoding="utf-8")) == [
        EXTENSION_ID + ";https://endpoint.sosnadmin.local/api/v1/browser-sensor/update.xml"
    ]
