"""Browser status is a read-only, per-family projection of local facts."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from endpoint_contracts.endpoint_policy import EndpointPolicyV1
from pc_agent.platform.windows.activity_api import BrowserHeartbeatFact
from pc_agent.platform.windows.browser_policy import (
    APPROVED_UPDATE_URL, CHROME_POLICY_PATH, MARKER_PATH, YANDEX_POLICY_PATH,
)
from pc_agent.platform.windows.browser_status import (
    BrowserHostFacts, WindowsBrowserProbe, build_browser_status_report,
    inspect_browser_policy,
)
from tests.contracts.test_endpoint_policy_v1 import _policy


EXTENSION_ID = "a" * 32
NOW = datetime(2026, 9, 25, 12, tzinfo=UTC)


class Registry:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], str] = {}

    def read(self, path: str, name: str) -> str | None:
        return self.values.get((path, name))

    def values_at(self, path: str) -> dict[str, str]:
        return {name: value for (key, name), value in self.values.items() if key == path}


def _marker(slot: str | None) -> str:
    return json.dumps({
        "schema_version": 1, "extension_id": EXTENSION_ID,
        "update_url": APPROVED_UPDATE_URL, "slot": slot,
    })


def _policy_entry() -> dict[str, str]:
    return {"installation_mode": "force_installed", "update_url": APPROVED_UPDATE_URL}


def test_chrome_policy_inspection_distinguishes_external_owner_and_conflict() -> None:
    registry = Registry()
    assert inspect_browser_policy(registry, "chrome", EXTENSION_ID) == (
        "NONE", "NOT_APPLIED",
    )
    registry.values[(CHROME_POLICY_PATH, "ExtensionSettings")] = json.dumps({
        EXTENSION_ID: _policy_entry(), "b" * 32: {"installation_mode": "allowed"},
    })
    assert inspect_browser_policy(registry, "chrome", EXTENSION_ID) == (
        "EXTERNAL", "APPLIED",
    )
    registry.values[(CHROME_POLICY_PATH, "ExtensionSettings")] = json.dumps({
        EXTENSION_ID: {**_policy_entry(), "toolbar_pin": "force_pinned"},
    })
    assert inspect_browser_policy(registry, "chrome", EXTENSION_ID) == (
        "EXTERNAL", "APPLIED",
    )
    registry.values[(MARKER_PATH, "chrome")] = _marker(None)
    assert inspect_browser_policy(registry, "chrome", EXTENSION_ID) == (
        "CONFLICT", "CONFLICT",
    )
    registry.values[(CHROME_POLICY_PATH, "ExtensionSettings")] = json.dumps({
        EXTENSION_ID: _policy_entry(),
    })
    assert inspect_browser_policy(registry, "chrome", EXTENSION_ID) == (
        "ENDPOINT", "APPLIED",
    )
    registry.values[(CHROME_POLICY_PATH, "ExtensionSettings")] = json.dumps({
        EXTENSION_ID: {"installation_mode": "allowed"},
    })
    assert inspect_browser_policy(registry, "chrome", EXTENSION_ID) == (
        "CONFLICT", "CONFLICT",
    )


def test_yandex_policy_inspection_keeps_its_own_slot_and_foreign_values() -> None:
    registry = Registry()
    registry.values[(YANDEX_POLICY_PATH, "1")] = "b" * 32 + ";https://foreign.example"
    assert inspect_browser_policy(registry, "yandex", EXTENSION_ID) == (
        "NONE", "NOT_APPLIED",
    )
    registry.values[(YANDEX_POLICY_PATH, "2")] = (
        EXTENSION_ID + ";" + APPROVED_UPDATE_URL
    )
    assert inspect_browser_policy(registry, "yandex", EXTENSION_ID) == (
        "EXTERNAL", "APPLIED",
    )
    registry.values[(MARKER_PATH, "yandex")] = _marker("2")
    assert inspect_browser_policy(registry, "yandex", EXTENSION_ID) == (
        "ENDPOINT", "APPLIED",
    )
    registry.values[(YANDEX_POLICY_PATH, "2")] = EXTENSION_ID + ";https://wrong.example"
    assert inspect_browser_policy(registry, "yandex", EXTENSION_ID) == (
        "CONFLICT", "CONFLICT",
    )


def test_yandex_external_extension_settings_is_recognized_without_agent_marker() -> None:
    registry = Registry()
    settings_path = r"SOFTWARE\Policies\YandexBrowser"
    registry.values[(settings_path, "ExtensionSettings")] = json.dumps({
        EXTENSION_ID: {**_policy_entry(), "toolbar_pin": "force_pinned"},
    })
    assert inspect_browser_policy(registry, "yandex", EXTENSION_ID) == (
        "EXTERNAL", "APPLIED",
    )
    registry.values[(MARKER_PATH, "yandex")] = _marker("2")
    assert inspect_browser_policy(registry, "yandex", EXTENSION_ID) == (
        "CONFLICT", "CONFLICT",
    )


def test_report_keeps_browser_and_heartbeat_facts_separate() -> None:
    policy = EndpointPolicyV1.model_validate(_policy())
    report = build_browser_status_report(
        policy,
        {
            "chrome": BrowserHostFacts(
                browser_state="DETECTED", running_state="RUNNING",
                policy_owner="ENDPOINT", installation_policy_state="APPLIED",
                native_host_state="READY", last_running_at=NOW,
            ),
            "yandex": BrowserHostFacts(
                browser_state="UNKNOWN", running_state="UNKNOWN",
                policy_owner="NONE", installation_policy_state="NOT_APPLIED",
                native_host_state="MISSING", last_running_at=None,
            ),
        },
        {"chrome": BrowserHeartbeatFact("0.1.0", NOW - timedelta(minutes=1))},
        observed_at=NOW,
    )
    assert report.policy_id == policy.policy_id
    assert report.browsers[0].browser_family == "chrome"
    assert report.browsers[0].extension_last_seen_at == NOW - timedelta(minutes=1)
    assert report.browsers[1].browser_family == "yandex"
    assert report.browsers[1].extension_version is None
    assert "origin" not in report.model_dump_json()


def test_windows_probe_verifies_registered_binaries_and_native_bridge(tmp_path) -> None:
    registry = Registry()
    chrome = tmp_path / "Google" / "Chrome" / "Application" / "chrome.exe"
    yandex = tmp_path / "Yandex" / "YandexBrowser" / "Application" / "browser.exe"
    chrome.parent.mkdir(parents=True)
    yandex.parent.mkdir(parents=True)
    chrome.write_bytes(b"test")
    yandex.write_bytes(b"test")
    bridge = tmp_path / "EndpointBrowserBridge.exe"
    bridge.write_bytes(b"test")
    manifest = tmp_path / "ru.sosnadmin.endpoint.browser.json"
    manifest.write_text(json.dumps({
        "name": "ru.sosnadmin.endpoint.browser", "type": "stdio",
        "path": "EndpointBrowserBridge.exe",
        "allowed_origins": [f"chrome-extension://{EXTENSION_ID}/"],
    }), encoding="utf-8")
    app_paths = r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths"
    registry.values[(app_paths + r"\chrome.exe", "")] = str(chrome)
    registry.values[(app_paths + r"\browser.exe", "")] = str(yandex)
    registry.values[(
        r"SOFTWARE\Google\Chrome\NativeMessagingHosts\ru.sosnadmin.endpoint.browser", "",
    )] = str(manifest)
    registry.values[(
        r"SOFTWARE\Chromium\NativeMessagingHosts\ru.sosnadmin.endpoint.browser", "",
    )] = str(manifest)
    registry.values[(CHROME_POLICY_PATH, "ExtensionSettings")] = json.dumps({
        EXTENSION_ID: _policy_entry(),
    })
    registry.values[(MARKER_PATH, "chrome")] = _marker(None)

    class Process:
        info = {"name": "chrome.exe", "exe": str(chrome)}

    probe = WindowsBrowserProbe(
        registry=registry, install_root=tmp_path, extension_id=EXTENSION_ID,
        process_iter=lambda **_kw: [Process()],
    )
    facts = probe.collect(observed_at=NOW)
    assert facts["chrome"] == BrowserHostFacts(
        browser_state="DETECTED", running_state="RUNNING",
        policy_owner="ENDPOINT", installation_policy_state="APPLIED",
        native_host_state="READY", last_running_at=NOW,
    )
    assert facts["yandex"].browser_state == "DETECTED"
    assert facts["yandex"].running_state == "CLOSED"
    assert facts["yandex"].native_host_state == "READY"
    assert facts["yandex"].last_running_at is None
    manifest.write_text(json.dumps({
        "name": "ru.sosnadmin.endpoint.browser", "type": "stdio",
        "path": "EndpointBrowserBridge.exe",
        "allowed_origins": ["chrome-extension://" + "b" * 32 + "/"],
    }), encoding="utf-8")
    rejected = probe.collect(observed_at=NOW)
    assert rejected["chrome"].native_host_state == "MISSING"
    assert rejected["yandex"].native_host_state == "MISSING"


def test_windows_probe_reports_unknown_when_browser_installation_is_unregistered(tmp_path) -> None:
    probe = WindowsBrowserProbe(
        registry=Registry(), install_root=tmp_path, extension_id=EXTENSION_ID,
        process_iter=lambda **_kw: [],
    )
    facts = probe.collect(observed_at=NOW)
    assert facts["chrome"].browser_state == "UNKNOWN"
    assert facts["chrome"].running_state == "UNKNOWN"
    assert facts["chrome"].native_host_state == "MISSING"
    assert facts["yandex"].browser_state == "UNKNOWN"


def test_stale_app_path_does_not_prove_browser_absent(tmp_path) -> None:
    registry = Registry()
    registry.values[(
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe", "",
    )] = str(tmp_path / "missing" / "chrome.exe")
    probe = WindowsBrowserProbe(
        registry=registry, install_root=tmp_path, extension_id=EXTENSION_ID,
        process_iter=lambda **_kw: [],
    )
    facts = probe.collect(observed_at=NOW)
    assert facts["chrome"].browser_state == "UNKNOWN"
    assert facts["chrome"].running_state == "UNKNOWN"


def test_unrelated_binary_named_chrome_is_not_reported_as_browser(tmp_path) -> None:
    executable = tmp_path / "Unrelated" / "chrome.exe"
    executable.parent.mkdir()
    executable.write_bytes(b"test")
    registry = Registry()
    registry.values[(
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe", "",
    )] = str(executable)
    probe = WindowsBrowserProbe(
        registry=registry, install_root=tmp_path, extension_id=EXTENSION_ID,
        process_iter=lambda **_kw: [],
    )
    assert probe.collect(observed_at=NOW)["chrome"].browser_state == "UNKNOWN"
