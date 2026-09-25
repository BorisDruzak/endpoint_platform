"""Browser policy writes own only the pinned extension's machine-level entry."""

from __future__ import annotations

import json

import pytest

from pc_agent.platform.windows.browser_policy import (
    CHROME_POLICY_PATH,
    MARKER_PATH,
    YANDEX_POLICY_PATH,
    BrowserPolicyApplicator,
    BrowserPolicyConflict,
    WindowsPolicyRegistry,
)


EXTENSION_ID = "abcdefghijklmnopabcdefghijklmnop"
FOREIGN_ID = "ponmlkjihgfedcbaponmlkjihgfedcba"
UPDATE_URL = "https://endpoint.sosnadmin.local/api/v1/browser-sensor/update.xml"


class MemoryRegistry:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], str] = {}
        self.writes: list[tuple[str, str, str | None]] = []
        self.interfere_at: tuple[str, str] | None = None

    def read(self, path: str, name: str) -> str | None:
        return self.values.get((path, name))

    def values_at(self, path: str) -> dict[str, str]:
        return {
            name: value for (key, name), value in self.values.items() if key == path
        }

    def put(self, path: str, name: str, value: str, *, expected: str | None) -> None:
        key = (path, name)
        if self.interfere_at == key:
            self.values[key] = "externally changed"
            self.interfere_at = None
        if self.values.get(key) != expected:
            raise BrowserPolicyConflict("POLICY_CONFLICT")
        self.values[key] = value
        self.writes.append((path, name, value))

    def remove(self, path: str, name: str, *, expected: str) -> None:
        key = (path, name)
        if self.values.get(key) != expected:
            raise BrowserPolicyConflict("POLICY_CONFLICT")
        del self.values[key]
        self.writes.append((path, name, None))


def _app(registry: MemoryRegistry) -> BrowserPolicyApplicator:
    return BrowserPolicyApplicator(
        registry, extension_id=EXTENSION_ID, update_url=UPDATE_URL
    )


def test_chrome_apply_from_absent_is_repeatable_and_relinquishes_exact_entry() -> None:
    registry = MemoryRegistry()
    applicator = _app(registry)
    assert applicator.apply("chrome") == "APPLIED"
    policy = json.loads(registry.read(CHROME_POLICY_PATH, "ExtensionSettings"))
    assert policy == {
        EXTENSION_ID: {
            "installation_mode": "force_installed",
            "update_url": UPDATE_URL,
        }
    }
    first_writes = list(registry.writes)
    assert applicator.apply("chrome") == "APPLIED"
    assert registry.writes == first_writes
    assert applicator.relinquish("chrome") == "EXTERNALLY_MANAGED"
    assert registry.values_at(CHROME_POLICY_PATH) == {}
    assert registry.values_at(MARKER_PATH) == {}
    assert applicator.relinquish("chrome") == "EXTERNALLY_MANAGED"
    assert len(registry.writes) == len(first_writes) + 2


def test_chrome_never_replaces_unowned_or_malformed_extension_settings() -> None:
    registry = MemoryRegistry()
    registry.values[(CHROME_POLICY_PATH, "ExtensionSettings")] = '{"other":{}}'
    with pytest.raises(BrowserPolicyConflict):
        _app(registry).apply("chrome")
    assert registry.writes == []
    registry.values[(CHROME_POLICY_PATH, "ExtensionSettings")] = "{broken"
    with pytest.raises(BrowserPolicyConflict):
        _app(registry).apply("chrome")
    assert registry.writes == []


def test_direct_external_management_never_writes_browser_or_native_host_policy() -> None:
    registry = MemoryRegistry()
    chrome_policy = {
        EXTENSION_ID: {
            "installation_mode": "force_installed",
            "update_url": UPDATE_URL,
        },
        FOREIGN_ID: {"installation_mode": "allowed"},
    }
    registry.values[(CHROME_POLICY_PATH, "ExtensionSettings")] = json.dumps(chrome_policy)
    registry.values[(YANDEX_POLICY_PATH, "1")] = f"{EXTENSION_ID};{UPDATE_URL}"
    registry.values[(YANDEX_POLICY_PATH, "2")] = (
        f"{FOREIGN_ID};https://example.org/update.xml"
    )
    native_host_path = r"SOFTWARE\Policies\Google\Chrome\NativeMessagingAllowlist"
    registry.values[(native_host_path, "1")] = "com.cryptopro.browser"
    before = dict(registry.values)

    applicator = _app(registry)
    assert applicator.relinquish("chrome") == "EXTERNALLY_MANAGED"
    assert applicator.relinquish("yandex") == "EXTERNALLY_MANAGED"

    assert registry.values == before
    assert registry.writes == []
    assert registry.values_at(MARKER_PATH) == {}


def test_chrome_preserves_foreign_entries_added_after_ownership() -> None:
    registry = MemoryRegistry()
    app = _app(registry)
    app.apply("chrome")
    policy = json.loads(registry.read(CHROME_POLICY_PATH, "ExtensionSettings"))
    policy[FOREIGN_ID] = {"installation_mode": "allowed"}
    registry.values[(CHROME_POLICY_PATH, "ExtensionSettings")] = json.dumps(policy)
    assert app.apply("chrome") == "APPLIED"
    assert app.relinquish("chrome") == "EXTERNALLY_MANAGED"
    assert json.loads(registry.read(CHROME_POLICY_PATH, "ExtensionSettings")) == {
        FOREIGN_ID: {"installation_mode": "allowed"},
    }


def test_chrome_fails_closed_if_owned_entry_changes() -> None:
    registry = MemoryRegistry()
    app = _app(registry)
    app.apply("chrome")
    policy = json.loads(registry.read(CHROME_POLICY_PATH, "ExtensionSettings"))
    policy[EXTENSION_ID]["update_url"] = "https://elsewhere.example/update.xml"
    registry.values[(CHROME_POLICY_PATH, "ExtensionSettings")] = json.dumps(policy)
    before = dict(registry.values)
    with pytest.raises(BrowserPolicyConflict):
        app.relinquish("chrome")
    assert registry.values == before


def test_chrome_detects_change_between_read_and_write() -> None:
    registry = MemoryRegistry()
    registry.interfere_at = (CHROME_POLICY_PATH, "ExtensionSettings")
    with pytest.raises(BrowserPolicyConflict):
        _app(registry).apply("chrome")
    assert (
        registry.read(CHROME_POLICY_PATH, "ExtensionSettings") == "externally changed"
    )


def test_yandex_uses_one_free_number_and_preserves_foreign_entries() -> None:
    registry = MemoryRegistry()
    foreign_value = f"{FOREIGN_ID};https://example.org/update.xml"
    registry.values[(YANDEX_POLICY_PATH, "1")] = foreign_value
    app = _app(registry)
    assert app.apply("yandex") == "APPLIED"
    assert registry.read(YANDEX_POLICY_PATH, "1") == foreign_value
    assert registry.read(YANDEX_POLICY_PATH, "2") == f"{EXTENSION_ID};{UPDATE_URL}"
    writes = list(registry.writes)
    assert app.apply("yandex") == "APPLIED"
    assert registry.writes == writes
    assert app.relinquish("yandex") == "EXTERNALLY_MANAGED"
    assert registry.values_at(YANDEX_POLICY_PATH) == {
        "1": foreign_value,
    }


def test_yandex_rejects_unowned_same_id_and_changed_owned_slot() -> None:
    registry = MemoryRegistry()
    registry.values[(YANDEX_POLICY_PATH, "1")] = f"{EXTENSION_ID};{UPDATE_URL}"
    with pytest.raises(BrowserPolicyConflict):
        _app(registry).apply("yandex")
    assert registry.writes == []
    del registry.values[(YANDEX_POLICY_PATH, "1")]
    app = _app(registry)
    app.apply("yandex")
    registry.values[(YANDEX_POLICY_PATH, "1")] = (
        f"{FOREIGN_ID};https://example.org/update.xml"
    )
    with pytest.raises(BrowserPolicyConflict):
        app.relinquish("yandex")
    assert (
        registry.read(YANDEX_POLICY_PATH, "1")
        == f"{FOREIGN_ID};https://example.org/update.xml"
    )


def test_yandex_rejects_malformed_foreign_list_entry() -> None:
    registry = MemoryRegistry()
    registry.values[(YANDEX_POLICY_PATH, "1")] = "not-an-extension-id"
    with pytest.raises(BrowserPolicyConflict):
        _app(registry).apply("yandex")
    assert registry.writes == []


def test_yandex_rejects_a_preexisting_root_list_value() -> None:
    registry = MemoryRegistry()
    parent = YANDEX_POLICY_PATH.rsplit("\\", 1)[0]
    registry.values[(parent, "ExtensionInstallForcelist")] = (
        '["other;https://example.org"]'
    )
    with pytest.raises(BrowserPolicyConflict):
        _app(registry).apply("yandex")
    assert registry.writes == []


def test_yandex_rejects_extension_settings_that_can_override_forcelist() -> None:
    registry = MemoryRegistry()
    parent = YANDEX_POLICY_PATH.rsplit("\\", 1)[0]
    registry.values[(parent, "ExtensionSettings")] = "{}"
    with pytest.raises(BrowserPolicyConflict):
        _app(registry).apply("yandex")
    assert registry.writes == []


def test_yandex_reports_conflict_when_numbered_list_has_no_free_slot() -> None:
    registry = MemoryRegistry()
    for number in range(1, 1001):
        registry.values[(YANDEX_POLICY_PATH, str(number))] = FOREIGN_ID
    with pytest.raises(BrowserPolicyConflict):
        _app(registry).apply("yandex")
    assert registry.writes == []


def test_retries_policy_creation_after_marker_is_durably_written() -> None:
    registry = MemoryRegistry()
    app = _app(registry)
    registry.interfere_at = (CHROME_POLICY_PATH, "ExtensionSettings")
    with pytest.raises(BrowserPolicyConflict):
        app.apply("chrome")
    assert registry.read(MARKER_PATH, "chrome") is not None
    del registry.values[(CHROME_POLICY_PATH, "ExtensionSettings")]
    assert app.apply("chrome") == "APPLIED"


def test_relinquish_recovers_after_owned_entry_was_already_removed() -> None:
    registry = MemoryRegistry()
    app = _app(registry)
    app.apply("chrome")
    del registry.values[(CHROME_POLICY_PATH, "ExtensionSettings")]
    assert app.relinquish("chrome") == "EXTERNALLY_MANAGED"
    assert registry.values_at(MARKER_PATH) == {}


def test_rejects_unapproved_update_url_before_any_registry_write() -> None:
    registry = MemoryRegistry()
    with pytest.raises(ValueError, match="unapproved"):
        BrowserPolicyApplicator(
            registry,
            extension_id=EXTENSION_ID,
            update_url="https://example.org/update.xml",
        )
    assert registry.writes == []


def test_windows_registry_reads_only_target_value_not_unrelated_dword() -> None:
    class Key:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

    class FakeWinreg:
        HKEY_LOCAL_MACHINE = 1
        KEY_READ = 2
        KEY_WOW64_64KEY = 4
        REG_SZ = 1
        REG_DWORD = 4

        def OpenKey(self, *_):
            return Key()

        def EnumValue(self, _key, index):
            if index == 0:
                return "SomeOtherChromePolicy", 1, self.REG_DWORD
            if index == 1:
                return "ExtensionSettings", "{}", self.REG_SZ
            raise OSError(259, "no more values")

        def QueryValueEx(self, _key, name):
            assert name == "ExtensionSettings"
            return "{}", self.REG_SZ

    registry = object.__new__(WindowsPolicyRegistry)
    registry._winreg = FakeWinreg()
    assert registry.read(CHROME_POLICY_PATH, "ExtensionSettings") == "{}"
