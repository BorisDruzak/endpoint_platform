"""Browser policy writes own only the pinned extension's machine-level entry."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pc_agent.platform.windows.browser_policy import (
    CHROME_POLICY_PATH,
    MARKER_PATH,
    YANDEX_POLICY_PATH,
    BrowserPolicyApplicator,
    BrowserPolicyConflict,
    WindowsPolicyRegistry,
    YandexPolicyFile,
)


EXTENSION_ID = "abcdefghijklmnopabcdefghijklmnop"
FOREIGN_ID = "ponmlkjihgfedcbaponmlkjihgfedcba"
UPDATE_URL = "https://endpoint.sosnadmin.local/api/v1/browser-sensor/update.xml"


class MemoryRegistry:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], str] = {}
        self.writes: list[tuple[str, str, str | None]] = []
        self.interfere_at: tuple[str, str] | None = None
        self.policy_file = MemoryPolicyFile()

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


class MemoryPolicyFile:
    path = Path("C:/Program Files/Endpoint Platform/Agent/yandex-forcelist.json")

    def __init__(self) -> None:
        self.content: str | None = None
        self.writes: list[str | None] = []

    def read(self) -> str | None:
        return self.content

    def put(self, value: str, *, expected: str | None) -> None:
        if self.content != expected:
            raise BrowserPolicyConflict("POLICY_CONFLICT")
        self.content = value
        self.writes.append(value)

    def remove(self, *, expected: str) -> None:
        if self.content != expected:
            raise BrowserPolicyConflict("POLICY_CONFLICT")
        self.content = None
        self.writes.append(None)


def _app(registry: MemoryRegistry) -> BrowserPolicyApplicator:
    return BrowserPolicyApplicator(
        registry, extension_id=EXTENSION_ID, update_url=UPDATE_URL,
        yandex_file=registry.policy_file,
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


def test_yandex_file_policy_applies_idempotently_and_relinquishes() -> None:
    registry = MemoryRegistry()
    app = _app(registry)
    assert app.apply("yandex") == "APPLIED"
    parent = YANDEX_POLICY_PATH.rsplit("\\", 1)[0]
    pointer = registry.read(parent, "ExtensionInstallForcelist")
    assert json.loads(pointer) == [{"_FILE_": {"name": registry.policy_file.path.as_posix()}}]
    assert json.loads(registry.policy_file.read()) == [f"{EXTENSION_ID};{UPDATE_URL}"]
    assert registry.values_at(YANDEX_POLICY_PATH) == {}
    writes = list(registry.writes)
    file_writes = list(registry.policy_file.writes)
    assert app.apply("yandex") == "APPLIED"
    assert registry.writes == writes
    assert registry.policy_file.writes == file_writes
    assert app.relinquish("yandex") == "EXTERNALLY_MANAGED"
    assert registry.read(parent, "ExtensionInstallForcelist") is None
    assert registry.policy_file.read() is None
    assert registry.values_at(MARKER_PATH) == {}


def test_yandex_rejects_foreign_numbered_entries_without_writes() -> None:
    registry = MemoryRegistry()
    registry.values[(YANDEX_POLICY_PATH, "1")] = (
        f"{FOREIGN_ID};https://example.org/update.xml"
    )
    with pytest.raises(BrowserPolicyConflict):
        _app(registry).apply("yandex")
    assert registry.writes == []
    assert registry.policy_file.writes == []


def test_yandex_migrates_only_its_legacy_numbered_entry() -> None:
    registry = MemoryRegistry()
    old = f"{EXTENSION_ID};{UPDATE_URL}"
    registry.values[(YANDEX_POLICY_PATH, "1")] = old
    registry.values[(MARKER_PATH, "yandex")] = json.dumps({
        "schema_version": 1, "extension_id": EXTENSION_ID,
        "update_url": UPDATE_URL, "slot": "1",
    })
    app = _app(registry)
    assert app.apply("yandex") == "APPLIED"
    assert registry.values_at(YANDEX_POLICY_PATH) == {}
    assert json.loads(registry.policy_file.read()) == [old]
    assert json.loads(registry.read(MARKER_PATH, "yandex"))["slot"] == "file"
    assert registry.writes.index((YANDEX_POLICY_PATH, "1", None)) < next(
        index for index, write in enumerate(registry.writes)
        if write[:2] == (YANDEX_POLICY_PATH.rsplit("\\", 1)[0], "ExtensionInstallForcelist")
    )
    assert app.relinquish("yandex") == "EXTERNALLY_MANAGED"
    assert registry.values_at(MARKER_PATH) == {}


def test_yandex_resumes_migration_after_owned_slot_removal() -> None:
    registry = MemoryRegistry()
    registry.values[(MARKER_PATH, "yandex")] = json.dumps({
        "schema_version": 1, "extension_id": EXTENSION_ID,
        "update_url": UPDATE_URL, "slot": "1",
    })
    registry.policy_file.content = json.dumps([f"{EXTENSION_ID};{UPDATE_URL}"],
                                              separators=(",", ":"))
    assert _app(registry).apply("yandex") == "APPLIED"
    assert json.loads(registry.read(MARKER_PATH, "yandex"))["slot"] == "file"


def test_yandex_rejects_tampered_owned_file_on_relinquish() -> None:
    registry = MemoryRegistry()
    app = _app(registry)
    app.apply("yandex")
    registry.policy_file.content = json.dumps([f"{FOREIGN_ID};{UPDATE_URL}"])
    before = dict(registry.values)
    with pytest.raises(BrowserPolicyConflict):
        app.relinquish("yandex")
    assert registry.values == before


def test_yandex_retries_after_registry_interference_without_clobbering_it() -> None:
    registry = MemoryRegistry()
    parent = YANDEX_POLICY_PATH.rsplit("\\", 1)[0]
    registry.interfere_at = (parent, "ExtensionInstallForcelist")
    app = _app(registry)
    with pytest.raises(BrowserPolicyConflict):
        app.apply("yandex")
    assert registry.read(parent, "ExtensionInstallForcelist") == "externally changed"
    assert registry.policy_file.read() is not None
    del registry.values[(parent, "ExtensionInstallForcelist")]
    assert app.apply("yandex") == "APPLIED"


def test_yandex_policy_file_rejects_external_change_before_cleanup(tmp_path: Path) -> None:
    policy_file = YandexPolicyFile(tmp_path / "yandex-forcelist.json")
    policy_file.put('["owned"]', expected=None)
    assert policy_file.read() == '["owned"]'
    policy_file.path.write_text('["other"]', encoding="utf-8")
    with pytest.raises(BrowserPolicyConflict):
        policy_file.remove(expected='["owned"]')
    assert policy_file.read() == '["other"]'


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
