"""Fixed machine-policy changes for the Endpoint Browser Sensor extension.

This module is intended for the MSI-owned privileged helper, not the
LocalService Agent or an interactive user process. The helper supplies the
packaged extension identity and exposes only typed apply/relinquish actions.
"""

from __future__ import annotations

import json
import os
import re
from typing import Literal, Protocol


CHROME_POLICY_PATH = r"SOFTWARE\Policies\Google\Chrome"
YANDEX_POLICY_PATH = r"SOFTWARE\Policies\YandexBrowser\ExtensionInstallForcelist"
_YANDEX_ROOT_PATH = r"SOFTWARE\Policies\YandexBrowser"
MARKER_PATH = r"SOFTWARE\Endpoint Platform\Agent\BrowserPolicy"
APPROVED_UPDATE_URL = (
    "https://endpoint.sosnadmin.local/api/v1/browser-sensor/update.xml"
)
_CHROME_VALUE = "ExtensionSettings"
_MAX_POLICY_BYTES = 256 * 1024
BrowserFamily = Literal["chrome", "yandex"]


class BrowserPolicyConflict(RuntimeError):
    """A machine policy value cannot be safely changed by this Agent."""


class PolicyRegistry(Protocol):
    def read(self, path: str, name: str) -> str | None: ...

    def values_at(self, path: str) -> dict[str, str]: ...

    def put(
        self, path: str, name: str, value: str, *, expected: str | None
    ) -> None: ...

    def remove(self, path: str, name: str, *, expected: str) -> None: ...


class WindowsPolicyRegistry:
    """Read and write only 64-bit HKLM REG_SZ values with a pre-write check."""

    def __init__(self) -> None:
        if os.name != "nt":
            raise RuntimeError("Windows machine policy requires Windows")
        import winreg

        self._winreg = winreg

    def values_at(self, path: str) -> dict[str, str]:
        reg = self._winreg
        try:
            key = reg.OpenKey(
                reg.HKEY_LOCAL_MACHINE, path, 0, reg.KEY_READ | reg.KEY_WOW64_64KEY
            )
        except FileNotFoundError:
            return {}
        with key:
            values: dict[str, str] = {}
            index = 0
            while True:
                try:
                    name, value, kind = reg.EnumValue(key, index)
                except OSError as error:
                    if getattr(error, "winerror", None) == 259:
                        break
                    raise
                if kind != reg.REG_SZ or not isinstance(value, str):
                    raise BrowserPolicyConflict("POLICY_CONFLICT")
                values[name] = value
                index += 1
            return values

    def read(self, path: str, name: str) -> str | None:
        reg = self._winreg
        try:
            with reg.OpenKey(
                reg.HKEY_LOCAL_MACHINE, path, 0, reg.KEY_READ | reg.KEY_WOW64_64KEY
            ) as key:
                value, kind = reg.QueryValueEx(key, name)
        except FileNotFoundError:
            return None
        if kind != reg.REG_SZ or not isinstance(value, str):
            raise BrowserPolicyConflict("POLICY_CONFLICT")
        return value

    def put(self, path: str, name: str, value: str, *, expected: str | None) -> None:
        if self.read(path, name) != expected:
            raise BrowserPolicyConflict("POLICY_CONFLICT")
        reg = self._winreg
        with reg.CreateKeyEx(
            reg.HKEY_LOCAL_MACHINE, path, 0, reg.KEY_SET_VALUE | reg.KEY_WOW64_64KEY
        ) as key:
            reg.SetValueEx(key, name, 0, reg.REG_SZ, value)

    def remove(self, path: str, name: str, *, expected: str) -> None:
        if self.read(path, name) != expected:
            raise BrowserPolicyConflict("POLICY_CONFLICT")
        reg = self._winreg
        with reg.OpenKey(
            reg.HKEY_LOCAL_MACHINE, path, 0, reg.KEY_SET_VALUE | reg.KEY_WOW64_64KEY
        ) as key:
            reg.DeleteValue(key, name)


def _parse_chrome(raw: str) -> dict[str, object]:
    if len(raw.encode("utf-8")) > _MAX_POLICY_BYTES:
        raise BrowserPolicyConflict("POLICY_CONFLICT")
    try:
        parsed = json.loads(raw)
    except (ValueError, TypeError) as error:
        raise BrowserPolicyConflict("POLICY_CONFLICT") from error
    if not isinstance(parsed, dict) or any(
        not isinstance(key, str) or not isinstance(value, dict)
        for key, value in parsed.items()
    ):
        raise BrowserPolicyConflict("POLICY_CONFLICT")
    return parsed


def _serialize(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


class BrowserPolicyApplicator:
    """Own only the pinned extension entry; preserve all other policy values."""

    def __init__(
        self,
        registry: PolicyRegistry,
        *,
        extension_id: str,
        update_url: str,
    ) -> None:
        if not re.fullmatch(r"[a-p]{32}", extension_id):
            raise ValueError("invalid packaged Browser Sensor identity")
        if update_url != APPROVED_UPDATE_URL:
            raise ValueError("unapproved Browser Sensor update URL")
        self._registry = registry
        self._extension_id = extension_id
        self._update_url = update_url

    def _entry(self) -> dict[str, str]:
        return {"installation_mode": "force_installed", "update_url": self._update_url}

    def _marker(self, slot: str | None) -> str:
        return _serialize(
            {
                "schema_version": 1,
                "extension_id": self._extension_id,
                "update_url": self._update_url,
                "slot": slot,
            }
        )

    def _read_marker(self, family: BrowserFamily) -> tuple[str | None, str | None]:
        raw = self._registry.read(MARKER_PATH, family)
        if raw is None:
            return None, None
        try:
            value = json.loads(raw)
        except (TypeError, ValueError) as error:
            raise BrowserPolicyConflict("POLICY_CONFLICT") from error
        if (
            not isinstance(value, dict)
            or set(value)
            != {
                "schema_version",
                "extension_id",
                "update_url",
                "slot",
            }
            or value["schema_version"] != 1
            or value["extension_id"] != self._extension_id
            or value["update_url"] != self._update_url
        ):
            raise BrowserPolicyConflict("POLICY_CONFLICT")
        slot = value["slot"]
        if family == "chrome" and slot is not None:
            raise BrowserPolicyConflict("POLICY_CONFLICT")
        if family == "yandex" and (
            not isinstance(slot, str)
            or not slot.isdecimal()
            or not 1 <= int(slot) <= 1000
            or str(int(slot)) != slot
        ):
            raise BrowserPolicyConflict("POLICY_CONFLICT")
        return raw, slot

    def apply(self, family: BrowserFamily) -> str:
        if family == "chrome":
            return self._apply_chrome()
        if family == "yandex":
            return self._apply_yandex()
        raise ValueError("unsupported browser family")

    def relinquish(self, family: BrowserFamily) -> str:
        if family == "chrome":
            return self._relinquish_chrome()
        if family == "yandex":
            return self._relinquish_yandex()
        raise ValueError("unsupported browser family")

    def _apply_chrome(self) -> str:
        marker, _ = self._read_marker("chrome")
        raw = self._registry.read(CHROME_POLICY_PATH, _CHROME_VALUE)
        if marker is None:
            if raw is not None:
                raise BrowserPolicyConflict("POLICY_CONFLICT")
            self._registry.put(MARKER_PATH, "chrome", self._marker(None), expected=None)
        if raw is None:
            self._registry.put(
                CHROME_POLICY_PATH,
                _CHROME_VALUE,
                _serialize({self._extension_id: self._entry()}),
                expected=None,
            )
            return "APPLIED"
        policy = _parse_chrome(raw)
        if policy.get(self._extension_id) != self._entry():
            raise BrowserPolicyConflict("POLICY_CONFLICT")
        return "APPLIED"

    def _relinquish_chrome(self) -> str:
        marker, _ = self._read_marker("chrome")
        if marker is None:
            return "EXTERNALLY_MANAGED"
        raw = self._registry.read(CHROME_POLICY_PATH, _CHROME_VALUE)
        if raw is not None:
            policy = _parse_chrome(raw)
            owned = policy.get(self._extension_id)
            if owned is not None and owned != self._entry():
                raise BrowserPolicyConflict("POLICY_CONFLICT")
            if owned is not None:
                del policy[self._extension_id]
                if policy:
                    self._registry.put(
                        CHROME_POLICY_PATH,
                        _CHROME_VALUE,
                        _serialize(policy),
                        expected=raw,
                    )
                else:
                    self._registry.remove(
                        CHROME_POLICY_PATH, _CHROME_VALUE, expected=raw
                    )
        self._registry.remove(MARKER_PATH, "chrome", expected=marker)
        return "EXTERNALLY_MANAGED"

    def _apply_yandex(self) -> str:
        self._check_yandex_conflicting_policy()
        marker, slot = self._read_marker("yandex")
        values = self._registry.values_at(YANDEX_POLICY_PATH)
        self._validate_yandex_values(values)
        entry = f"{self._extension_id};{self._update_url}"
        if marker is None:
            if any(
                value.split(";", 1)[0] == self._extension_id
                for value in values.values()
            ):
                raise BrowserPolicyConflict("POLICY_CONFLICT")
            next_slot = next(
                (number for number in range(1, 1001) if str(number) not in values), None
            )
            if next_slot is None:
                raise BrowserPolicyConflict("POLICY_CONFLICT")
            slot = str(next_slot)
            self._registry.put(MARKER_PATH, "yandex", self._marker(slot), expected=None)
        assert slot is not None
        current = values.get(slot)
        if current is None:
            self._registry.put(YANDEX_POLICY_PATH, slot, entry, expected=None)
        elif current != entry:
            raise BrowserPolicyConflict("POLICY_CONFLICT")
        return "APPLIED"

    def _relinquish_yandex(self) -> str:
        marker, slot = self._read_marker("yandex")
        if marker is None:
            return "EXTERNALLY_MANAGED"
        self._check_yandex_conflicting_policy()
        assert slot is not None
        current = self._registry.read(YANDEX_POLICY_PATH, slot)
        if current is not None:
            if current != f"{self._extension_id};{self._update_url}":
                raise BrowserPolicyConflict("POLICY_CONFLICT")
            self._registry.remove(YANDEX_POLICY_PATH, slot, expected=current)
        self._registry.remove(MARKER_PATH, "yandex", expected=marker)
        return "EXTERNALLY_MANAGED"

    def _check_yandex_conflicting_policy(self) -> None:
        if any(
            self._registry.read(_YANDEX_ROOT_PATH, name) is not None
            for name in ("ExtensionInstallForcelist", "ExtensionSettings")
        ):
            raise BrowserPolicyConflict("POLICY_CONFLICT")

    @staticmethod
    def _validate_yandex_values(values: dict[str, str]) -> None:
        for slot, entry in values.items():
            if (
                not slot.isdecimal()
                or not 1 <= int(slot) <= 1000
                or str(int(slot)) != slot
            ):
                raise BrowserPolicyConflict("POLICY_CONFLICT")
            if len(entry.encode("utf-8")) > 4096 or "\n" in entry or "\r" in entry:
                raise BrowserPolicyConflict("POLICY_CONFLICT")
            extension_id, separator, update_url = entry.partition(";")
            if not re.fullmatch(r"[a-p]{32}", extension_id) or (
                separator and not update_url
            ):
                raise BrowserPolicyConflict("POLICY_CONFLICT")
