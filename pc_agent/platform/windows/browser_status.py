"""Read-only browser policy facts and bounded Gateway status projection."""

from __future__ import annotations

import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Callable, Iterable, Literal, Protocol

import psutil

from pc_agent.browser_status import (
    BrowserHostFacts, BrowserStatusRuntime, build_browser_status_report,
    BrowserFamily, PolicyOwner, PolicyState,
)
from .browser_policy import (
    APPROVED_UPDATE_URL, CHROME_POLICY_PATH, MARKER_PATH, YANDEX_POLICY_PATH,
    BrowserPolicyConflict,
)


_YANDEX_ROOT_PATH = r"SOFTWARE\Policies\YandexBrowser"
_MAX_CHROME_POLICY_BYTES = 256 * 1024
_APP_PATHS = r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths"
_NATIVE_HOST = "ru.sosnadmin.endpoint.browser"
_PROCESS_NAMES = {"chrome": "chrome.exe", "yandex": "browser.exe"}
_VENDOR_SUFFIX = {
    "chrome": ("google", "chrome", "application", "chrome.exe"),
    "yandex": ("yandex", "yandexbrowser", "application", "browser.exe"),
}
_NATIVE_KEYS = {
    "chrome": rf"SOFTWARE\Google\Chrome\NativeMessagingHosts\{_NATIVE_HOST}",
    "yandex": rf"SOFTWARE\Chromium\NativeMessagingHosts\{_NATIVE_HOST}",
}


class ReadOnlyRegistry(Protocol):
    def read(self, path: str, name: str) -> str | None: ...

    def values_at(self, path: str) -> dict[str, str]: ...


def _marker_slot(raw: str | None, family: BrowserFamily, extension_id: str) -> str | None:
    if raw is None:
        return None
    try:
        marker = json.loads(raw)
    except (TypeError, ValueError) as error:
        raise ValueError("invalid browser ownership marker") from error
    if (
        not isinstance(marker, dict)
        or set(marker) != {"schema_version", "extension_id", "update_url", "slot"}
        or marker["schema_version"] != 1
        or marker["extension_id"] != extension_id
        or marker["update_url"] != APPROVED_UPDATE_URL
    ):
        raise ValueError("invalid browser ownership marker")
    slot = marker["slot"]
    if family == "chrome" and slot is not None:
        raise ValueError("invalid Chrome ownership marker")
    if family == "yandex" and (
        not isinstance(slot, str)
        or not slot.isdecimal()
        or not 1 <= int(slot) <= 1000
        or str(int(slot)) != slot
    ):
        raise ValueError("invalid Yandex ownership marker")
    return slot


def _force_install_entry(entry: object) -> bool:
    return isinstance(entry, dict) and (
        entry.get("installation_mode") == "force_installed"
        and entry.get("update_url") == APPROVED_UPDATE_URL
    )


def inspect_browser_policy(
    registry: ReadOnlyRegistry,
    family: BrowserFamily,
    extension_id: str,
) -> tuple[PolicyOwner, PolicyState]:
    """Inspect only the pinned extension entry; never modify machine policy."""
    if family not in ("chrome", "yandex") or not re.fullmatch(r"[a-p]{32}", extension_id):
        raise ValueError("invalid browser family or extension ID")
    try:
        raw_marker = registry.read(MARKER_PATH, family)
        slot = _marker_slot(raw_marker, family, extension_id)
        if family == "chrome":
            raw = registry.read(CHROME_POLICY_PATH, "ExtensionSettings")
            if raw is None:
                return ("CONFLICT", "CONFLICT") if raw_marker else ("NONE", "NOT_APPLIED")
            if len(raw.encode("utf-8")) > _MAX_CHROME_POLICY_BYTES:
                raise ValueError("oversized Chrome policy")
            values = json.loads(raw)
            if not isinstance(values, dict):
                raise ValueError("invalid Chrome policy")
            entry = values.get(extension_id)
            if entry is None:
                return ("CONFLICT", "CONFLICT") if raw_marker else ("NONE", "NOT_APPLIED")
            expected = {
                "installation_mode": "force_installed",
                "update_url": APPROVED_UPDATE_URL,
            }
            applied = _force_install_entry(entry)
            if raw_marker and entry != expected:
                return "CONFLICT", "CONFLICT"
            return ("ENDPOINT" if raw_marker else "EXTERNAL",
                    "APPLIED" if applied else "NOT_APPLIED")

        settings_raw = registry.read(_YANDEX_ROOT_PATH, "ExtensionSettings")
        if settings_raw is not None:
            if raw_marker:
                return "CONFLICT", "CONFLICT"
            if len(settings_raw.encode("utf-8")) > _MAX_CHROME_POLICY_BYTES:
                raise ValueError("oversized Yandex ExtensionSettings")
            settings = json.loads(settings_raw)
            if not isinstance(settings, dict):
                raise ValueError("invalid Yandex ExtensionSettings")
            entry = settings.get(extension_id)
            if entry is None:
                return "NONE", "NOT_APPLIED"
            return ("EXTERNAL", "APPLIED" if _force_install_entry(entry)
                    else "NOT_APPLIED")
        if registry.read(_YANDEX_ROOT_PATH, "ExtensionInstallForcelist") is not None:
            return "CONFLICT", "CONFLICT"
        values = registry.values_at(YANDEX_POLICY_PATH)
        for name, value in values.items():
            if (
                not name.isdecimal() or not 1 <= int(name) <= 1000
                or str(int(name)) != name or not isinstance(value, str)
                or len(value.encode("utf-8")) > 4096
            ):
                raise ValueError("invalid Yandex policy")
        entries = {
            name: value for name, value in values.items()
            if value.split(";", 1)[0] == extension_id
        }
        if raw_marker and (
            len(entries) != 1 or slot not in entries
            or entries[slot] != f"{extension_id};{APPROVED_UPDATE_URL}"
        ):
            return "CONFLICT", "CONFLICT"
        if not entries:
            return "NONE", "NOT_APPLIED"
        if len(entries) != 1:
            return "CONFLICT", "CONFLICT"
        applied = next(iter(entries.values())) == f"{extension_id};{APPROVED_UPDATE_URL}"
        return ("ENDPOINT" if raw_marker else "EXTERNAL",
                "APPLIED" if applied else "NOT_APPLIED")
    except OSError:
        return "UNKNOWN", "UNKNOWN"
    except (BrowserPolicyConflict, TypeError, UnicodeError, ValueError):
        return "CONFLICT", "CONFLICT"


def _same_path(left: str | Path, right: str | Path) -> bool:
    return os.path.normpath(str(left)).casefold() == os.path.normpath(str(right)).casefold()


class WindowsBrowserProbe:
    """Read machine registration and process metadata without touching profiles."""

    def __init__(
        self,
        *,
        registry: ReadOnlyRegistry,
        install_root: Path,
        extension_id: str,
        process_iter: Callable[..., Iterable[object]] | None = None,
    ) -> None:
        if not re.fullmatch(r"[a-p]{32}", extension_id):
            raise ValueError("invalid packaged Browser Sensor extension ID")
        self._registry = registry
        self._install_root = install_root
        self._extension_id = extension_id
        self._process_iter = process_iter or psutil.process_iter

    def _native_host_state(self, family: BrowserFamily) -> Literal["READY", "MISSING", "UNKNOWN"]:
        manifest = self._install_root / f"{_NATIVE_HOST}.json"
        bridge = self._install_root / "EndpointBrowserBridge.exe"
        try:
            registered = self._registry.read(_NATIVE_KEYS[family], "")
            if registered is None or not _same_path(registered, manifest):
                return "MISSING"
            if (
                manifest.is_symlink() or bridge.is_symlink()
                or not manifest.is_file() or not bridge.is_file()
                or manifest.stat().st_size > 4096
            ):
                return "MISSING"
            value = json.loads(manifest.read_text(encoding="utf-8"))
            if (
                not isinstance(value, dict)
                or value.get("name") != _NATIVE_HOST
                or value.get("type") != "stdio"
                or value.get("path") != "EndpointBrowserBridge.exe"
                or value.get("allowed_origins")
                != [f"chrome-extension://{self._extension_id}/"]
            ):
                return "MISSING"
            return "READY"
        except (OSError, BrowserPolicyConflict):
            return "UNKNOWN"
        except (UnicodeError, ValueError):
            return "MISSING"

    def collect(self, *, observed_at: datetime) -> dict[BrowserFamily, BrowserHostFacts]:
        """Never infer absence from a missing App Paths entry alone."""
        if observed_at.tzinfo is None or observed_at.utcoffset() is None:
            raise ValueError("browser observation time must be timezone-aware")
        paths: dict[BrowserFamily, str | None] = {}
        for family in ("chrome", "yandex"):
            try:
                paths[family] = self._registry.read(
                    rf"{_APP_PATHS}\{_PROCESS_NAMES[family]}", "",
                )
            except (OSError, BrowserPolicyConflict):
                paths[family] = None
        running_paths: set[str] = set()
        uncertain_names: set[str] = set()
        process_scan_failed = False
        try:
            for process in self._process_iter(attrs=["name", "exe"], ad_value=None):
                info = process.info
                name = info.get("name")
                if not isinstance(name, str) or name.casefold() not in _PROCESS_NAMES.values():
                    continue
                exe = info.get("exe")
                if isinstance(exe, str):
                    running_paths.add(os.path.normpath(exe).casefold())
                else:
                    uncertain_names.add(name.casefold())
        except (OSError, psutil.Error):
            process_scan_failed = True

        result: dict[BrowserFamily, BrowserHostFacts] = {}
        for family in ("chrome", "yandex"):
            app_path = paths[family]
            exists = bool(
                app_path
                and tuple(part.casefold() for part in Path(app_path).parts[-4:])
                == _VENDOR_SUFFIX[family]
                and Path(app_path).is_file()
            )
            matched = bool(
                app_path and os.path.normpath(app_path).casefold() in running_paths
            )
            if exists:
                browser_state = "DETECTED"
                running_state = (
                    "RUNNING" if matched else "UNKNOWN"
                    if process_scan_failed or _PROCESS_NAMES[family] in uncertain_names
                    else "CLOSED"
                )
            else:
                browser_state, running_state = "UNKNOWN", "UNKNOWN"
            owner, installation = inspect_browser_policy(
                self._registry, family, self._extension_id,
            )
            result[family] = BrowserHostFacts(
                browser_state=browser_state,
                running_state=running_state,
                policy_owner=owner,
                installation_policy_state=installation,
                native_host_state=self._native_host_state(family),
                last_running_at=observed_at if running_state == "RUNNING" else None,
            )
        return result
