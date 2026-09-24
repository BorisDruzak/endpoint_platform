"""Bounded software facts from fixed Windows uninstall views or ALT RPM."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
import os
import re
import subprocess
import time

from pydantic import ValidationError

from endpoint_contracts.software_primitives import (
    SoftwareFactV1,
    SoftwareFindParametersV1,
    SoftwareFindResultV1,
    SoftwareListParametersV1,
    SoftwareListResultV1,
)
from pc_agent.context_profiles.probe import _execute_bounded_command


_MAX_SCAN_RECORDS = 2048
_SCAN_SECONDS = 10.0
_RPM_OUTPUT_LIMIT = 262144
_RPM_COMMAND = (
    "/usr/bin/rpm", "-qa", "--queryformat",
    "%{NAME}\t%{VERSION}\t%{VENDOR}\t%{ARCH}\n",
)


def _windows_inventory() -> list[dict[str, object]]:
    import winreg

    root_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    deadline = time.monotonic() + _SCAN_SECONDS
    rows: list[dict[str, object]] = []
    for view, architecture in ((winreg.KEY_WOW64_64KEY, "x64"), (winreg.KEY_WOW64_32KEY, "x86")):
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, root_path, 0, winreg.KEY_READ | view) as root:
            for index in range(_MAX_SCAN_RECORDS):
                if time.monotonic() >= deadline:
                    raise TimeoutError("software inventory exceeded deadline")
                try:
                    key_name = winreg.EnumKey(root, index)
                except OSError:
                    break
                try:
                    with winreg.OpenKey(root, key_name, 0, winreg.KEY_READ) as key:
                        def read(name: str) -> str | None:
                            try:
                                value, _ = winreg.QueryValueEx(key, name)
                            except OSError:
                                return None
                            return value if isinstance(value, str) else None
                        product = read("DisplayName")
                        if product:
                            rows.append({
                                "name": product, "version": read("DisplayVersion"),
                                "publisher": read("Publisher"),
                                "source": "windows_registry", "architecture": architecture,
                            })
                except OSError:
                    continue
    return rows


def _alt_inventory() -> list[dict[str, object]]:
    raw = _execute_bounded_command(_RPM_COMMAND, _SCAN_SECONDS, _RPM_OUTPUT_LIMIT, check_exit=True)
    if len(raw) >= _RPM_OUTPUT_LIMIT:
        raise ValueError("RPM inventory exceeds bound")
    rows: list[dict[str, object]] = []
    for line in raw.decode("utf-8", errors="replace").splitlines():
        parts = line.split("\t")
        if len(parts) != 4:
            continue
        name, version, vendor, architecture = parts
        rows.append({
            "name": name, "version": version, "publisher": vendor,
            "source": "alt_rpm", "architecture": architecture,
        })
        if len(rows) >= _MAX_SCAN_RECORDS:
            break
    return rows


def _inventory() -> list[dict[str, object]]:
    return _windows_inventory() if os.name == "nt" else _alt_inventory()


def _text(value: object, maximum: int) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = re.sub(r"[\x00-\x1f\x7f]", "", value).strip()[:maximum]
    return cleaned or None


def _facts(rows: list[dict[str, object]]) -> list[SoftwareFactV1]:
    facts: dict[tuple[str, str, str], SoftwareFactV1] = {}
    for row in rows[:_MAX_SCAN_RECORDS]:
        name = _text(row.get("name"), 128)
        if name is None:
            continue
        try:
            fact = SoftwareFactV1(
                name=name,
                version=_text(row.get("version"), 64),
                publisher=_text(row.get("publisher"), 128),
                source=row.get("source"),
                architecture=_text(row.get("architecture"), 32),
            )
        except ValidationError:
            continue
        key = (fact.name.casefold(), (fact.version or "").casefold(), fact.architecture or "")
        facts.setdefault(key, fact)
    return sorted(facts.values(), key=lambda item: (item.name.casefold(), item.version or "", item.architecture or ""))


def software_list(
    parameters: SoftwareListParametersV1,
    *, query_inventory: Callable[[], list[dict[str, object]]] = _inventory,
) -> SoftwareListResultV1:
    del parameters
    now = datetime.now(UTC)
    try:
        return SoftwareListResultV1(
            schema_version="software_list_result_v1",
            software=_facts(query_inventory())[:32],
            status="succeeded", collected_at=now,
        )
    except (OSError, ValueError, TimeoutError, subprocess.TimeoutExpired):
        return SoftwareListResultV1(
            schema_version="software_list_result_v1", status="failed",
            error_code="software_inventory_failed", collected_at=now,
        )


def software_find(
    parameters: SoftwareFindParametersV1,
    *, query_inventory: Callable[[], list[dict[str, object]]] = _inventory,
) -> SoftwareFindResultV1:
    now = datetime.now(UTC)
    try:
        needle = parameters.name.casefold()
        matches = [fact for fact in _facts(query_inventory()) if needle in fact.name.casefold()][:20]
        return SoftwareFindResultV1(
            schema_version="software_find_result_v1",
            present=bool(matches), matches=matches,
            status="succeeded", collected_at=now,
        )
    except (OSError, ValueError, TimeoutError, subprocess.TimeoutExpired):
        return SoftwareFindResultV1(
            schema_version="software_find_result_v1", present=False,
            status="failed", error_code="software_inventory_failed", collected_at=now,
        )
