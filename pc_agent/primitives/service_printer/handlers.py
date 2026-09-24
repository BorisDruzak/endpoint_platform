"""Logical service catalog and printer facts without print document data."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import re
import subprocess

import psutil

from endpoint_contracts.service_printer_primitives import (
    PrinterFactV1,
    PrinterListParametersV1,
    PrinterListResultV1,
    PrinterQueueSummaryParametersV1,
    PrinterQueueSummaryResultV1,
    PrinterStatusParametersV1,
    PrinterStatusResultV1,
    ServiceFactV1,
    ServiceListParametersV1,
    ServiceListResultV1,
    ServiceStatusParametersV1,
    ServiceStatusResultV1,
)
from pc_agent.context_profiles.probe import _execute_bounded_command
from pc_agent.primitives.read_only.handlers import _linux_service_details


_WINDOWS_SERVICES = {
    "endpoint_agent": ("EndpointAgent", "Endpoint Agent"),
    "endpoint_agent_updater": ("EndpointAgentUpdater", "Endpoint Agent Updater"),
    "print_service": ("Spooler", "Служба печати"),
}
_LINUX_SERVICES = {
    "endpoint_agent": ("endpoint-agent.service", "Endpoint Agent"),
    "endpoint_agent_updater": ("endpoint-agent-update.service", "Endpoint Agent Updater"),
    "print_service": ("cups.service", "Служба печати"),
}
_WINDOWS_PRINTER_SCRIPT = (
    "$items=@(Get-CimInstance -ClassName Win32_Printer -ErrorAction Stop | "
    "Select-Object -First 16 | ForEach-Object { "
    "[pscustomobject]@{name=[string]$_.Name;driver_name=[string]$_.DriverName;"
    "port_name=[string]$_.PortName;default=[bool]$_.Default;"
    "printer_status=[int]$_.PrinterStatus;work_offline=[bool]$_.WorkOffline;"
    "paused=[bool]$_.Paused} });ConvertTo-Json -InputObject $items -Depth 3 -Compress"
)
_WINDOWS_QUEUE_SCRIPT = (
    "$jobs=@(Get-CimInstance -ClassName Win32_PrintJob -ErrorAction Stop);"
    "$now=Get-Date;[pscustomobject]@{job_count=[int]$jobs.Count;"
    "printing_count=[int]@($jobs|Where-Object{$_.JobStatus -match 'Printing'}).Count;"
    "queued_count=[int]@($jobs|Where-Object{$_.JobStatus -match 'Spooling|Queued|Normal'}).Count;"
    "paused_count=[int]@($jobs|Where-Object{$_.JobStatus -match 'Paused'}).Count;"
    "error_count=[int]@($jobs|Where-Object{$_.JobStatus -match 'Error|Blocked'}).Count;"
    "oldest_job_age_seconds=if($jobs.Count){[int][Math]::Min(31536000,[Math]::Max(0,"
    "($now-($jobs|Sort-Object TimeSubmitted|Select-Object -First 1).TimeSubmitted).TotalSeconds))}"
    "else{$null}}|ConvertTo-Json -Compress"
)


def _platform() -> str:
    return "windows" if os.name == "nt" else "linux"


def _windows_service_details(name: str) -> tuple[bool, str, str]:
    try:
        service = psutil.win_service_get(name)
        state = service.status()
        start = service.start_type()
    except psutil.NoSuchProcess:
        return False, "not_found", "unknown"
    return (
        True,
        state if state in {"running", "stopped", "paused", "failed"} else "unknown",
        start if start in {"automatic", "manual", "disabled"} else "unknown",
    )


def _service_fact(
    key: str, platform: str, query: Callable[[str], tuple[bool, str, str]],
) -> ServiceFactV1:
    name, display = (_WINDOWS_SERVICES if platform == "windows" else _LINUX_SERVICES)[key]
    installed, state, start = query(name)
    return ServiceFactV1(
        service_key=key,
        display_name=display,
        installed=bool(installed),
        state=state,
        startup_type=start,
    )


def service_list(
    parameters: ServiceListParametersV1,
    *,
    platform_name: str | None = None,
    windows_query: Callable[[str], tuple[bool, str, str]] = _windows_service_details,
    linux_query: Callable[[str], tuple[bool, str, str]] = _linux_service_details,
) -> ServiceListResultV1:
    del parameters
    now = datetime.now(UTC)
    platform = platform_name or _platform()
    try:
        catalog = _WINDOWS_SERVICES if platform == "windows" else _LINUX_SERVICES if platform == "linux" else None
        if catalog is None:
            raise OSError("unsupported platform")
        query = windows_query if platform == "windows" else linux_query
        return ServiceListResultV1(
            schema_version="service_list_result_v1",
            services=[_service_fact(key, platform, query) for key in catalog],
            status="succeeded",
            collected_at=now,
        )
    except (OSError, ValueError, subprocess.TimeoutExpired, psutil.Error):
        return ServiceListResultV1(
            schema_version="service_list_result_v1",
            status="failed", error_code="service_list_failed", collected_at=now,
        )


def service_status(
    parameters: ServiceStatusParametersV1,
    *,
    platform_name: str | None = None,
    windows_query: Callable[[str], tuple[bool, str, str]] = _windows_service_details,
    linux_query: Callable[[str], tuple[bool, str, str]] = _linux_service_details,
) -> ServiceStatusResultV1:
    now = datetime.now(UTC)
    platform = platform_name or _platform()
    try:
        catalog = _WINDOWS_SERVICES if platform == "windows" else _LINUX_SERVICES if platform == "linux" else None
        if catalog is None or parameters.service_key not in catalog:
            raise ValueError("service key is unsupported on this platform")
        query = windows_query if platform == "windows" else linux_query
        return ServiceStatusResultV1(
            schema_version="service_status_v2_result_v1",
            service=_service_fact(parameters.service_key, platform, query),
            status="succeeded",
            collected_at=now,
        )
    except (OSError, ValueError, subprocess.TimeoutExpired, psutil.Error):
        return ServiceStatusResultV1(
            schema_version="service_status_v2_result_v1",
            status="failed", error_code="service_query_failed", collected_at=now,
        )


def _run_fixed(command: tuple[str, ...], limit: int = 16384) -> str:
    return _execute_bounded_command(command, 10.0, limit, check_exit=True).decode("utf-8", errors="replace")


def _powershell(script: str, *, limit: int = 16384) -> str:
    system_root = Path(os.environ.get("SystemRoot", "C:\\Windows"))
    executable = system_root / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    return _run_fixed((str(executable), "-NoProfile", "-NonInteractive", "-Command", script), limit=limit)


def _windows_printers() -> list[dict[str, object]]:
    value = json.loads(_powershell(_WINDOWS_PRINTER_SCRIPT))
    return value if isinstance(value, list) else []


def _linux_printers() -> list[dict[str, object]]:
    raw = _execute_bounded_command(("/usr/bin/lpstat", "-p"), 10.0, 16384)
    if len(raw) >= 16384:
        raise ValueError("CUPS printer inventory exceeds bound")
    output = raw.decode("utf-8", errors="replace")
    if "no destinations added" in output.casefold() or "назначения не добавлены" in output.casefold():
        return []
    if not output.strip() or not any(line.startswith("printer ") for line in output.splitlines()):
        raise OSError("CUPS printer inventory is unavailable")
    default_output = _execute_bounded_command(("/usr/bin/lpstat", "-d"), 10.0, 16384).decode("utf-8", errors="replace")
    default = default_output.strip().split(":", 1)[-1].strip() if ":" in default_output else ""
    printers: list[dict[str, object]] = []
    for line in output.splitlines():
        match = re.match(r"^printer\s+(\S+)\s+is\s+(.+)$", line)
        if match is None:
            continue
        name, state = match.groups()
        printers.append({
            "name": name, "driver_name": None, "port_name": "",
            "default": name == default, "state": "paused" if "disabled" in state else "ready" if "idle" in state else "unknown",
        })
        if len(printers) == 16:
            break
    return printers


def _printer_fact(raw: dict[str, object]) -> PrinterFactV1 | None:
    try:
        name = re.sub(r"[\x00-\x1f\x7f]", "", str(raw.get("name") or "")).strip()[:128]
        if not name:
            return None
        driver = re.sub(r"[\x00-\x1f\x7f]", "", str(raw.get("driver_name") or "")).strip()[:128] or None
        if "state" in raw:
            state = raw["state"]
        else:
            state = "offline" if raw.get("work_offline") or raw.get("printer_status") == 7 else "paused" if raw.get("paused") else "ready" if raw.get("printer_status") in (3, 4, 5) else "unknown"
        port = str(raw.get("port_name") or "").casefold()
        port_type = "network" if port.startswith(("ip_", "tcp", "http", "wds")) else "usb" if port.startswith("usb") else "virtual" if port.startswith(("nul", "file", "portprompt")) else "local" if port else "unknown"
        return PrinterFactV1(name=name, driver_name=driver, port_type=port_type, default=bool(raw.get("default")), state=state)
    except (TypeError, ValueError):
        return None


def _enumerate_printers() -> list[dict[str, object]]:
    return _windows_printers() if _platform() == "windows" else _linux_printers()


def printer_list(
    parameters: PrinterListParametersV1,
    *, enumerate_printers: Callable[[], list[dict[str, object]]] = _enumerate_printers,
) -> PrinterListResultV1:
    del parameters
    now = datetime.now(UTC)
    try:
        facts = [fact for raw in enumerate_printers()[:16] if (fact := _printer_fact(raw)) is not None]
        return PrinterListResultV1(schema_version="printer_list_result_v1", printers=facts, status="succeeded", collected_at=now)
    except (OSError, ValueError, subprocess.TimeoutExpired, json.JSONDecodeError):
        return PrinterListResultV1(schema_version="printer_list_result_v1", status="failed", error_code="printer_list_failed", collected_at=now)


def printer_status(
    parameters: PrinterStatusParametersV1,
    *, enumerate_printers: Callable[[], list[dict[str, object]]] = _enumerate_printers,
) -> PrinterStatusResultV1:
    now = datetime.now(UTC)
    listed = printer_list(PrinterListParametersV1(schema_version="printer_list_parameters_v1"), enumerate_printers=enumerate_printers)
    if listed.status == "failed":
        return PrinterStatusResultV1(schema_version="printer_status_result_v1", exists=False, state="unknown", offline=False, error=False, paused=False, status="failed", error_code="printer_query_failed", collected_at=now)
    found = next((item for item in listed.printers if item.name.casefold() == parameters.printer_name.casefold()), None)
    state = found.state if found is not None else "unknown"
    return PrinterStatusResultV1(
        schema_version="printer_status_result_v1", exists=found is not None,
        state=state, offline=state == "offline", error=state == "error", paused=state == "paused",
        status="succeeded", collected_at=now,
    )


def _windows_queue_summary() -> dict[str, object]:
    value = json.loads(_powershell(_WINDOWS_QUEUE_SCRIPT))
    if not isinstance(value, dict):
        raise ValueError("invalid queue summary")
    return value


def printer_queue_summary(
    parameters: PrinterQueueSummaryParametersV1,
    *, query_summary: Callable[[], dict[str, object]] = _windows_queue_summary,
) -> PrinterQueueSummaryResultV1:
    del parameters
    now = datetime.now(UTC)
    try:
        if _platform() != "windows" and query_summary is _windows_queue_summary:
            raise OSError("queue summary is unsupported on this platform")
        raw = query_summary()
        counts = {key: max(0, min(10000, int(raw[key]))) for key in (
            "job_count", "printing_count", "queued_count", "paused_count", "error_count",
        )}
        age = raw.get("oldest_job_age_seconds")
        return PrinterQueueSummaryResultV1(
            schema_version="printer_queue_summary_result_v1",
            **counts,
            oldest_job_age_seconds=max(0, min(31536000, int(age))) if age is not None else None,
            status="succeeded", collected_at=now,
        )
    except (OSError, ValueError, TypeError, KeyError, subprocess.TimeoutExpired, json.JSONDecodeError):
        return PrinterQueueSummaryResultV1(
            schema_version="printer_queue_summary_result_v1",
            job_count=0, printing_count=0, queued_count=0, paused_count=0, error_count=0,
            status="failed", error_code="printer_queue_failed", collected_at=now,
        )
