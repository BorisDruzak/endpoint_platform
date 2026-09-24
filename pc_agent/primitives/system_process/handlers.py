"""Bounded machine facts without process command lines or private paths."""

from __future__ import annotations

from datetime import UTC, datetime
import math
import os
import re
import time

import psutil

from endpoint_contracts.system_process_primitives import (
    ProcessFindParametersV1,
    ProcessFindResultV1,
    ProcessListParametersV1,
    ProcessListResultV1,
    ProcessSummaryV1,
    SystemResourceSnapshotParametersV1,
    SystemResourceSnapshotResultV1,
)


_PROCESS_FIELDS = ("pid", "name", "status", "cpu_percent", "memory_info")
_PROCESS_STATES = frozenset({
    "running", "sleeping", "disk_sleep", "stopped", "zombie", "dead",
    "waking", "parked", "idle", "locked", "waiting", "unknown",
})
_PROCESS_DEADLINE_SECONDS = 5.0


def resource_snapshot(
    parameters: SystemResourceSnapshotParametersV1,
) -> SystemResourceSnapshotResultV1:
    del parameters
    now = datetime.now(UTC)
    try:
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage(os.path.abspath(os.sep))
        cpu = float(psutil.cpu_percent(interval=0.1))
        uptime = max(0, int(time.time() - psutil.boot_time()))
        if not math.isfinite(cpu):
            raise ValueError("CPU result is not finite")
        return SystemResourceSnapshotResultV1(
            schema_version="system_resource_snapshot_result_v1",
            uptime_seconds=uptime,
            cpu_percent=max(0.0, min(100.0, cpu)),
            memory_total_bytes=max(0, int(memory.total)),
            memory_available_bytes=max(0, int(memory.available)),
            system_drive_free_bytes=max(0, int(disk.free)),
            status="succeeded",
            collected_at=now,
        )
    except (OSError, ValueError, psutil.Error):
        return SystemResourceSnapshotResultV1(
            schema_version="system_resource_snapshot_result_v1",
            status="failed",
            error_code="resource_snapshot_failed",
            collected_at=now,
        )


def _summary(info: dict[str, object]) -> ProcessSummaryV1 | None:
    try:
        pid = info.get("pid")
        if type(pid) is not int or pid < 0 or pid > 2**31 - 1:
            return None
        raw_name = info.get("name")
        name = re.sub(r"[\x00-\x1f\x7f]", "", raw_name if isinstance(raw_name, str) else "").strip()[:128]
        if not name:
            name = "unknown"
        raw_state = info.get("status")
        state = raw_state if isinstance(raw_state, str) and raw_state in _PROCESS_STATES else "unknown"
        raw_cpu = info.get("cpu_percent")
        cpu = float(raw_cpu) if isinstance(raw_cpu, (int, float)) and math.isfinite(raw_cpu) else None
        if cpu is not None:
            cpu = max(0.0, min(10000.0, cpu))
        raw_memory = info.get("memory_info")
        raw_rss = getattr(raw_memory, "rss", None)
        memory_bytes = max(0, min(2**63 - 1, int(raw_rss))) if isinstance(raw_rss, int) else None
        return ProcessSummaryV1(pid=pid, name=name, state=state, cpu_percent=cpu, memory_bytes=memory_bytes)
    except (TypeError, ValueError, OverflowError):
        return None


def _iter_summaries():
    deadline = time.monotonic() + _PROCESS_DEADLINE_SECONDS
    for process in psutil.process_iter(attrs=_PROCESS_FIELDS, ad_value=None):
        if time.monotonic() >= deadline:
            raise TimeoutError("process enumeration exceeded deadline")
        summary = _summary(process.info)
        if summary is not None:
            yield summary


def process_list(parameters: ProcessListParametersV1) -> ProcessListResultV1:
    del parameters
    now = datetime.now(UTC)
    try:
        items: list[ProcessSummaryV1] = []
        for summary in _iter_summaries():
            items.append(summary)
            if len(items) == 32:
                break
        return ProcessListResultV1(
            schema_version="process_list_result_v1",
            processes=items,
            process_count=len(items),
            status="succeeded",
            collected_at=now,
        )
    except (OSError, TimeoutError, psutil.Error):
        return ProcessListResultV1(
            schema_version="process_list_result_v1",
            process_count=0,
            status="failed",
            error_code="process_list_failed",
            collected_at=now,
        )


def process_find(parameters: ProcessFindParametersV1) -> ProcessFindResultV1:
    now = datetime.now(UTC)
    try:
        count = 0
        matches: list[ProcessSummaryV1] = []
        wanted = parameters.name.casefold()
        for summary in _iter_summaries():
            if summary.name.casefold() == wanted:
                count += 1
                if len(matches) < 20:
                    matches.append(summary)
        return ProcessFindResultV1(
            schema_version="process_find_result_v1",
            present=count > 0,
            process_count=count,
            matches=matches,
            status="succeeded",
            collected_at=now,
        )
    except (OSError, TimeoutError, psutil.Error):
        return ProcessFindResultV1(
            schema_version="process_find_result_v1",
            present=False,
            process_count=0,
            status="failed",
            error_code="process_find_failed",
            collected_at=now,
        )
