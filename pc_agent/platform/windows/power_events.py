"""Whitelisted System metadata and native suspend/resume callbacks.

Kernel-General12 is classified only with Kernel-Boot27 BootType. EventLog6005
is deliberately absent: a service restart is never an OS startup fact.
"""

from __future__ import annotations

import asyncio
import json
import xml.etree.ElementTree as ET
from datetime import UTC, datetime, timedelta

from endpoint_contracts.power_events import PowerSourceStatusV1
from pc_agent.power.native import NativePage, native_event, opaque_id

_FIELDS = {
    "StartTime",
    "StopTime",
    "BootMode",
    "BootType",
    "TargetState",
    "EffectiveState",
    "WakeTime",
}
_GENERAL = "Microsoft-Windows-Kernel-General"
_BOOT = "Microsoft-Windows-Kernel-Boot"
_POWER = "Microsoft-Windows-Kernel-Power"
_TROUBLE = "Microsoft-Windows-Power-Troubleshooter"
_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
_FILTER = "(Provider[@Name='Microsoft-Windows-Kernel-General'] and (EventID=12 or EventID=13)) or (Provider[@Name='Microsoft-Windows-Kernel-Boot'] and EventID=27) or (Provider[@Name='Microsoft-Windows-Kernel-Power'] and (EventID=41 or EventID=42 or EventID=107)) or (Provider[@Name='Microsoft-Windows-Power-Troubleshooter'] and EventID=1) or (Provider[@Name='User32'] and EventID=1074)"


def parse_event_xml(encoded):
    if len(encoded) > 65536:
        raise ValueError("native event exceeds bound")
    root = ET.fromstring(encoded)
    system = root.find("e:System", _NS)
    return {
        "provider": system.find("e:Provider", _NS).attrib["Name"],
        "event_id": int(system.find("e:EventID", _NS).text),
        "record_id": int(system.find("e:EventRecordID", _NS).text),
        "timestamp": system.find("e:TimeCreated", _NS).attrib["SystemTime"],
        "data": {
            row.attrib["Name"]: row.text
            for row in root.findall("e:EventData/e:Data", _NS)
            if row.attrib.get("Name") in _FIELDS
        },
    }


def _time(value):
    result = datetime.fromisoformat(value)
    if result.tzinfo is None:
        raise ValueError("native timestamp unavailable")
    return result.astimezone(UTC)


def project_windows_page(rows, checkpoint, *, now):
    if len(rows) > 128:
        raise ValueError("Windows native page exceeds bound")
    state = json.loads(checkpoint) if checkpoint else {}
    events, losses = [], 0
    for row in rows:
        try:
            record_id = int(row["record_id"])
            if record_id <= state.get("record_id", 0):
                continue
            state["record_id"] = record_id
            provider, identifier, data = (
                row["provider"],
                int(row["event_id"]),
                row.get("data", {}),
            )
            occurred = _time(row["timestamp"])
            if occurred > now + timedelta(minutes=5):
                raise ValueError("native clock skew")
            if provider == _GENERAL and identifier == 12:
                # Retain only bounded timestamp/identity across a page boundary.
                started = _time(data["StartTime"])
                state["pending_start"] = {
                    "time": started.isoformat(),
                    "record": record_id,
                }
                continue
            kind, evidence, subtype = None, "transition", None
            if provider == _BOOT and identifier == 27:
                boot_type = int(data["BootType"])
                if boot_type not in {0, 1, 2}:
                    raise ValueError("unknown native boot type")
                state.pop("pending_start", None)
                # On some Windows versions Boot27 precedes General12. The real
                # Boot27 record itself supplies a stable boot boundary there.
                state["boot_id"] = opaque_id(
                    f"System:boot:{record_id}:{occurred.isoformat()}"
                )
                kind = "OS_STARTED" if boot_type == 0 else "OS_RESUMED"
            elif provider == _GENERAL and identifier == 13:
                kind, occurred = "OS_SHUTDOWN_STARTED", _time(data["StopTime"])
            elif provider == _POWER and identifier in {41, 42, 107}:
                kind = {
                    41: "OS_UNEXPECTED_SHUTDOWN_REPORTED",
                    42: "OS_SLEEP_STARTED",
                    107: "OS_RESUMED",
                }[identifier]
                if identifier == 41:
                    evidence = "reported"
                if identifier == 42:
                    subtype = (
                        "hibernate"
                        if str(data.get("EffectiveState", data.get("TargetState")))
                        == "5"
                        else "sleep"
                    )
            elif provider == _TROUBLE and identifier == 1:
                kind = "OS_RESUMED"
                if data.get("WakeTime"):
                    occurred = _time(data["WakeTime"])
            elif provider == "User32" and identifier == 1074:
                kind, evidence = "OS_SHUTDOWN_STARTED", "request"
            if kind is None:
                continue
            if "boot_id" not in state:
                # Incomplete retained log cannot identify the historical boot.
                losses += 1
                continue
            if occurred > now + timedelta(minutes=5):
                raise ValueError("native clock skew")
            events.append(
                native_event(
                    source="windows.system",
                    boot_id=state["boot_id"],
                    native_record_id=str(record_id),
                    event_kind=kind,
                    occurred_at=occurred,
                    observed_at=now,
                    evidence=evidence,
                    sleep_subtype=subtype,
                )
            )
        except (ValueError, TypeError, KeyError, OverflowError):
            losses += 1
    state["coverage"] = min(
        [
            state.get("coverage", now.isoformat()),
            *[e.occurred_at.isoformat() for e in events],
        ]
    )
    status = PowerSourceStatusV1(
        schema_version="power_source_status_v1",
        source="windows.system",
        availability="DEGRADED" if losses else "READY",
        reported_at=now,
        coverage_started_at=min(_time(state["coverage"]), now),
    )
    return NativePage(
        tuple(events),
        json.dumps(state, separators=(",", ":")),
        status,
        loss_count=losses,
    )


def _read_system(checkpoint, now):
    import win32evtlog

    state = json.loads(checkpoint) if checkpoint else {}
    cursor = state.get("record_id", 0)

    def query_one(flags, filter="*"):
        query = win32evtlog.EvtQuery("System", flags, filter)
        try:
            handles = win32evtlog.EvtNext(query, 1, 1000)
            if not handles:
                return None
            try:
                return parse_event_xml(
                    win32evtlog.EvtRender(handles[0], win32evtlog.EvtRenderEventXml)
                )
            finally:
                handles[0].Close()
        finally:
            query.Close()

    oldest = query_one(
        win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryForwardDirection
    )
    newest = query_one(
        win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection
    )
    live_boot = query_one(
        win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection,
        "*[System[Provider[@Name='Microsoft-Windows-Kernel-Boot'] and EventID=27]]",
    )
    reset = bool(
        cursor
        and (
            not newest
            or cursor > newest["record_id"]
            or (oldest and cursor < oldest["record_id"])
        )
    )
    if reset:
        cursor, state = 0, {}
    since = (now - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    query = win32evtlog.EvtQuery(
        "System",
        win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryForwardDirection,
        f"*[System[({_FILTER}) and EventRecordID>{cursor} and TimeCreated[@SystemTime>='{since}']]]",
    )
    rows = []
    try:
        for handle in win32evtlog.EvtNext(query, 128, 1000):
            try:
                rows.append(
                    parse_event_xml(
                        win32evtlog.EvtRender(handle, win32evtlog.EvtRenderEventXml)
                    )
                )
            finally:
                handle.Close()
    finally:
        query.Close()
    live_boot_id = (
        opaque_id(
            f"System:boot:{live_boot['record_id']}:{_time(live_boot['timestamp']).isoformat()}"
        )
        if live_boot
        else None
    )
    return rows, json.dumps(state), reset, live_boot_id


class WindowsPowerSource:
    source = "windows.system"

    def __init__(self, *, reader=_read_system):
        self._reader = reader
        self._boot_id = None
        self._notifications_ready = False

    async def read_page(self, checkpoint, *, now):
        rows, state, reset, live_boot_id = await asyncio.to_thread(
            self._reader, checkpoint, now
        )
        page = project_windows_page(rows, state, now=now)
        self._boot_id = live_boot_id
        status = page.status.model_copy(
            update={
                "availability": "DEGRADED"
                if reset
                or page.loss_count
                or not self._notifications_ready
                or not live_boot_id
                else "READY"
            }
        )
        return NativePage(
            page.events, page.checkpoint, status, page.loss_count, int(reset)
        )

    def notification_event(self, kind, *, now):
        if kind not in {4, 18} or self._boot_id is None:
            return None
        return native_event(
            source="windows.notification",
            boot_id=self._boot_id,
            native_record_id=opaque_id(f"{kind}:{now.isoformat()}"),
            event_kind="OS_SLEEP_STARTED" if kind == 4 else "OS_RESUMED",
            sleep_subtype="unknown" if kind == 4 else None,
            occurred_at=now,
            observed_at=now,
        )

    async def notifications(self, record):
        import ctypes
        from ctypes import wintypes

        loop = asyncio.get_running_loop()
        callback_type = ctypes.WINFUNCTYPE(
            wintypes.ULONG, ctypes.c_void_p, wintypes.ULONG, ctypes.c_void_p
        )

        class Parameters(ctypes.Structure):
            _fields_ = [("Callback", callback_type), ("Context", ctypes.c_void_p)]

        def callback(_context, kind, _setting):
            event = self.notification_event(kind, now=datetime.now(UTC))
            if event is None:
                return 0
            future = asyncio.run_coroutine_threadsafe(record(event), loop)
            try:
                # Small bounded durable-write window before the OS suspends.
                future.result(timeout=2)
            except Exception:  # noqa: BLE001 - owning optional native boundary; cancellation propagates
                self._notifications_ready = False
            return 0

        native_callback = callback_type(callback)
        parameters = Parameters(native_callback, None)
        library = ctypes.WinDLL("PowrProf", use_last_error=True)
        library.PowerRegisterSuspendResumeNotification.argtypes = [
            wintypes.DWORD,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        library.PowerRegisterSuspendResumeNotification.restype = wintypes.DWORD
        library.PowerUnregisterSuspendResumeNotification.argtypes = [ctypes.c_void_p]
        library.PowerUnregisterSuspendResumeNotification.restype = wintypes.DWORD
        handle = ctypes.c_void_p()
        code = library.PowerRegisterSuspendResumeNotification(
            2, ctypes.byref(parameters), ctypes.byref(handle)
        )
        if code:
            raise OSError(code, "native power notifications unavailable")
        self._notifications_ready = True
        try:
            await asyncio.Event().wait()
        finally:
            self._notifications_ready = False
            library.PowerUnregisterSuspendResumeNotification(handle)
