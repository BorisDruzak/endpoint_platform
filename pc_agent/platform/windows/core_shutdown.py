"""Protected boot and owner evidence for the Windows Core selector boundary."""
from __future__ import annotations

from contextlib import ExitStack, contextmanager
from dataclasses import asdict, dataclass, replace
from hashlib import sha256
import os
import re
from uuid import UUID, uuid4
from xml.etree import ElementTree

from .acl import PyWin32AclAdapter
from .durable_state import _check_directories, flush_directory, write_json_atomic
from .update_transaction import _assert_state_security, _read_state, _windows_transaction

if os.name == "nt":
    from pywintypes import error as Win32Error
else:
    Win32Error = OSError


_GATE = r"Global\EndpointPlatform.Agent.CoreShutdown"
_STATE_NAME = "core-shutdown.json"
_LIMIT = 1024
_KERNEL_BOOT = "Microsoft-Windows-Kernel-Boot"
_KERNEL_GENERAL = "Microsoft-Windows-Kernel-General"
_EVENT_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
_MAX_BOOT_COUNTER = 0xFFFFFFFF


class CoreShutdownUnconfirmed(ValueError):
    """The captured Core owner cannot authorize a selector change."""


@dataclass(frozen=True, slots=True)
class BootStamp:
    counter: int
    anchor_sha256: str


@dataclass(frozen=True, slots=True)
class CoreOwner:
    boot_id: str | None
    run_id: str
    selector_sha256: str
    state: str
    unresolved: bool
    boot_event: int | None = None
    debt_boot_id: str | None = None
    debt_boot_event: int | None = None
    boot_stamp: BootStamp | None = None
    debt_boot_stamp: BootStamp | None = None


@contextmanager
def core_shutdown_gate(paths):
    """Serialize only owner reservation and exact selector mutation."""
    with ExitStack() as scope:
        try:
            scope.enter_context(_windows_transaction(3000, name=_GATE))
        except Win32Error as error:
            raise CoreShutdownUnconfirmed("Core shutdown gate is unavailable") from error
        yield


def _native_boot_id() -> str | None:
    """Read the kernel boot GUID, with no clock-based fallback."""
    import ctypes
    from ctypes import wintypes

    try:
        # This native information class may be unavailable on unsupported builds.
        query = ctypes.WinDLL("ntdll").NtQuerySystemInformation
        query.argtypes = (ctypes.c_int, ctypes.c_void_p, wintypes.ULONG, ctypes.POINTER(wintypes.ULONG))
        query.restype = ctypes.c_long
        data = (ctypes.c_ubyte * 32)()
        size = wintypes.ULONG()
        if query(90, ctypes.byref(data), ctypes.sizeof(data), ctypes.byref(size)) != 0 or not 16 <= size.value <= 32:
            return None
        boot = UUID(bytes_le=bytes(data[:16]))
        return str(boot) if boot.int else None
    except (AttributeError, OSError, ValueError):
        return None


def _last_system_event(filter):
    import win32evtlog
    from .power_event_xml import parse_event_xml

    query = win32evtlog.EvtQuery(
        "System", win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection, filter,
    )
    try:
        entries = win32evtlog.EvtNext(query, 1, 250)
        try:
            if len(entries) == 1:
                xml = win32evtlog.EvtRender(entries[0], win32evtlog.EvtRenderEventXml)
                try:
                    row = parse_event_xml(xml)
                except ElementTree.ParseError:
                    return None
                row["event_sha256"] = sha256(xml.encode("utf-8")).hexdigest()
                if row["provider"] == _KERNEL_BOOT and row["event_id"] == 20:
                    value = ElementTree.fromstring(xml).find(
                        f"{_EVENT_NS}EventData/{_EVENT_NS}Data[@Name='LastBootId']",
                    )
                    if value is not None:
                        row["data"]["LastBootId"] = value.text
                return row
        finally:
            for entry in entries:
                entry.Close()
    finally:
        query.Close()
    return None


def _native_cold_boot_event() -> int | None:
    """The latest boot record, with hybrid and resume records excluded."""
    try:
        row = _last_system_event("*[System[Provider[@Name='Microsoft-Windows-Kernel-Boot'] and EventID=27]]")
        if row is not None and int(row["data"]["BootType"]) == 0:
            event = int(row["record_id"])
            return event if event > 0 else None
    except (ImportError, OSError, ValueError, TypeError, KeyError, Win32Error):
        pass
    return None


def _event_watermark() -> int | None:
    try:
        row = _last_system_event("*")
        if row is not None:
            event = int(row["record_id"])
            return event if event > 0 else None
    except (ImportError, OSError, ValueError, TypeError, KeyError, Win32Error):
        pass
    return None


def _known_reboot(boot, event, old_boot, old_event) -> bool:
    # A GUID change alone is insufficient on uncertain/hybrid boot boundaries.
    return (
        boot is not None and old_boot is not None and boot != old_boot
        and event is not None and old_event is not None and event > old_event
    )


def _kernel_boot_counter() -> int | None:
    """Read the existing kernel boot counter without creating or writing a key."""
    try:
        import winreg

        key_name = r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_name, 0, winreg.KEY_QUERY_VALUE) as key:
            counter, kind = winreg.QueryValueEx(key, "BootId")
        return counter if kind == winreg.REG_DWORD and _boot_counter_valid(counter) else None
    except (ImportError, OSError):
        return None


def _boot_counter_valid(counter) -> bool:
    # Zero/reset and the wrap boundary cannot establish continuity.
    return type(counter) is int and 0 < counter < _MAX_BOOT_COUNTER


def _system_anchor(record: int) -> str | None:
    row = _last_system_event(f"*[System[EventRecordID={record}]]")
    return row["event_sha256"] if row is not None and row["record_id"] == record else None


def _current_boot_stamp(event: int | None, watermark: int | None) -> tuple[BootStamp, int] | None:
    """Bind the current registry generation to the latest cold System cluster."""
    if event is None or watermark is None:
        return None
    try:
        counter = _kernel_boot_counter()
        if not _boot_counter_valid(counter):
            return None
        general = _last_system_event(f"*[System[Provider[@Name='{_KERNEL_GENERAL}'] and EventID=12]]")
        status = _last_system_event(f"*[System[Provider[@Name='{_KERNEL_BOOT}'] and EventID=20]]")
        if general is None or status is None:
            return None
        start = general["record_id"]
        if (
            not 0 < start < status["record_id"] < event <= watermark
            or int(general["data"]["BootMode"]) != 0
            or int(status["data"]["LastBootId"]) != counter - 1
        ):
            return None
        anchor = _system_anchor(watermark)
        if anchor is None or _kernel_boot_counter() != counter:
            return None
        return BootStamp(counter, anchor), start
    except (ImportError, OSError, ValueError, TypeError, KeyError, Win32Error):
        return None


def _boot_evidence(boot, event, current, old_boot, old_event, old_stamp) -> bool:
    if _known_reboot(boot, event, old_boot, old_event):
        return True
    if boot is None or boot != old_boot or current is None or old_event is None or old_stamp is None:
        return False
    stamp, first_record = current
    if stamp.counter <= old_stamp.counter or first_record <= old_event:
        return False
    return _anchor_matches(old_event, old_stamp)


def _anchor_matches(record, stamp):
    if record is None or stamp is None:
        return False
    try:
        # A cleared, replaced, or truncated System log cannot release debt.
        return _system_anchor(record) == stamp.anchor_sha256
    except (ImportError, OSError, ValueError, TypeError, KeyError, Win32Error):
        return False


def _uuid(value):
    if not isinstance(value, str):
        return False
    try:
        parsed = UUID(value)
        return parsed.int != 0 and str(parsed) == value
    except ValueError:
        return False


def _parse_stamp(stamp):
    if stamp is None:
        return None
    if (
        not isinstance(stamp, dict) or set(stamp) != {"counter", "anchor_sha256"}
        or not _boot_counter_valid(stamp["counter"])
        or not isinstance(stamp["anchor_sha256"], str)
        or re.fullmatch("[0-9a-f]{64}", stamp["anchor_sha256"]) is None
    ):
        raise ValueError("invalid Core boot stamp")
    return BootStamp(**stamp)


def _read_owner(paths) -> CoreOwner | None:
    try:
        data = _read_state(paths.updates_root / _STATE_NAME, _LIMIT)
        if not isinstance(data, dict):
            return None
        schema = data.pop("schema_version", None)
        fields = set(CoreOwner.__dataclass_fields__)
        if schema == 1:
            fields -= {"boot_stamp", "debt_boot_stamp"}
        if type(schema) is not int or schema not in (1, 2) or set(data) != fields:
            return None
        if (
            (data["boot_id"] is not None and not _uuid(data["boot_id"]))
            or (data["debt_boot_id"] is not None and not _uuid(data["debt_boot_id"]))
            or any(value is not None and (type(value) is not int or value <= 0)
                   for value in (data["boot_event"], data["debt_boot_event"]))
            or not _uuid(data["run_id"])
            or not isinstance(data["selector_sha256"], str)
            or re.fullmatch("[0-9a-f]{64}", data["selector_sha256"]) is None
            or data["state"] not in ("running", "stopped")
            or type(data["unresolved"]) is not bool
        ):
            return None
        for prefix in ("boot", "debt_boot"):
            stamp = _parse_stamp(data.get(f"{prefix}_stamp"))
            if stamp is not None and (data[f"{prefix}_id"] is None or data[f"{prefix}_event"] is None):
                return None
            data[f"{prefix}_stamp"] = stamp
        return CoreOwner(**data)
    except (OSError, ValueError, Win32Error):
        return None


def _write_owner(paths, owner):
    root = paths.updates_root
    parent = root.parent
    _check_directories(parent)
    _assert_state_security(parent)
    if not root.exists():
        root.mkdir()
        PyWin32AclAdapter().protect_update_path(root)
        flush_directory(parent)
    _check_directories(root)
    _assert_state_security(root)
    write_json_atomic(
        root / _STATE_NAME, {"schema_version": 2, **asdict(owner)},
        trusted_root=root, max_bytes=_LIMIT, protect=PyWin32AclAdapter().protect_update_path,
    )


def reserve_core_owner(paths, selector_bytes) -> CoreOwner:
    """Called under the short gate before spawning the selected Core."""
    previous = _read_owner(paths)
    boot, event = _native_boot_id(), _native_cold_boot_event()
    watermark = max(filter(None, (event, _event_watermark())), default=None)
    evidence = _current_boot_stamp(event, watermark) if boot is not None else None
    stamp = evidence[0] if evidence is not None else None
    unresolved = True
    if previous is None or previous.boot_id is None:
        # No historical anchor is available. Establish a baseline without authorizing this boot.
        debt_boot, debt_event, debt_stamp = boot, watermark, stamp
    elif previous.state == "running":
        # A newer unverified run is the latest possible unresolved process owner.
        debt_boot, debt_event, debt_stamp = previous.boot_id, previous.boot_event, previous.boot_stamp
    else:
        debt_boot, debt_event = previous.debt_boot_id, previous.debt_boot_event
        debt_stamp = previous.debt_boot_stamp
        unresolved = previous.unresolved
    if _boot_evidence(boot, event, evidence, debt_boot, debt_event, debt_stamp):
        unresolved = False
    if unresolved and debt_boot is None:
        debt_boot, debt_event, debt_stamp = boot, watermark, stamp
    if unresolved and debt_boot == boot and debt_event is None:
        debt_event = watermark
    if unresolved and stamp is not None and not _anchor_matches(debt_event, debt_stamp):
        # Replace unavailable legacy or retired evidence at reservation only.
        # The new baseline retains all debt until a later verified cold boot.
        debt_boot, debt_event, debt_stamp = boot, watermark, stamp
    owner = CoreOwner(
        boot, str(uuid4()), sha256(selector_bytes).hexdigest(), "running", unresolved,
        watermark, debt_boot if unresolved else None, debt_event if unresolved else None,
        stamp, debt_stamp if unresolved else None,
    )
    _write_owner(paths, owner)
    return owner

def record_core_stopped(paths, owner) -> None:
    """Publish only the launcher's independently verified termination."""
    with core_shutdown_gate(paths):
        if (
            owner.boot_id is None or _native_boot_id() != owner.boot_id or _read_owner(paths) != owner
            or (owner.boot_stamp is not None and _kernel_boot_counter() != owner.boot_stamp.counter)
        ):
            raise CoreShutdownUnconfirmed("Core run ownership changed before shutdown receipt")
        try:
            _write_owner(paths, replace(owner, state="stopped"))
        except Win32Error as error:
            raise CoreShutdownUnconfirmed("Core shutdown receipt could not be protected") from error


def _capture_core(paths, selector_bytes):
    owner = _read_owner(paths)
    boot, event = _native_boot_id(), _native_cold_boot_event()
    if owner is None or boot is None or owner.boot_id is None or owner.selector_sha256 != sha256(selector_bytes).hexdigest():
        return None, False
    evidence = None
    if boot == owner.boot_id and (owner.boot_stamp is not None or owner.debt_boot_stamp is not None):
        evidence = _current_boot_stamp(event, _event_watermark())
    if _boot_evidence(boot, event, evidence, owner.boot_id, owner.boot_event, owner.boot_stamp):
        return owner, True
    if boot != owner.boot_id:
        return None, False
    if owner.boot_stamp is not None and _kernel_boot_counter() != owner.boot_stamp.counter:
        return None, False
    if owner.unresolved and not _boot_evidence(
        boot, event, evidence, owner.debt_boot_id, owner.debt_boot_event, owner.debt_boot_stamp,
    ):
        return None, False
    return owner, False


def capture_core_owner(paths, selector_bytes) -> CoreOwner | None:
    """Snapshot the exact pre-stop owner while the caller holds the gate."""
    owner, _ = _capture_core(paths, selector_bytes)
    return owner


def require_core_stopped(paths, selector_bytes, owner) -> None:
    """Require the same owner, or authoritative reboot evidence for that owner."""
    current, rebooted = _capture_core(paths, selector_bytes)
    if (
        owner is None or current is None
        or (current.boot_id, current.run_id, current.selector_sha256)
            != (owner.boot_id, owner.run_id, owner.selector_sha256)
        or (not rebooted and current.state != "stopped")
    ):
        raise CoreShutdownUnconfirmed("Core shutdown evidence is unavailable")
    # Retry a previously failed directory flush before relying on visible bytes.
    flush_directory(paths.updates_root)
