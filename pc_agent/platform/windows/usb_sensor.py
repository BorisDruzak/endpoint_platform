"""Project bounded USB interface notifications into content-free audit events."""

from __future__ import annotations

import ctypes
import hashlib
import logging
import queue
import re
import threading
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Literal
from uuid import UUID, uuid4

from endpoint_contracts.endpoint_policy import EndpointPolicyV1
from endpoint_contracts.security_events import (
    UsbConnectedEventV1,
    UsbDisconnectedEventV1,
    UsbEventMetadataV1,
)


USB_INTERFACE_CLASS_GUID = "a5dcbf10-6530-11d2-901f-00c04fb951ed"
_USB_IDS = re.compile(r"VID_([0-9a-fA-F]{4})&PID_([0-9a-fA-F]{4})(?:&MI_[0-9a-fA-F]{2})?")
_STABLE_SERIAL = re.compile(r"[A-Za-z0-9_.-]{1,128}")
_MAX_SYMBOLIC_LINK_CHARS = 1024
_MAX_NATIVE_EVENT_BYTES = 24 + _MAX_SYMBOLIC_LINK_CHARS * 2
_MAX_PENDING_CHANGES = 256
_LOG = logging.getLogger(__name__)


class _Guid(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_uint32),
        ("Data2", ctypes.c_uint16),
        ("Data3", ctypes.c_uint16),
        ("Data4", ctypes.c_ubyte * 8),
    ]


class _NotifyFilterUnion(ctypes.Union):
    _fields_ = [
        ("DeviceInterface", _Guid),
        ("DeviceHandle", ctypes.c_void_p),
        ("DeviceInstance", ctypes.c_uint16 * 200),
    ]


class _NotifyFilter(ctypes.Structure):
    _fields_ = [
        ("cbSize", ctypes.c_uint32),
        ("Flags", ctypes.c_uint32),
        ("FilterType", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint32),
        ("u", _NotifyFilterUnion),
    ]


def _decode_usb_interface_path(event_data: int, event_data_size: int) -> str | None:
    """Copy only one bounded UTF-16 interface link from CM_NOTIFY_EVENT_DATA."""
    if not event_data or not 26 <= event_data_size <= _MAX_NATIVE_EVENT_BYTES:
        return None
    raw = ctypes.string_at(event_data, event_data_size)
    if int.from_bytes(raw[:4], "little") != 0:
        return None
    path_bytes = raw[24:]
    if len(path_bytes) % 2:
        return None
    try:
        decoded = path_bytes.decode("utf-16-le")
    except UnicodeDecodeError:
        return None
    path = decoded.split("\x00", 1)[0]
    return path if path and len(path) <= _MAX_SYMBOLIC_LINK_CHARS else None


class UsbInterfaceNotifications:
    """Register PnP callbacks and dispatch bounded changes off the OS thread."""

    def __init__(self, on_change: Callable[[str, str], None]) -> None:
        self._on_change = on_change
        self._pending: queue.Queue[tuple[str, str]] = queue.Queue(_MAX_PENDING_CHANGES)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._callback: object | None = None
        self._handle: ctypes.c_void_p | None = None
        self._cfgmgr: object | None = None
        self.dropped = 0
        self.failed = 0

    @property
    def available(self) -> bool:
        return self._handle is not None

    def start(self) -> None:
        if self.available:
            return
        if not hasattr(ctypes, "WinDLL") or not hasattr(ctypes, "WINFUNCTYPE"):
            raise OSError("USB PnP notification is available only on Windows")
        cfgmgr = ctypes.WinDLL("CfgMgr32", use_last_error=True)
        callback_type = ctypes.WINFUNCTYPE(
            ctypes.c_uint32, ctypes.c_void_p, ctypes.c_void_p,
            ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32,
        )
        register = cfgmgr.CM_Register_Notification
        register.argtypes = [
            ctypes.POINTER(_NotifyFilter), ctypes.c_void_p, callback_type,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        register.restype = ctypes.c_uint32
        cfgmgr.CM_Unregister_Notification.argtypes = [ctypes.c_void_p]
        cfgmgr.CM_Unregister_Notification.restype = ctypes.c_uint32
        filter_value = _NotifyFilter()
        filter_value.cbSize = ctypes.sizeof(_NotifyFilter)
        filter_value.FilterType = 0  # CM_NOTIFY_FILTER_TYPE_DEVICEINTERFACE
        filter_value.u.DeviceInterface = _Guid.from_buffer_copy(
            UUID(USB_INTERFACE_CLASS_GUID).bytes_le
        )

        def callback(
            _notification: int, _context: int, action: int,
            event_data: int, event_data_size: int,
        ) -> int:
            try:
                if action not in (0, 1):
                    return 0
                path = _decode_usb_interface_path(event_data, event_data_size)
                if path is not None:
                    self._pending.put_nowait((
                        "arrived" if action == 0 else "removed", path,
                    ))
            except queue.Full:
                self.dropped += 1
            except Exception:
                self.failed += 1
            return 0

        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        self._callback = callback_type(callback)
        handle = ctypes.c_void_p()
        result = register(
            ctypes.byref(filter_value), None, self._callback, ctypes.byref(handle)
        )
        if result != 0:
            self._stop.set()
            self._thread.join(timeout=1)
            self._thread = None
            self._callback = None
            raise OSError(f"USB PnP notification registration failed ({result})")
        self._handle = handle
        self._cfgmgr = cfgmgr

    def stop(self) -> None:
        handle = self._handle
        if handle is not None:
            assert self._cfgmgr is not None
            result = self._cfgmgr.CM_Unregister_Notification(handle)
            if result != 0:
                raise OSError(f"USB PnP notification unregister failed ({result})")
            self._handle = None
            self._callback = None
            self._cfgmgr = None
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.5)
            self._thread = None
        while True:
            try:
                self._pending.get_nowait()
            except queue.Empty:
                break
            self.dropped += 1

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                action, path = self._pending.get(timeout=0.1)
            except queue.Empty:
                continue
            try:
                self._on_change(action, path)
            except Exception:
                self.failed += 1
                _LOG.warning("USB audit change dispatch failed")


def project_usb_change(
    action: Literal["arrived", "removed"],
    symbolic_link: str,
    policy: EndpointPolicyV1 | None,
    *,
    occurred_at: datetime,
) -> UsbConnectedEventV1 | UsbDisconnectedEventV1 | None:
    """Keep only bounded VID/PID and a hash of a stable instance serial."""
    if policy is None or policy.dlp.usb_device_events != "audit":
        return None
    if action not in {"arrived", "removed"}:
        return None
    if occurred_at.tzinfo is None or occurred_at.utcoffset() is None:
        raise ValueError("USB event time must be timezone-aware")
    if not isinstance(symbolic_link, str) or len(symbolic_link) > _MAX_SYMBOLIC_LINK_CHARS:
        return None
    parts = symbolic_link.split("#")
    if len(parts) != 4 or parts[0].casefold() != r"\\?\usb":
        return None
    match = _USB_IDS.fullmatch(parts[1])
    if match is None or parts[3].casefold() != "{" + USB_INTERFACE_CLASS_GUID + "}":
        return None
    vendor_id, product_id = (item.lower() for item in match.groups())
    serial_hash = None
    if _STABLE_SERIAL.fullmatch(parts[2]):
        identity = f"{vendor_id}:{product_id}:{parts[2].lower()}"
        serial_hash = hashlib.sha256(identity.encode("ascii")).hexdigest()
    metadata = UsbEventMetadataV1(
        vendor=f"VID_{vendor_id.upper()}",
        product=f"PID_{product_id.upper()}",
        removable=True,
        serial_hash=serial_hash,
    )
    common = dict(
        schema_version="security_event_v1",
        event_identifier=uuid4(),
        severity="INFO",
        occurred_at=occurred_at.astimezone(UTC),
        user_login=None,
        policy_id=policy.policy_id,
        policy_version=policy.policy_version,
        channel="USB",
        safe_metadata=metadata,
    )
    if action == "arrived":
        return UsbConnectedEventV1(event_type="USB_DEVICE_CONNECTED", **common)
    return UsbDisconnectedEventV1(event_type="USB_DEVICE_DISCONNECTED", **common)
