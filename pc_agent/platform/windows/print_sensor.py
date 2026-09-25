"""Observe local spooler job additions without requesting document titles."""

from __future__ import annotations

import ctypes
import hashlib
import logging
import re
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import uuid4

from endpoint_contracts.endpoint_policy import EndpointPolicyV1
from endpoint_contracts.security_events import PrintEventMetadataV1, PrintJobEventV1


JOB_NOTIFY_FIELD_PRINTER_NAME = 0
JOB_NOTIFY_FIELD_USER_NAME = 3
JOB_NOTIFY_FIELD_DOCUMENT = 0x0D
JOB_NOTIFY_FIELD_TOTAL_PAGES = 0x14
JOB_NOTIFY_FIELD_TOTAL_BYTES = 0x16
JOB_NOTIFY_FIELDS = (
    JOB_NOTIFY_FIELD_PRINTER_NAME,
    JOB_NOTIFY_FIELD_USER_NAME,
    JOB_NOTIFY_FIELD_TOTAL_PAGES,
    JOB_NOTIFY_FIELD_TOTAL_BYTES,
)

_JOB_NOTIFY_TYPE = 1
_PRINTER_CHANGE_ADD_JOB = 0x100
_PRINTER_NOTIFY_INFO_DISCARDED = 0x01
_PRINTER_NOTIFY_OPTIONS_REFRESH = 0x01
_WAIT_OBJECT_0 = 0
_WAIT_TIMEOUT = 0x102
_WAIT_FAILED = 0xFFFFFFFF
_MAX_NOTIFY_ITEMS = 256
_MAX_STRING_BYTES = 512
_SAFE_PRINTER = re.compile(r"[^\\/:\x00-\x1f]{1,128}\Z")
_SAFE_USER = re.compile(r"[^\x00-\x1f]{1,256}\Z")
_LOG = logging.getLogger(__name__)


class _NotifyDataBuffer(ctypes.Structure):
    _fields_ = [("cbBuf", ctypes.c_uint32), ("pBuf", ctypes.c_void_p)]


class _NotifyData(ctypes.Union):
    _fields_ = [("adwData", ctypes.c_uint32 * 2), ("Data", _NotifyDataBuffer)]


class _PrinterNotifyInfoData(ctypes.Structure):
    _fields_ = [
        ("Type", ctypes.c_uint16),
        ("Field", ctypes.c_uint16),
        ("Reserved", ctypes.c_uint32),
        ("Id", ctypes.c_uint32),
        ("NotifyData", _NotifyData),
    ]


class _PrinterNotifyInfo(ctypes.Structure):
    _fields_ = [
        ("Version", ctypes.c_uint32),
        ("Flags", ctypes.c_uint32),
        ("Count", ctypes.c_uint32),
        ("aData", _PrinterNotifyInfoData * 1),
    ]


class _PrinterNotifyOptionsType(ctypes.Structure):
    _fields_ = [
        ("Type", ctypes.c_uint16),
        ("Reserved0", ctypes.c_uint16),
        ("Reserved1", ctypes.c_uint32),
        ("Reserved2", ctypes.c_uint32),
        ("Count", ctypes.c_uint32),
        ("pFields", ctypes.POINTER(ctypes.c_uint16)),
    ]


class _PrinterNotifyOptions(ctypes.Structure):
    _fields_ = [
        ("Version", ctypes.c_uint32),
        ("Flags", ctypes.c_uint32),
        ("Count", ctypes.c_uint32),
        ("pTypes", ctypes.POINTER(_PrinterNotifyOptionsType)),
    ]


@dataclass(frozen=True, slots=True)
class PrintJobFacts:
    """Safe subset of an ADD_JOB notification; job ID stays local."""

    job_id: int
    printer_name: str
    user_name: str | None = None
    page_count: int | None = None
    total_bytes: int | None = None


def _safe_printer_name(name: str) -> str | None:
    if not isinstance(name, str) or not name or len(name) > 512:
        return None
    if _SAFE_PRINTER.fullmatch(name):
        return name
    return "printer-" + hashlib.sha256(name.encode("utf-8")).hexdigest()[:32]


def project_print_job(
    facts: PrintJobFacts,
    policy: EndpointPolicyV1 | None,
    *,
    occurred_at: datetime,
) -> PrintJobEventV1 | None:
    """Apply the policy gate before creating a content-free PRINT_JOB event."""
    if policy is None or policy.dlp.print_events != "audit":
        return None
    if occurred_at.tzinfo is None or occurred_at.utcoffset() is None:
        raise ValueError("print event time must be timezone-aware")
    printer_identity = _safe_printer_name(facts.printer_name)
    if printer_identity is None:
        return None
    user = facts.user_name
    if user is not None and (not isinstance(user, str) or not _SAFE_USER.fullmatch(user)):
        user = None
    pages = facts.page_count
    if type(pages) is not int or not 0 <= pages <= 1_000_000:
        pages = None
    size = facts.total_bytes
    if type(size) is not int or not 0 <= size <= 2**53 - 1:
        size = None
    return PrintJobEventV1(
        schema_version="security_event_v1",
        event_identifier=uuid4(),
        severity="INFO",
        occurred_at=occurred_at.astimezone(UTC),
        user_login=user,
        policy_id=policy.policy_id,
        policy_version=policy.policy_version,
        event_type="PRINT_JOB",
        channel="PRINT",
        safe_metadata=PrintEventMetadataV1(
            printer_identity=printer_identity,
            page_count=pages,
            total_bytes=size,
        ),
    )


def _read_notify_string(item: _PrinterNotifyInfoData) -> str | None:
    length = item.NotifyData.Data.cbBuf
    address = item.NotifyData.Data.pBuf
    if not address or not 2 <= length <= _MAX_STRING_BYTES or length % 2:
        return None
    try:
        value = ctypes.string_at(address, length).decode("utf-16-le").rstrip("\x00")
    except (UnicodeDecodeError, ValueError):
        return None
    return value or None


def _job_facts_from_info(address: int) -> list[PrintJobFacts]:
    """Read only subscribed fields from one bounded, system-owned notification."""
    if not address:
        return []
    header = _PrinterNotifyInfo.from_address(address)
    if header.Count > _MAX_NOTIFY_ITEMS:
        return []
    first = address + _PrinterNotifyInfo.aData.offset
    grouped: dict[int, dict[str, str | int]] = {}
    for index in range(header.Count):
        item = _PrinterNotifyInfoData.from_address(
            first + index * ctypes.sizeof(_PrinterNotifyInfoData)
        )
        if item.Type != _JOB_NOTIFY_TYPE or item.Field not in JOB_NOTIFY_FIELDS:
            continue
        values = grouped.setdefault(item.Id, {})
        if item.Field == JOB_NOTIFY_FIELD_PRINTER_NAME:
            name = _read_notify_string(item)
            if name is not None:
                values["printer_name"] = name
        elif item.Field == JOB_NOTIFY_FIELD_USER_NAME:
            user = _read_notify_string(item)
            if user is not None:
                values["user_name"] = user
        elif item.Field == JOB_NOTIFY_FIELD_TOTAL_PAGES:
            values["page_count"] = item.NotifyData.adwData[0]
        elif item.Field == JOB_NOTIFY_FIELD_TOTAL_BYTES:
            values["total_bytes"] = item.NotifyData.adwData[0]
    return [
        PrintJobFacts(job_id=job_id, **values)
        for job_id, values in grouped.items()
        if "printer_name" in values
    ]


class PrintJobNotifications:
    """Subscribe to local server ADD_JOB changes on a dedicated worker."""

    def __init__(self, on_job: Callable[[PrintJobFacts], None]) -> None:
        self._on_job = on_job
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._spooler: object | None = None
        self._kernel: object | None = None
        self._printer = ctypes.c_void_p()
        self._notification = ctypes.c_void_p()
        self.failed = 0
        self.dropped = 0

    @property
    def available(self) -> bool:
        return bool(
            self._notification.value
            and self._thread is not None
            and self._thread.is_alive()
            and not self._stop.is_set()
        )

    def start(self) -> None:
        if self.available:
            return
        if self._notification.value:
            raise RuntimeError("print notification must be stopped before restart")
        if not hasattr(ctypes, "WinDLL"):
            raise OSError("print notifications are available only on Windows")
        spooler = ctypes.WinDLL("Winspool.drv", use_last_error=True)
        kernel = ctypes.WinDLL("Kernel32", use_last_error=True)
        spooler.OpenPrinterW.argtypes = [
            ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p,
        ]
        spooler.OpenPrinterW.restype = ctypes.c_int
        spooler.ClosePrinter.argtypes = [ctypes.c_void_p]
        spooler.ClosePrinter.restype = ctypes.c_int
        spooler.FindFirstPrinterChangeNotification.argtypes = [
            ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32,
            ctypes.POINTER(_PrinterNotifyOptions),
        ]
        spooler.FindFirstPrinterChangeNotification.restype = ctypes.c_void_p
        spooler.FindNextPrinterChangeNotification.argtypes = [
            ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32),
            ctypes.POINTER(_PrinterNotifyOptions), ctypes.POINTER(ctypes.c_void_p),
        ]
        spooler.FindNextPrinterChangeNotification.restype = ctypes.c_int
        spooler.FreePrinterNotifyInfo.argtypes = [ctypes.c_void_p]
        spooler.FreePrinterNotifyInfo.restype = ctypes.c_int
        spooler.FindClosePrinterChangeNotification.argtypes = [ctypes.c_void_p]
        spooler.FindClosePrinterChangeNotification.restype = ctypes.c_int
        kernel.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        kernel.WaitForSingleObject.restype = ctypes.c_uint32

        fields = (ctypes.c_uint16 * len(JOB_NOTIFY_FIELDS))(*JOB_NOTIFY_FIELDS)
        option_type = _PrinterNotifyOptionsType(
            Type=_JOB_NOTIFY_TYPE, Count=len(fields), pFields=fields,
        )
        options = _PrinterNotifyOptions(
            Version=2, Count=1, pTypes=ctypes.pointer(option_type),
        )
        if not spooler.OpenPrinterW(None, ctypes.byref(self._printer), None):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            raw = spooler.FindFirstPrinterChangeNotification(
                self._printer, _PRINTER_CHANGE_ADD_JOB, 0, ctypes.byref(options),
            )
            if raw in (None, ctypes.c_void_p(-1).value):
                raise ctypes.WinError(ctypes.get_last_error())
            self._notification = ctypes.c_void_p(raw)
            self._spooler = spooler
            self._kernel = kernel
            self._stop.clear()
            self._thread = threading.Thread(target=self._run, daemon=True)
            self._thread.start()
        except Exception:
            if self._notification.value:
                spooler.FindClosePrinterChangeNotification(self._notification)
                self._notification = ctypes.c_void_p()
            spooler.ClosePrinter(self._printer)
            self._printer = ctypes.c_void_p()
            self._spooler = None
            self._kernel = None
            raise

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2)
            if self._thread.is_alive():
                raise RuntimeError("print notification worker did not stop")
            self._thread = None
        if self._notification.value:
            assert self._spooler is not None
            self._spooler.FindClosePrinterChangeNotification(self._notification)
            self._spooler.ClosePrinter(self._printer)
            self._notification = ctypes.c_void_p()
            self._printer = ctypes.c_void_p()
            self._spooler = None
            self._kernel = None

    def _run(self) -> None:
        assert self._kernel is not None and self._spooler is not None
        while not self._stop.is_set():
            state = self._kernel.WaitForSingleObject(self._notification, 250)
            if state == _WAIT_TIMEOUT:
                continue
            if state == _WAIT_FAILED:
                self.failed += 1
                return
            if state != _WAIT_OBJECT_0:
                self.failed += 1
                return
            changes = ctypes.c_uint32()
            info = ctypes.c_void_p()
            try:
                if not self._spooler.FindNextPrinterChangeNotification(
                    self._notification, ctypes.byref(changes), None, ctypes.byref(info),
                ):
                    self.failed += 1
                    return
                if not info.value:
                    continue
                header = _PrinterNotifyInfo.from_address(info.value)
                if header.Flags & _PRINTER_NOTIFY_INFO_DISCARDED:
                    self.dropped += 1
                    self._refresh()
                    continue
                if not changes.value & _PRINTER_CHANGE_ADD_JOB:
                    continue
                for facts in _job_facts_from_info(info.value):
                    try:
                        self._on_job(facts)
                    except Exception:
                        self.failed += 1
                        _LOG.warning("print audit job dispatch failed")
            finally:
                if info.value:
                    self._spooler.FreePrinterNotifyInfo(info)

    def _refresh(self) -> None:
        assert self._spooler is not None
        fields = (ctypes.c_uint16 * len(JOB_NOTIFY_FIELDS))(*JOB_NOTIFY_FIELDS)
        option_type = _PrinterNotifyOptionsType(
            Type=_JOB_NOTIFY_TYPE, Count=len(fields), pFields=fields,
        )
        options = _PrinterNotifyOptions(
            Version=2, Flags=_PRINTER_NOTIFY_OPTIONS_REFRESH,
            Count=1, pTypes=ctypes.pointer(option_type),
        )
        changes = ctypes.c_uint32()
        info = ctypes.c_void_p()
        if not self._spooler.FindNextPrinterChangeNotification(
            self._notification, ctypes.byref(changes),
            ctypes.byref(options), ctypes.byref(info),
        ):
            self.failed += 1
            self._stop.set()
        if info.value:
            self._spooler.FreePrinterNotifyInfo(info)
