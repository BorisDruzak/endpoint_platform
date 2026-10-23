"""Bounded, metadata-only IPP queries to the local CUPS Unix socket.

No browser/user configuration, remote print servers or document attributes
are read. Printer and job requests share the installed CUPS protocol.
"""
from __future__ import annotations

from datetime import UTC, datetime
import http.client
import socket
import struct

MAX_RESPONSE_BYTES = 65536
MAX_RECORDS = 128
_SOCKET = "/run/cups/cups.sock"
_PRINTER_ATTRIBUTES = ("printer-name", "printer-state", "printer-make-and-model", "printer-type")
_JOB_ATTRIBUTES = ("job-id", "job-state", "time-at-creation")
AUDIT_JOB_ATTRIBUTES = (*_JOB_ATTRIBUTES, 'job-uuid', 'job-printer-uri', 'job-impressions', 'copies')


class _LocalCupsConnection(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        try:
            self.sock.connect(_SOCKET)
        except BaseException:
            self.sock.close()
            raise


def _attribute(tag: int, name: str, value: str | int) -> bytes:
    key = name.encode("ascii")
    data = struct.pack(">i", value) if isinstance(value, int) else value.encode("ascii")
    return bytes([tag]) + struct.pack(">H", len(key)) + key + struct.pack(">H", len(data)) + data


def query(operation: int, attributes: tuple[str, ...], *, which_jobs: str = "not-completed",
          first_job_id: int | None = None, allow_page: bool = False) -> list[dict[str, object]]:
    if operation not in {0x000A, 0x4002} or which_jobs not in {"not-completed", "all"}:
        raise ValueError("CUPS_QUERY_INVALID")
    if type(allow_page) is not bool or (allow_page and (operation != 0x000A or which_jobs != 'all')):
        raise ValueError('CUPS_PAGE_INVALID')
    if first_job_id is not None and (not allow_page or type(first_job_id) is not int or not 1 <= first_job_id < 2**31):
        raise ValueError('CUPS_PAGE_INVALID')
    allowed = set(_PRINTER_ATTRIBUTES if operation == 0x4002 else AUDIT_JOB_ATTRIBUTES)
    if not attributes or not set(attributes) <= allowed:
        raise ValueError("CUPS_ATTRIBUTES_INVALID")
    request = struct.pack(">BBHI", 1, 1, operation, 1) + b"\x01"
    request += _attribute(0x47, "attributes-charset", "utf-8")
    request += _attribute(0x48, "attributes-natural-language", "en")
    if operation == 0x000A:
        request += _attribute(0x45, "printer-uri", "ipp://localhost/")
        request += _attribute(0x44, "which-jobs", which_jobs)
        if first_job_id is not None:
            request += _attribute(0x21, 'first-job-id', first_job_id)
    request += _attribute(0x21, "limit", MAX_RECORDS)
    for index, name in enumerate(attributes):
        request += _attribute(0x44, "requested-attributes" if index == 0 else "", name)
    request += b"\x03"
    connection = _LocalCupsConnection("localhost", timeout=3)
    try:
        connection.request("POST", "/", body=request, headers={"Content-Type": "application/ipp"})
        response = connection.getresponse()
        if response.status != 200 or response.getheader("Content-Type", "").split(";", 1)[0] != "application/ipp":
            raise OSError("CUPS_RESPONSE_UNAVAILABLE")
        raw = response.read(MAX_RESPONSE_BYTES + 1)
        rows = parse_response(raw, operation=operation)
        # A response at the requested limit might omit more jobs/printers.
        # Never report an incomplete enumeration as an accurate summary.
        if len(rows) >= MAX_RECORDS and not allow_page:
            raise ValueError("CUPS_RECORD_LIMIT")
        return rows
    finally:
        connection.close()


def parse_response(raw: bytes, *, operation: int | None = None) -> list[dict[str, object]]:
    if not 9 <= len(raw) <= MAX_RESPONSE_BYTES:
        raise ValueError("CUPS_RESPONSE_SIZE")
    major, minor, status, request_id = struct.unpack_from(">BBHI", raw)
    if (major, minor) != (1, 1) or request_id != 1:
        raise ValueError("CUPS_RESPONSE_HEADER")
    # CUPS-Get-Printers returns client-error-not-found when no queues exist.
    # Get-Jobs and every other failure retain their failure semantics.
    empty_printers = status == 0x0406 and operation == 0x4002
    if status > 0x00FF and not empty_printers:
        raise OSError("CUPS_QUERY_FAILED")
    offset, group, name = 8, 0, ""
    rows: list[dict[str, object]] = []
    row: dict[str, object] | None = None
    while offset < len(raw):
        tag = raw[offset]
        offset += 1
        if tag == 3:
            if offset != len(raw):
                raise ValueError("CUPS_UNEXPECTED_BODY")
            if empty_printers and rows:
                raise ValueError('CUPS_UNEXPECTED_PRINTERS')
            return rows
        if tag < 0x10:
            if tag not in {1, 2, 4, 5}:
                raise ValueError("CUPS_GROUP_INVALID")
            group, name = tag, ""
            row = {} if group in {2, 4} else None
            if row is not None:
                rows.append(row)
                if len(rows) > MAX_RECORDS:
                    raise ValueError("CUPS_RECORD_LIMIT")
            continue
        if offset + 2 > len(raw):
            raise ValueError("CUPS_ATTRIBUTE_TRUNCATED")
        name_size = int.from_bytes(raw[offset:offset + 2], "big")
        offset += 2
        if name_size > 128 or offset + name_size + 2 > len(raw):
            raise ValueError("CUPS_ATTRIBUTE_TRUNCATED")
        if name_size:
            name = raw[offset:offset + name_size].decode("ascii")
        elif not name:
            raise ValueError("CUPS_ATTRIBUTE_NAME_MISSING")
        offset += name_size
        size = int.from_bytes(raw[offset:offset + 2], "big")
        offset += 2
        if offset + size > len(raw):
            raise ValueError("CUPS_VALUE_TRUNCATED")
        data = raw[offset:offset + size]
        offset += size
        if row is None:
            continue
        if name in row:
            raise ValueError("CUPS_DUPLICATE_ATTRIBUTE")
        if name not in {*_PRINTER_ATTRIBUTES, *AUDIT_JOB_ATTRIBUTES}:
            continue
        if tag in {0x21, 0x23} and size == 4:
            row[name] = int.from_bytes(data, "big", signed=True)
        elif tag in {0x41, 0x42, 0x44, 0x45} and size <= (512 if tag == 0x45 else 256):
            row[name] = data.decode("utf-8", errors="strict")
        else:
            raise ValueError("CUPS_ATTRIBUTE_TYPE_INVALID")
    raise ValueError("CUPS_RESPONSE_INCOMPLETE")


def printers() -> list[dict[str, object]]:
    result = []
    for row in query(0x4002, _PRINTER_ATTRIBUTES):
        name, state = row.get("printer-name"), row.get("printer-state")
        if not isinstance(name, str) or not name or state not in {3, 4, 5}:
            raise ValueError("CUPS_PRINTER_INVALID")
        printer_type = row.get("printer-type", 0)
        result.append({"name": name, "driver_name": row.get("printer-make-and-model"), "port_name": "", "default": bool(isinstance(printer_type, int) and printer_type & 0x20000), "state": "paused" if state == 5 else "ready"})
    return result[:16]


def queue_summary() -> dict[str, object]:
    rows = query(0x000A, _JOB_ATTRIBUTES)
    counts = {"job_count": len(rows), "printing_count": 0, "queued_count": 0, "paused_count": 0, "error_count": 0}
    ages = []
    for row in rows:
        state = row.get("job-state")
        if state not in {3, 4, 5, 6}:
            raise ValueError("CUPS_JOB_STATE_INVALID")
        counts[{3: "queued_count", 4: "paused_count", 5: "printing_count", 6: "error_count"}[state]] += 1
        created = row.get("time-at-creation")
        if isinstance(created, int) and 0 < created <= datetime.now(UTC).timestamp():
            ages.append(max(0, int(datetime.now(UTC).timestamp()) - created))
    return {**counts, "oldest_job_age_seconds": max(ages) if len(ages) == len(rows) and ages else None}
