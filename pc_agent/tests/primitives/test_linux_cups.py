"""Local IPP requests must bound data and explicitly exclude document fields."""
from datetime import UTC, datetime
import struct

import pytest


def _attr(tag, name, value):
    name = name.encode()
    value = struct.pack(">i", value) if isinstance(value, int) else value.encode()
    return bytes([tag]) + struct.pack(">H", len(name)) + name + struct.pack(">H", len(value)) + value


def test_cups_queue_uses_safe_attributes_and_correct_job_states(monkeypatch):
    from pc_agent.platform.linux import cups

    now = int(datetime.now(UTC).timestamp())
    rows = [{"job-state": state, "time-at-creation": now - 30} for state in (3, 4, 5, 6)]
    def query(operation, attributes, **kwargs):
        assert operation == 0x000A
        assert "job-name" not in attributes and "job-originating-user-name" not in attributes
        return rows
    monkeypatch.setattr(cups, "query", query)
    result = cups.queue_summary()
    assert result == {"job_count": 4, "printing_count": 1, "queued_count": 1, "paused_count": 1, "error_count": 1, "oldest_job_age_seconds": 30}


def test_ipp_parser_preserves_records_and_repeated_attributes():
    from pc_agent.platform.linux.cups import parse_response

    packet = struct.pack(">BBHI", 1, 1, 0, 1) + b"\x02" + _attr(0x21, "job-id", 1) + _attr(0x23, "job-state", 3) + b"\x02" + _attr(0x21, "job-id", 2) + _attr(0x23, "job-state", 5) + b"\x03"
    assert parse_response(packet) == [{"job-id": 1, "job-state": 3}, {"job-id": 2, "job-state": 5}]


@pytest.mark.parametrize("packet", [b"", struct.pack(">BBHI", 1, 1, 0x0401, 1) + b"\x03", struct.pack(">BBHI", 1, 1, 0, 2) + b"\x03", struct.pack(">BBHI", 1, 1, 0, 1) + b"\x02\x21\xff\xff"], ids=["empty", "denied", "wrong-request", "truncated"])
def test_ipp_parser_rejects_invalid_response(packet):
    from pc_agent.platform.linux.cups import parse_response

    with pytest.raises((OSError, ValueError)):
        parse_response(packet)


def test_cups_no_printers_status_is_empty_only_for_printer_enumeration():
    from pc_agent.platform.linux.cups import parse_response
    packet = struct.pack('>BBHI',1,1,0x0406,1)+b'\x03'
    assert parse_response(packet, operation=0x4002) == []
    with pytest.raises(OSError):
        parse_response(packet, operation=0x000A)
    with pytest.raises(OSError):
        parse_response(packet)
    with pytest.raises(ValueError):
        parse_response(packet[:-1], operation=0x4002)
    with pytest.raises(ValueError):
        parse_response(packet[:-1]+b'\x04'+_attr(0x42,'printer-name','untrusted')+b'\x03', operation=0x4002)


def test_cups_printers_project_state_without_device_uri_or_description(monkeypatch):
    from pc_agent.platform.linux import cups

    monkeypatch.setattr(cups, "query", lambda *a, **k: [{"printer-name": "Office", "printer-state": 4, "printer-make-and-model": "Driver", "printer-type": 0, "device-uri": "smb://secret@server/path", "printer-info": "private"}])
    printers = cups.printers()
    assert printers[0]["name"] == "Office" and printers[0]["state"] == "ready"
    assert "secret" not in str(printers) and "private" not in str(printers)


def test_linux_queue_is_wired_to_existing_handler(monkeypatch):
    from pc_agent.platform.linux import cups
    from pc_agent.primitives.service_printer import handlers
    from endpoint_contracts.service_printer_primitives import PrinterQueueSummaryParametersV1

    monkeypatch.setattr(handlers, "_platform", lambda: "linux")
    monkeypatch.setattr(cups, "queue_summary", lambda: {"job_count": 1, "printing_count": 1, "queued_count": 0, "paused_count": 0, "error_count": 0})
    result = handlers.printer_queue_summary(PrinterQueueSummaryParametersV1(schema_version="printer_queue_summary_parameters_v1"))
    assert result.status == "succeeded" and result.printing_count == 1
