"""Print auditing projects only safe spooler job fields."""

from __future__ import annotations

import ctypes
from datetime import UTC, datetime

from endpoint_contracts.endpoint_policy import EndpointPolicyV1
from pc_agent.platform.windows.print_sensor import (
    JOB_NOTIFY_FIELD_DOCUMENT,
    JOB_NOTIFY_FIELDS,
    PrintJobFacts,
    _PrinterNotifyInfo,
    _PrinterNotifyInfoData,
    _job_facts_from_info,
    project_print_job,
)
from tests.contracts.test_endpoint_policy_v1 import _policy


NOW = datetime(2026, 9, 25, 12, tzinfo=UTC)


def _print_policy(*, enabled: bool) -> EndpointPolicyV1:
    value = _policy()
    value["dlp"] = {
        **value["dlp"], "print_events": "audit" if enabled else "disabled",
    }
    return EndpointPolicyV1.model_validate(value)


def test_print_job_contract_excludes_document_field_even_from_subscription() -> None:
    assert JOB_NOTIFY_FIELD_DOCUMENT not in JOB_NOTIFY_FIELDS
    facts = PrintJobFacts(
        job_id=7, printer_name="Office-1", user_name="DOMAIN\\ivanova.aa",
        page_count=2, total_bytes=4096,
    )
    event = project_print_job(facts, _print_policy(enabled=True), occurred_at=NOW)
    assert event is not None
    assert event.event_type == "PRINT_JOB"
    assert event.channel == "PRINT"
    assert event.user_login == "DOMAIN\\ivanova.aa"
    assert event.safe_metadata.printer_identity == "Office-1"
    assert event.safe_metadata.page_count == 2
    assert event.safe_metadata.total_bytes == 4096
    assert event.safe_metadata.copies is None
    assert "document" not in event.model_dump_json().lower()


def test_print_job_is_disabled_without_applied_print_audit() -> None:
    facts = PrintJobFacts(job_id=7, printer_name="Office-1")
    assert project_print_job(facts, None, occurred_at=NOW) is None
    assert project_print_job(facts, _print_policy(enabled=False), occurred_at=NOW) is None


def test_unc_printer_name_is_pseudonymized_and_values_are_bounded() -> None:
    facts = PrintJobFacts(
        job_id=7, printer_name=r"\\private-server\shared-printer",
        user_name="too-long-" * 100, page_count=2_000_000, total_bytes=-1,
    )
    event = project_print_job(facts, _print_policy(enabled=True), occurred_at=NOW)
    assert event is not None
    assert event.safe_metadata.printer_identity.startswith("printer-")
    assert event.user_login is None
    assert event.safe_metadata.page_count is None
    assert event.safe_metadata.total_bytes is None
    assert "private-server" not in event.model_dump_json()


def test_native_notification_parser_skips_document_even_if_present() -> None:
    items = [
        (0, "Office-1"),
        (3, "DOMAIN\\ivanova.aa"),
        (JOB_NOTIFY_FIELD_DOCUMENT, "secret-document-title"),
        (0x14, 2),
        (0x16, 4096),
    ]
    offset = _PrinterNotifyInfo.aData.offset
    raw = ctypes.create_string_buffer(offset + len(items) * ctypes.sizeof(_PrinterNotifyInfoData))
    header = _PrinterNotifyInfo.from_buffer(raw)
    header.Count = len(items)
    buffers = []
    for index, (field, value) in enumerate(items):
        item = _PrinterNotifyInfoData.from_buffer(
            raw, offset + index * ctypes.sizeof(_PrinterNotifyInfoData),
        )
        item.Type = 1
        item.Field = field
        item.Id = 7
        if isinstance(value, str):
            encoded = value.encode("utf-16-le") + b"\0\0"
            native = ctypes.create_string_buffer(encoded)
            buffers.append(native)
            item.NotifyData.Data.cbBuf = len(encoded)
            item.NotifyData.Data.pBuf = ctypes.addressof(native)
        else:
            item.NotifyData.adwData[0] = value
    facts = _job_facts_from_info(ctypes.addressof(raw))
    assert facts == [PrintJobFacts(
        job_id=7, printer_name="Office-1", user_name="DOMAIN\\ivanova.aa",
        page_count=2, total_bytes=4096,
    )]
    assert "secret-document-title" not in repr(facts)
