"""Shared content-free print projection for native Windows and Linux sources."""
from __future__ import annotations
from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
import re
from uuid import UUID, uuid4
from endpoint_contracts.endpoint_policy import EndpointPolicyV1
from endpoint_contracts.security_events import PrintEventMetadataV1, PrintJobEventV1

_SAFE_PRINTER = re.compile(r"[^\\/:\x00-\x1f]{1,128}\Z")
_SAFE_USER = re.compile(r"[^\x00-\x1f]{1,256}\Z")


@dataclass(frozen=True, slots=True)
class PrintJobFacts:
    """Safe subset of an ADD_JOB notification; job ID stays local."""

    job_id: int
    printer_name: str
    user_name: str | None = None
    page_count: int | None = None
    total_bytes: int | None = None
    copies: int | None = None


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
    event_identifier: UUID | None = None,
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
    copies = facts.copies
    if type(copies) is not int or not 1 <= copies <= 1_000_000:
        copies = None
    return PrintJobEventV1(
        schema_version="security_event_v1",
        event_identifier=event_identifier or uuid4(),
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
            copies=copies,
            total_bytes=size,
        ),
    )
