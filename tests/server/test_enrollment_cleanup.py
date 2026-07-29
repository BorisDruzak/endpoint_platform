"""Expired enrollment-delivery envelope cleanup tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy.dialects import postgresql

from endpoint_server.db.models import AuditEvent, EnrollmentRetryEnvelope
from endpoint_server.enrollment.delivery import cleanup_expired_retry_envelopes


NOW = datetime(2026, 7, 29, 12, tzinfo=UTC)


def _envelope(*, seconds_ago: int) -> EnrollmentRetryEnvelope:
    return EnrollmentRetryEnvelope(
        id=uuid4(),
        device_credential_id=uuid4(),
        receipt_digest="receipt-digest-" + uuid4().hex,
        fingerprint_digest="fingerprint-digest-" + uuid4().hex,
        encrypted_token=b"ciphertext",
        encryption_nonce=b"012345678901",
        expires_at=NOW - timedelta(seconds=seconds_ago),
    )


class _ScalarRows:
    def __init__(self, rows: list[EnrollmentRetryEnvelope]) -> None:
        self.rows = rows

    def all(self) -> list[EnrollmentRetryEnvelope]:
        return self.rows


class _Result:
    def __init__(self, rows: list[EnrollmentRetryEnvelope]) -> None:
        self.rows = rows

    def scalars(self) -> _ScalarRows:
        return _ScalarRows(self.rows)


class _CleanupSession:
    def __init__(self, rows: list[EnrollmentRetryEnvelope]) -> None:
        self.rows = rows
        self.statement: object | None = None
        self.added: list[object] = []
        self.deleted: list[object] = []

    async def execute(self, statement: object) -> _Result:
        self.statement = statement
        return _Result(self.rows)

    def add(self, value: object) -> None:
        self.added.append(value)

    async def delete(self, value: object) -> None:
        self.deleted.append(value)


@pytest.mark.asyncio
async def test_cleanup_locks_bounded_expired_batch_and_audits_each_delete() -> None:
    """An unbounded or unlocked cleanup could race workers or monopolize a table."""
    envelopes = [_envelope(seconds_ago=2), _envelope(seconds_ago=1)]
    session = _CleanupSession(envelopes)

    cleaned = await cleanup_expired_retry_envelopes(
        session,
        request_id="server_cleanup_request",
        now=NOW,
    )

    assert cleaned == 2
    assert session.deleted == envelopes
    audits = [value for value in session.added if isinstance(value, AuditEvent)]
    assert [audit.action for audit in audits] == [
        "enrollment.delivery_expired",
        "enrollment.delivery_expired",
    ]
    assert [audit.object_identifier for audit in audits] == [
        str(envelope.id) for envelope in envelopes
    ]
    assert all(audit.details == {"source": "periodic_cleanup"} for audit in audits)
    sql = str(
        session.statement.compile(
            dialect=postgresql.dialect(),
            compile_kwargs={"literal_binds": True},
        )
    )
    assert "ORDER BY enrollment_retry_envelopes.expires_at" in sql
    assert "enrollment_retry_envelopes.id" in sql
    assert "LIMIT 100" in sql
    assert "FOR UPDATE SKIP LOCKED" in sql


@pytest.mark.asyncio
async def test_cleanup_rejects_unbounded_or_invalid_limit() -> None:
    """Callers must not turn one cleanup pass into an unbounded operation."""
    session = _CleanupSession([])

    for limit in (0, 101):
        with pytest.raises(ValueError, match="between 1 and 100"):
            await cleanup_expired_retry_envelopes(
                session,
                request_id="server_cleanup_request",
                now=NOW,
                limit=limit,
            )

    assert session.statement is None
