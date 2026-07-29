"""Security-focused tests for append-only redacted audit events."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta, timezone
from pathlib import PurePosixPath
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects import postgresql
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Session

from endpoint_server.audit.redaction import REDACTED, redact_audit_details
from endpoint_server.audit.service import (
    AuditMutationError,
    append_audit_event,
)
from endpoint_server.db.models import AuditEvent


class _AuditSession:
    def __init__(self) -> None:
        self.added: list[object] = []
        self.commit_calls = 0

    def add(self, value: object) -> None:
        self.added.append(value)

    async def commit(self) -> None:
        self.commit_calls += 1


def test_recursive_redaction_produces_json_safe_independent_details() -> None:
    """Nested credential fields or bearer text must never survive sanitization."""
    object_id = uuid4()
    source = {
        "Password": "password-marker",
        "nested": (
            {
                "access_token": "token-marker",
                "Authorization": "Basic authorization-marker",
                "headers": {"Cookie": "session=cookie-marker"},
            },
            {
                "clientSecret": "secret-marker",
                "bearer": "bearer-marker",
                "message": "failed for Bearer bearer-value at upstream",
            },
        ),
        "at": datetime(2026, 7, 29, 8, 30, tzinfo=UTC),
        "object_id": object_id,
        "path": PurePosixPath("safe/relative"),
    }

    redacted = redact_audit_details(source)

    assert redacted == {
        "Password": REDACTED,
        "nested": [
            {
                "access_token": REDACTED,
                "Authorization": REDACTED,
                "headers": {"Cookie": REDACTED},
            },
            {
                "clientSecret": REDACTED,
                "bearer": REDACTED,
                "message": f"failed for Bearer {REDACTED} at upstream",
            },
        ],
        "at": "2026-07-29T08:30:00+00:00",
        "object_id": str(object_id),
        "path": "safe/relative",
    }
    assert source["Password"] == "password-marker"
    json.dumps(redacted, allow_nan=False)


def test_redaction_rejects_non_json_safe_values_and_cycles() -> None:
    """Silent repr fallbacks or recursion would leak opaque object state."""

    class _Opaque:
        pass

    cyclic: list[object] = []
    cyclic.append(cyclic)

    with pytest.raises(TypeError, match="JSON-safe"):
        redact_audit_details({"value": _Opaque()})
    with pytest.raises(ValueError, match="circular"):
        redact_audit_details(cyclic)
    with pytest.raises(ValueError, match="finite"):
        redact_audit_details({"value": float("nan")})


@pytest.mark.asyncio
async def test_append_attributes_event_in_utc_and_persists_only_redacted_details() -> (
    None
):
    """Losing actor, object, request, UTC, or redaction breaks audit attribution."""
    session = _AuditSession()
    occurred_at = datetime(
        2026,
        7,
        29,
        13,
        45,
        tzinfo=timezone(timedelta(hours=5)),
    )

    event = await append_audit_event(
        session,
        actor_kind="admin",
        actor_identifier="admin-42",
        action="service_credential.created",
        object_kind="service_credential",
        object_identifier="credential-7",
        request_id="request-123",
        details={
            "scope_count": 2,
            "credentials": [{"token": "token-marker"}],
        },
        occurred_at=occurred_at,
    )

    assert event.actor_kind == "admin"
    assert event.actor_identifier == "admin-42"
    assert event.action == "service_credential.created"
    assert event.object_kind == "service_credential"
    assert event.object_identifier == "credential-7"
    assert event.request_id == "request-123"
    assert event.created_at == datetime(2026, 7, 29, 8, 45, tzinfo=UTC)
    assert event.created_at.tzinfo is UTC
    assert event.details == {
        "scope_count": 2,
        "credentials": [{"token": REDACTED}],
    }
    assert session.added == [event]
    assert session.commit_calls == 1


@pytest.mark.asyncio
async def test_append_rejects_naive_timestamp_before_persistence() -> None:
    """A naive event timestamp cannot provide reliable UTC chronology."""
    session = _AuditSession()

    with pytest.raises(ValueError, match="timezone-aware"):
        await append_audit_event(
            session,
            actor_kind="system",
            actor_identifier=None,
            action="health.changed",
            object_kind="service",
            object_identifier=None,
            request_id="request-456",
            details={},
            occurred_at=datetime(2026, 7, 29, 13, 45),
        )

    assert session.added == []
    assert session.commit_calls == 0


def test_orm_rejects_audit_update_and_delete() -> None:
    """Application-side ORM writes must not mutate or remove persisted audit rows."""
    engine = create_engine("sqlite://")
    AuditEvent.__table__.create(engine)
    event = AuditEvent(
        actor_kind="system",
        actor_identifier=None,
        action="service.started",
        object_kind="service",
        object_identifier=None,
        request_id="request-789",
        details={"safe": True},
        created_at=datetime(2026, 7, 29, 13, 45, tzinfo=UTC),
    )

    with Session(engine, expire_on_commit=False) as session:
        session.add(event)
        session.commit()

        event.action = "service.stopped"
        with pytest.raises(AuditMutationError, match="append-only"):
            session.commit()
        session.rollback()

        persisted = session.get(AuditEvent, event.id)
        assert persisted is not None
        session.delete(persisted)
        with pytest.raises(AuditMutationError, match="append-only"):
            session.commit()


def test_audit_schema_stores_request_attribution_and_json_details() -> None:
    """Dropping either field would make persisted audit records incomplete."""
    columns = AuditEvent.__table__.columns

    assert not columns["request_id"].nullable
    assert not columns["details"].nullable
    assert isinstance(
        columns["details"].type.dialect_impl(postgresql.dialect()),
        JSONB,
    )
