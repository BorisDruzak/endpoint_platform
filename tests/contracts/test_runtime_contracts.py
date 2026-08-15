"""Adapter-facing tests for the strictly bounded runtime target contract."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

import pytest

from endpoint_contracts.runtime import (
    RuntimeDiagnosticTargetUnavailable,
    parse_runtime_diagnostic_target_response,
    redacted_runtime_diagnostic_target_shadow,
)


_DEVICE_REF = "11111111-1111-4111-8111-111111111111"
_CORRELATION_ID = "helpdesk-diagnostic-42"


def _success_payload() -> dict[str, object]:
    return {
        "schema_version": "endpoint_runtime_v1",
        "correlation_id": _CORRELATION_ID,
        "data": {
            "device_ref": _DEVICE_REF,
            "online": True,
            "connection_state": "online",
            "last_seen_at": "2026-08-16T10:00:00Z",
            "last_handshake_at": "2026-08-16T10:00:00Z",
            "agent_version": "3.2.11",
        },
    }


def test_adapter_accepts_exact_success_and_returns_redacted_shadow() -> None:
    """A parser regression must not alter the six runtime fields Helpdesk may use."""
    parsed = parse_runtime_diagnostic_target_response(
        _success_payload(), _CORRELATION_ID
    )

    assert parsed.data.device_ref == UUID(_DEVICE_REF)
    assert parsed.data.last_seen_at == datetime(2026, 8, 16, 10, tzinfo=UTC)
    assert redacted_runtime_diagnostic_target_shadow(parsed) == {
        "online": True,
        "connection_state": "online",
        "last_seen_at": "2026-08-16T10:00:00Z",
        "last_handshake_at": "2026-08-16T10:00:00Z",
        "agent_version": "3.2.11",
    }


@pytest.mark.parametrize(
    "payload, expected_correlation",
    (
        (
            {
                **_success_payload(),
                "data": {**_success_payload()["data"], "ip": "192.0.2.10"},
            },
            _CORRELATION_ID,
        ),
        (_success_payload(), "different-correlation"),
        ({"correlation_id": _CORRELATION_ID, "data": {}}, _CORRELATION_ID),
    ),
)
def test_adapter_fails_closed_for_invalid_or_mismatched_runtime_response(
    payload: object, expected_correlation: str
) -> None:
    """Extra data, schema loss, or correlation substitution must make target unavailable."""
    with pytest.raises(RuntimeDiagnosticTargetUnavailable):
        parse_runtime_diagnostic_target_response(payload, expected_correlation)
