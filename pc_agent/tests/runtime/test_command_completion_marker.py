"""Safety contract for the bounded agent-side command completion marker."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from uuid import UUID

import pytest

from endpoint_contracts import AgentCommandV1, AgentResultV1
from pc_agent.runtime.lifecycle import emit_command_completed_marker


def _command() -> AgentCommandV1:
    return AgentCommandV1.model_construct(
        schema_version="agent_command_v1",
        command_id=UUID("00000000-0000-4000-8000-000000000511"),
        device_id=UUID("00000000-0000-4000-8000-000000000512"),
        capability="context.diagnostic.collect",
        parameters={"forbidden": "must-not-be-logged"},
        requested_by_service="staging-service",
        idempotency_key="must-not-be-logged",
        created_at=datetime(2026, 8, 23, tzinfo=UTC),
        deadline_at=datetime(2026, 8, 23, 0, 5, tzinfo=UTC),
    )


def _result(command: AgentCommandV1) -> AgentResultV1:
    return AgentResultV1(
        schema_version="agent_result_v1",
        command_id=command.command_id,
        device_id=command.device_id,
        status="succeeded",
        result_items=[{"forbidden": "raw-result"}],
        completed_at=datetime(2026, 8, 23, 0, 1, tzinfo=UTC),
    )


def test_command_completed_marker_is_bounded_and_excludes_sensitive_payloads(
    caplog: pytest.LogCaptureFixture,
) -> None:
    command = _command()

    with caplog.at_level(logging.INFO, logger="pc_agent.runtime.lifecycle"):
        emit_command_completed_marker(command, _result(command), duration_ms=27)

    record = caplog.records[-1]
    assert record.message == "endpoint_agent_command_completed"
    assert record.command_id == str(command.command_id)
    assert record.capability == "context.diagnostic.collect"
    assert record.status == "succeeded"
    assert record.duration_ms == 27
    assert record.result_item_count == 1
    assert record.timestamp == "2026-08-23T00:01:00+00:00"
    assert "must-not-be-logged" not in caplog.text
    assert "raw-result" not in caplog.text
    assert not hasattr(record, "parameters")
    assert not hasattr(record, "result_items")
