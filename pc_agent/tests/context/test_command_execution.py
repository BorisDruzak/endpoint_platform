from __future__ import annotations

import asyncio
from datetime import timedelta
from uuid import UUID

from endpoint_contracts.commands import AgentCommandV1
from pc_agent.core.orchestrator import execute_context_agent_command

from .conftest import FIXED_TIME


COMMAND_ID = UUID("00000000-0000-4000-8000-000000000301")
DEVICE_ID = UUID("00000000-0000-4000-8000-000000000302")


def _command(capability: str, parameters: dict[str, object] | None = None) -> AgentCommandV1:
    return AgentCommandV1(
        schema_version="agent_command_v1",
        command_id=COMMAND_ID,
        device_id=DEVICE_ID,
        capability=capability,
        parameters=parameters or {},
        requested_by_service="context-scheduler",
        idempotency_key="context-command-301",
        created_at=FIXED_TIME,
        deadline_at=FIXED_TIME + timedelta(minutes=5),
    )


def test_context_command_serializes_exactly_one_validated_envelope(fake_probe) -> None:
    """Removing envelope validation or adding arbitrary items would break the transport contract."""
    result = execute_context_agent_command(
        _command("context.baseline.collect"), probe=fake_probe, completed_at=FIXED_TIME
    )

    assert result.status == "succeeded"
    assert result.command_id == COMMAND_ID
    assert result.device_id == DEVICE_ID
    assert len(result.result_items) == 1
    assert result.result_items[0]["profile"] == "baseline_v1"
    assert result.result_items[0]["collected_at"] == "2026-07-29T12:00:00Z"


def test_context_command_maps_collector_timeout_to_failed_result(fake_probe, monkeypatch) -> None:
    """An uncaught collection timeout must be terminally reported without a partial payload."""
    from pc_agent.core import orchestrator

    def timed_out(*_args, **_kwargs):
        raise TimeoutError("probe timed out")

    monkeypatch.setattr(orchestrator, "execute_context_capability", timed_out)

    result = execute_context_agent_command(
        _command("context.health.collect"), probe=fake_probe, completed_at=FIXED_TIME
    )

    assert result.status == "failed"
    assert result.result_items == []
    assert result.message == "CONTEXT_COLLECTION_TIMED_OUT"


def test_context_command_maps_cancellation_to_canceled_result(fake_probe, monkeypatch) -> None:
    """Cancellation must preserve the terminal status expected by durable command replay."""
    from pc_agent.core import orchestrator

    def canceled(*_args, **_kwargs):
        raise asyncio.CancelledError()

    monkeypatch.setattr(orchestrator, "execute_context_capability", canceled)

    result = execute_context_agent_command(
        _command("context.network.collect"), probe=fake_probe, completed_at=FIXED_TIME
    )

    assert result.status == "canceled"
    assert result.result_items == []
    assert result.message == "OPERATION_CANCELED"
