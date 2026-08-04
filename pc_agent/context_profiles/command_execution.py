"""Typed Device Context command execution without the legacy orchestrator."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Literal

from endpoint_contracts.commands import AgentCommandV1, AgentResultV1
from endpoint_contracts.context import validate_context_result_item

from .registry import (
    CONTEXT_COLLECTION_CAPABILITIES,
    ContextCapabilityError,
    execute_context_capability,
)


def execute_context_agent_command(
    command: AgentCommandV1,
    *,
    probe: object,
    completed_at: datetime | None = None,
) -> AgentResultV1:
    """Execute exactly one allowlisted collector and return the typed result."""
    finished_at = completed_at or datetime.now(UTC)
    if command.capability not in CONTEXT_COLLECTION_CAPABILITIES:
        return _context_command_result(
            command,
            status="failed",
            message="CONTEXT_CAPABILITY_REJECTED",
            completed_at=finished_at,
        )
    try:
        envelope = execute_context_capability(
            command.capability,
            command.parameters,
            probe,
            collected_at=finished_at,
        )
        result_item = validate_context_result_item(envelope.model_dump(mode="json"))
    except asyncio.CancelledError:
        return _context_command_result(
            command,
            status="canceled",
            message="OPERATION_CANCELED",
            completed_at=finished_at,
        )
    except TimeoutError:
        return _context_command_result(
            command,
            status="failed",
            message="CONTEXT_COLLECTION_TIMED_OUT",
            completed_at=finished_at,
        )
    except ContextCapabilityError:
        return _context_command_result(
            command,
            status="failed",
            message="CONTEXT_CAPABILITY_REJECTED",
            completed_at=finished_at,
        )

    return AgentResultV1(
        schema_version="agent_result_v1",
        command_id=command.command_id,
        device_id=command.device_id,
        status="succeeded",
        result_items=[result_item.model_dump(mode="json")],
        completed_at=finished_at,
    )


def _context_command_result(
    command: AgentCommandV1,
    *,
    status: Literal["failed", "canceled"],
    message: str,
    completed_at: datetime,
) -> AgentResultV1:
    return AgentResultV1(
        schema_version="agent_result_v1",
        command_id=command.command_id,
        device_id=command.device_id,
        status=status,
        result_items=[],
        message=message,
        completed_at=completed_at,
    )
