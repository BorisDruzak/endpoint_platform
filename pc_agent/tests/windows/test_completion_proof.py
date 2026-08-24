from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from endpoint_contracts import AgentCommandV1, AgentResultV1
from pc_agent.platform.windows.completion_proof import (
    WindowsCompletionProofWriter,
    read_completion_proofs,
)


def _command() -> AgentCommandV1:
    return AgentCommandV1.model_construct(
        schema_version="agent_command_v1",
        command_id=UUID("00000000-0000-4000-8000-000000000011"),
        device_id=UUID("00000000-0000-4000-8000-000000000012"),
        capability="context.diagnostic.collect",
        parameters={"forbidden": "parameter"},
        requested_by_service="test",
        idempotency_key="forbidden",
        created_at=datetime(2026, 8, 24, tzinfo=UTC),
        deadline_at=datetime(2026, 8, 24, 0, 5, tzinfo=UTC),
    )


def _result() -> AgentResultV1:
    return AgentResultV1(
        schema_version="agent_result_v1",
        command_id=UUID("00000000-0000-4000-8000-000000000011"),
        device_id=UUID("00000000-0000-4000-8000-000000000012"),
        status="succeeded",
        result_items=[{"forbidden": "result"}],
        completed_at=datetime(2026, 8, 24, tzinfo=UTC),
    )


def test_writer_persists_only_bounded_completion_fields(tmp_path: Path) -> None:
    WindowsCompletionProofWriter(tmp_path).append(_command(), _result(), 27)

    assert read_completion_proofs(tmp_path) == ({
        "command_id": "00000000-0000-4000-8000-000000000011",
        "capability": "context.diagnostic.collect",
        "status": "succeeded",
        "duration_ms": 27,
        "result_item_count": 1,
        "timestamp": "2026-08-24T00:00:00+00:00",
    },)
