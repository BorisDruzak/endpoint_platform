"""Safety contract for the bounded agent-side command completion marker."""

from __future__ import annotations

import logging
import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import pytest

from endpoint_contracts import AgentCommandV1, AgentResultV1
from pc_agent.runtime.lifecycle import emit_command_completed_marker
from pc_agent.runtime import application as runtime_application
from pc_agent.runtime.application import RuntimeSettings
from pc_agent.platform.windows.canary_status import read_canary_status
from pc_agent.version import AGENT_VERSION


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


def test_command_completed_marker_forwards_only_bounded_values_to_windows_sink() -> None:
    command = _command()
    observed: list[dict[str, object]] = []

    emit_command_completed_marker(
        command,
        _result(command),
        duration_ms=27,
        completion_sink=observed.append,
    )

    assert observed == [{
        "command_id": str(command.command_id),
        "capability": "context.diagnostic.collect",
        "status": "succeeded",
        "duration_ms": 27,
        "result_item_count": 1,
        "timestamp": "2026-08-23T00:01:00+00:00",
    }]


def test_windows_completion_sink_updates_only_the_matching_canary_status(
    tmp_path: Path,
) -> None:
    """A completed diagnostic must become post-operation proof without persisting its payload."""
    data_root = tmp_path / "data"
    install_root = tmp_path / "install"
    data_root.mkdir()
    install_root.mkdir()
    (install_root / "current.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "source_revision": "a" * 40,
                "version": AGENT_VERSION,
            }
        ),
        encoding="utf-8",
    )
    settings = RuntimeSettings(
        data_root=data_root,
        install_root=install_root,
        ca_file=tmp_path / "endpoint-ca.crt",
        endpoint_origin="https://endpoint.sosnadmin.local",
        transport_mode="gateway_wss",
        migration_http_pull_fallback=False,
    )
    writer = runtime_application._create_canary_status_writer(settings)
    assert writer is not None
    writer.write_wss_ready()
    sink = runtime_application._create_completion_sink(settings)
    assert sink is not None

    emit_command_completed_marker(_command(), _result(_command()), duration_ms=27, completion_sink=sink)

    proof = read_canary_status(data_root)["completion_proof"]
    assert proof == {
        "command_id": "00000000-0000-4000-8000-000000000511",
        "capability": "context.diagnostic.collect",
        "status": "succeeded",
        "duration_ms": 27,
        "result_item_count": 1,
        "timestamp": "2026-08-23T00:01:00+00:00",
    }
