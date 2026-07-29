from __future__ import annotations

import asyncio
import json
import threading
from datetime import datetime, timezone
from pathlib import Path

import pytest

from endpoint_contracts.commands import AgentCommandV1, AgentResultV1
from pc_agent.core.database import DatabaseManager
from pc_agent.core.orchestrator import AgentOrchestrator
from pc_agent.config.config_loader import ConfigLoader, init_config
from pc_agent.ws_agent import WSAgent


COMMAND_ID = "00000000-0000-4000-8000-000000000351"
DEVICE_ID = "00000000-0000-4000-8000-000000000352"


def _context_result(command: AgentCommandV1) -> AgentResultV1:
    return AgentResultV1(
        schema_version="agent_result_v1",
        command_id=command.command_id,
        device_id=command.device_id,
        status="succeeded",
        result_items=[
            {
                "schema_version": "device_context_envelope_v1",
                "profile": "baseline_v1",
                "collected_at": "2026-07-29T12:00:00Z",
                "sections": {"identity": {"hostname": "fake-agent"}},
                "warnings": [],
            }
        ],
        completed_at=datetime(2026, 7, 29, 12, 0, tzinfo=timezone.utc),
    )


async def _send_context_command(agent: WSAgent, command_id: str = COMMAND_ID) -> None:
    await agent.handle_message(
        None,
        json.dumps(
            {
                "type": "command",
                "protocol_version": "ws_ticket_v3",
                "request_id": command_id,
                "device_id": DEVICE_ID,
                "trace_id": "trace-context",
                "ticket_id": "ticket-context",
                "payload": {"command": "context.baseline.collect", "params": {}},
                "meta": {"actor_role": "service"},
            }
        ),
    )


async def _wait_for_background_commands(agent: WSAgent) -> None:
    tasks = list(agent._background_command_tasks)
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)


async def _configure_context_agent(tmp_path: Path) -> tuple[WSAgent, DatabaseManager]:
    ConfigLoader._instance = None
    ConfigLoader._config = None
    init_config(tmp_path)
    db = DatabaseManager(str(tmp_path / "storage.db"))
    DatabaseManager._instance = None
    await db.init_db()
    agent = WSAgent(data_root=tmp_path)
    agent.db_manager = db
    agent._session_id = "context-test-runtime"
    agent.orchestrator = AgentOrchestrator(
        db_manager=db, enabled_modules=[], data_root=tmp_path
    )
    await agent.orchestrator.initialize()
    return agent, db


async def _send_cancel(agent: WSAgent, target_operation_id: str) -> None:
    await agent.handle_message(
        None,
        json.dumps(
            {
                "type": "command",
                "protocol_version": "ws_ticket_v3",
                "request_id": "00000000-0000-4000-8000-000000000399",
                "device_id": DEVICE_ID,
                "payload": {
                    "command": "cancel_operation",
                    "params": {"target_operation_id": target_operation_id},
                },
                "meta": {"actor_role": "service"},
            }
        ),
    )


@pytest.mark.asyncio
async def test_ws_context_command_uses_fixed_executor_and_sends_typed_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db = DatabaseManager(str(tmp_path / "storage.db"))
    DatabaseManager._instance = None
    await db.init_db()
    agent = WSAgent(data_root=tmp_path)
    agent.db_manager = db
    agent._session_id = "context-test-runtime"
    calls: list[AgentCommandV1] = []
    sent: list[dict] = []

    def fake_executor(command: AgentCommandV1, *, probe: object) -> AgentResultV1:
        calls.append(command)
        return _context_result(command)

    async def fake_send_envelope(_ws, msg_type, request_id, payload, **kwargs) -> None:
        sent.append({"type": msg_type, "request_id": request_id, "payload": payload})

    monkeypatch.setattr(
        "pc_agent.ws_agent.execute_context_agent_command", fake_executor, raising=False
    )
    monkeypatch.setattr(agent, "send_envelope", fake_send_envelope)

    await _send_context_command(agent)
    await _wait_for_background_commands(agent)

    assert [(item.capability, item.parameters) for item in calls] == [
        ("context.baseline.collect", {})
    ]
    result_messages = [item for item in sent if item["type"] == "command_result"]
    assert len(result_messages) == 1
    assert result_messages[0]["payload"]["status"] == "success"
    assert result_messages[0]["payload"]["data"]["schema_version"] == "agent_result_v1"
    assert result_messages[0]["payload"]["data"]["result_items"][0]["profile"] == "baseline_v1"


@pytest.mark.asyncio
async def test_ws_rejects_unsupported_context_command_without_executor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db = DatabaseManager(str(tmp_path / "storage.db"))
    DatabaseManager._instance = None
    await db.init_db()
    agent = WSAgent(data_root=tmp_path)
    agent.db_manager = db
    called = False
    sent: list[dict] = []

    def should_not_run(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError("unsupported context command reached executor")

    async def fake_send_envelope(_ws, msg_type, request_id, payload, **kwargs) -> None:
        sent.append({"type": msg_type, "request_id": request_id, "payload": payload})

    monkeypatch.setattr(
        "pc_agent.ws_agent.execute_context_agent_command", should_not_run, raising=False
    )
    monkeypatch.setattr(agent, "send_envelope", fake_send_envelope)
    await agent.handle_message(
        None,
        json.dumps(
            {
                "type": "command",
                "request_id": COMMAND_ID,
                "device_id": DEVICE_ID,
                "payload": {"command": "context.run_shell", "params": {"argv": ["id"]}},
            }
        ),
    )

    assert called is False
    result_messages = [item for item in sent if item["type"] == "command_result"]
    assert result_messages[0]["payload"]["status"] == "error"
    assert result_messages[0]["payload"]["error"]["code"] == "CONTEXT_CAPABILITY_REJECTED"


@pytest.mark.asyncio
async def test_duplicate_context_command_replays_cached_typed_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db = DatabaseManager(str(tmp_path / "storage.db"))
    DatabaseManager._instance = None
    await db.init_db()
    agent = WSAgent(data_root=tmp_path)
    agent.db_manager = db
    agent._session_id = "context-test-runtime"
    executions = 0
    sent: list[dict] = []

    def fake_executor(command: AgentCommandV1, *, probe: object) -> AgentResultV1:
        nonlocal executions
        executions += 1
        return _context_result(command)

    async def fake_send_envelope(_ws, msg_type, request_id, payload, **kwargs) -> None:
        sent.append({"type": msg_type, "request_id": request_id, "payload": payload})

    monkeypatch.setattr(
        "pc_agent.ws_agent.execute_context_agent_command", fake_executor, raising=False
    )
    monkeypatch.setattr(agent, "send_envelope", fake_send_envelope)

    await _send_context_command(agent)
    await _wait_for_background_commands(agent)
    await _send_context_command(agent)
    await _wait_for_background_commands(agent)

    assert executions == 1
    result_messages = [item for item in sent if item["type"] == "command_result"]
    assert len(result_messages) == 2
    assert result_messages[1]["payload"]["meta"]["cached"] is True
    assert result_messages[1]["payload"]["data"]["schema_version"] == "agent_result_v1"


@pytest.mark.asyncio
async def test_context_inflight_cancel_persists_typed_terminal_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    agent, db = await _configure_context_agent(tmp_path)
    started = threading.Event()
    release = threading.Event()
    sent: list[dict] = []

    def blocking_executor(command: AgentCommandV1, *, probe: object) -> AgentResultV1:
        started.set()
        release.wait(timeout=2)
        return _context_result(command)

    async def fake_send_envelope(_ws, msg_type, request_id, payload, **kwargs) -> None:
        sent.append({"type": msg_type, "request_id": request_id, "payload": payload})

    monkeypatch.setattr("pc_agent.ws_agent.execute_context_agent_command", blocking_executor)
    monkeypatch.setattr(agent, "send_envelope", fake_send_envelope)

    await _send_context_command(agent)
    assert await asyncio.to_thread(started.wait, 1)
    await _send_cancel(agent, COMMAND_ID)
    release.set()
    await _wait_for_background_commands(agent)

    cached = await db.get_command_result(COMMAND_ID)
    assert cached is not None
    assert cached["status"] == "canceled"
    payload = json.loads(cached["result_json"])
    assert payload["data"]["schema_version"] == "agent_result_v1"
    assert payload["data"]["status"] == "canceled"
    assert payload["data"]["command_id"] == COMMAND_ID
    assert payload["data"]["device_id"] == DEVICE_ID
    assert payload["error"]["code"] == "OPERATION_CANCELED"


@pytest.mark.asyncio
async def test_context_prestart_cancel_and_duplicate_replay_remain_typed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    agent, db = await _configure_context_agent(tmp_path)
    executions = 0
    sent: list[dict] = []

    def should_not_execute(*_args, **_kwargs) -> AgentResultV1:
        nonlocal executions
        executions += 1
        raise AssertionError("pre-start canceled context command must not execute")

    async def fake_send_envelope(_ws, msg_type, request_id, payload, **kwargs) -> None:
        sent.append({"type": msg_type, "request_id": request_id, "payload": payload})

    monkeypatch.setattr("pc_agent.ws_agent.execute_context_agent_command", should_not_execute)
    monkeypatch.setattr(agent, "send_envelope", fake_send_envelope)

    await db.mark_command_started(
        COMMAND_ID,
        owner_instance_id=agent._session_id,
        in_progress_result_json=agent._context_in_progress_result_json(
            "context.baseline.collect", DEVICE_ID
        ),
    )
    await _send_cancel(agent, COMMAND_ID)
    prestart_results = [
        item
        for item in sent
        if item["type"] == "command_result" and item["request_id"] == COMMAND_ID
    ]
    assert len(prestart_results) == 1
    assert prestart_results[0]["payload"]["data"]["schema_version"] == "agent_result_v1"
    assert prestart_results[0]["payload"]["data"]["status"] == "canceled"
    await _send_context_command(agent)
    await _wait_for_background_commands(agent)

    assert executions == 0
    cached = await db.get_command_result(COMMAND_ID)
    assert cached is not None and cached["status"] == "canceled"
    assert not await db.mark_command_seen(
        command_id=COMMAND_ID,
        status="success",
        result_json=json.dumps({"status": "success", "data": {}}),
    )
    cached = await db.get_command_result(COMMAND_ID)
    assert cached is not None and cached["status"] == "canceled"
    result_messages = [item for item in sent if item["type"] == "command_result"]
    assert result_messages[-1]["payload"]["meta"]["cached"] is True
    assert result_messages[-1]["payload"]["data"]["schema_version"] == "agent_result_v1"
    assert result_messages[-1]["payload"]["data"]["status"] == "canceled"


@pytest.mark.asyncio
async def test_context_restart_recovery_replays_typed_fixed_command_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    agent, db = await _configure_context_agent(tmp_path)
    agent._session_id = "new-context-runtime"
    await db.mark_command_started(
        COMMAND_ID,
        owner_instance_id="old-context-runtime",
        in_progress_result_json=json.dumps(
            {
                "meta": {
                    "context_command": {
                        "capability": "context.baseline.collect",
                        "device_id": DEVICE_ID,
                    }
                }
            }
        ),
    )
    sent: list[dict] = []

    async def fake_send_envelope(_ws, msg_type, request_id, payload, **kwargs) -> None:
        sent.append({"type": msg_type, "request_id": request_id, "payload": payload})

    monkeypatch.setattr(agent, "send_envelope", fake_send_envelope)
    await agent.recover_in_progress_commands_on_startup(None)

    cached = await db.get_command_result(COMMAND_ID)
    assert cached is not None and cached["status"] == "error"
    payload = json.loads(cached["result_json"])
    assert payload["data"]["schema_version"] == "agent_result_v1"
    assert payload["data"]["status"] == "failed"
    assert payload["data"]["command_id"] == COMMAND_ID
    assert payload["data"]["device_id"] == DEVICE_ID
    assert payload["error"]["code"] == "AGENT_RESTARTED"
    assert payload["meta"]["command"] == "context.baseline.collect"
    assert sent[-1]["payload"] == payload
