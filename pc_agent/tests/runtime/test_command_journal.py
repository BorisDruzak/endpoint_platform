from datetime import UTC, datetime, timedelta
import sqlite3
from uuid import uuid4

import pytest

from endpoint_contracts.commands import AgentCommandV1, AgentResultV1
from pc_agent.runtime import local_state


def _command(now):
    return AgentCommandV1(
        schema_version="agent_command_v1",
        command_id=uuid4(), device_id=uuid4(), capability="gateway.echo",
        requested_by_service="test-service", idempotency_key="test-key",
        created_at=now, deadline_at=now + timedelta(minutes=5),
    )


@pytest.mark.asyncio
async def test_command_journal_recovers_uncertain_start_and_persists_result(tmp_path):
    now = datetime.now(UTC)
    command = _command(now)
    path = tmp_path / "storage.db"
    journal = local_state.CommandJournal(path)
    await local_state.migrate_local_state(path)
    assert await journal.begin(command, now=now) == "execute"
    assert await journal.begin(command, now=now) == "running"
    changed = command.model_copy(update={"parameters": {"changed": True}})
    with pytest.raises(local_state.LocalStateError, match="command identity"):
        await journal.begin(changed, now=now)

    restarted = local_state.CommandJournal(path)
    await restarted.recover_interrupted(now=now)
    assert await restarted.begin(command, now=now) == "completed"
    (result,) = await restarted.pending(command.device_id)
    assert result.command_id == command.command_id
    assert result.message == "AGENT_COMMAND_OUTCOME_UNKNOWN"
    await restarted.acknowledge(result)
    assert await journal.pending(command.device_id) == []
    assert await journal.begin(command, now=now) == "completed"


@pytest.mark.asyncio
async def test_command_journal_cancel_and_deadline_gate_execution(tmp_path):
    now = datetime.now(UTC)
    path = tmp_path / "storage.db"
    await local_state.migrate_local_state(path)
    journal = local_state.CommandJournal(path)
    command = _command(now)
    await journal.cancel(command.device_id, command.command_id)
    assert await journal.begin(command, now=now) == "canceled"
    other = _command(now)
    assert await journal.begin(other, now=other.deadline_at) == "expired"
    assert await journal.begin(other, now=now) == "execute"
    result = AgentResultV1(
        schema_version="agent_result_v1", command_id=other.command_id,
        device_id=other.device_id, status="succeeded", completed_at=now,
    )
    await journal.complete(other, result)
    assert await journal.pending(other.device_id) == [result]
    wrong = result.model_copy(update={"message": "different result"})
    assert not await journal.acknowledge(wrong)
    assert await journal.pending(other.device_id) == [result]


@pytest.mark.asyncio
async def test_migration_and_capacity_keep_unacknowledged_results(tmp_path, monkeypatch):
    path = tmp_path / "storage.db"
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE endpoint_runtime_schema (singleton INTEGER PRIMARY KEY, schema_version INTEGER)")
        connection.execute("INSERT INTO endpoint_runtime_schema VALUES (1, 1)")
    await local_state.migrate_local_state(path)
    await local_state.migrate_local_state(path)
    monkeypatch.setattr(local_state, "_MAX_COMMAND_RECORDS", 1)
    old = _command(datetime.now(UTC) - timedelta(days=2))
    journal = local_state.CommandJournal(path)
    assert await journal.begin(old, now=old.created_at) == "execute"
    await journal.recover_interrupted(now=old.created_at)
    now = datetime.now(UTC)
    other = _command(now)
    with pytest.raises(local_state.LocalStateError, match="capacity"):
        await journal.begin(other, now=now)
    (result,) = await journal.pending(old.device_id)
    assert await journal.acknowledge(result)
    assert await journal.begin(other, now=now) == "execute"
    assert await journal.begin(old, now=now) == "expired"
