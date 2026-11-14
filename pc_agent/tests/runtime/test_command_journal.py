import asyncio
from datetime import UTC, datetime, timedelta
import sqlite3
from types import SimpleNamespace
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
    with sqlite3.connect(path) as connection:
        (stored,) = connection.execute(
            "SELECT result_json FROM endpoint_seen_commands WHERE command_id = ?",
            (str(command.command_id),),
        ).fetchone()
    assert AgentResultV1.model_validate_json(stored) == result


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
    await journal.complete(old, AgentResultV1(
        schema_version="agent_result_v1", command_id=old.command_id,
        device_id=old.device_id, status="failed", completed_at=old.created_at,
    ))
    now = datetime.now(UTC)
    other = _command(now)
    with pytest.raises(local_state.LocalStateError, match="capacity"):
        await journal.begin(other, now=now)
    (result,) = await journal.pending(old.device_id)
    assert await journal.acknowledge(result)
    assert await journal.begin(other, now=now) == "execute"
    assert await journal.begin(old, now=now) == "expired"


@pytest.mark.asyncio
async def test_connected_commands_replay_without_execution_and_require_exact_ack(tmp_path):
    from endpoint_contracts.gateway_ws import ResultAckV1
    from pc_agent.runtime.lifecycle import ConnectedCommands

    path = tmp_path / "storage.db"
    await local_state.migrate_local_state(path)
    journal = local_state.CommandJournal(path)
    command = _command(datetime.now(UTC))
    sent = []
    executed = []

    async def execute(value):
        executed.append(value)
        return AgentResultV1(
            schema_version="agent_result_v1", command_id=value.command_id,
            device_id=value.device_id, status="succeeded", completed_at=datetime.now(UTC),
        )

    async def send_result(result):
        sent.append(result)
        return len(sent)

    async def send_ack(acknowledgement):
        first.authorize_start(acknowledgement.command_id)

    from pc_agent.transport.base import GatewayRetryableError

    async def disconnected_send(_):
        raise GatewayRetryableError("connection lost before result delivery")

    transport = SimpleNamespace(send_result=send_result, send_ack=send_ack)
    executor = SimpleNamespace(execute=execute)
    first = ConnectedCommands(
        journal, SimpleNamespace(send_result=disconnected_send, send_ack=send_ack),
        command.device_id,
    )
    with pytest.raises(GatewayRetryableError):
        await first.execute(executor, command, None)
    second = ConnectedCommands(journal, transport, command.device_id)
    await second.execute(executor, command, None)
    third = ConnectedCommands(journal, transport, command.device_id)
    await third.execute(executor, command, None)
    assert executed == [command]
    assert sent == [sent[0], sent[0]]
    def ack(sequence):
        return ResultAckV1(schema_version="result_ack_v1", command_id=command.command_id,
                           result_sequence=sequence)
    await third.acknowledge(ack(1))
    assert await journal.pending(command.device_id) == [sent[0]]
    await third.acknowledge(ack(2))
    assert await journal.pending(command.device_id) == []


@pytest.mark.asyncio
async def test_connected_loop_recovers_unacknowledged_result_at_handshake(tmp_path):
    from endpoint_contracts.gateway_ws import COMMAND_JOURNAL_FEATURE, ResultAckV1
    from pc_agent.runtime.lifecycle import _run_connected
    from pc_agent.transport.protocol import compatibility_agent_hello

    path = tmp_path / "storage.db"
    await local_state.migrate_local_state(path)
    command = _command(datetime.now(UTC))
    journal = local_state.CommandJournal(path)
    assert await journal.begin(command, now=command.created_at) == "execute"
    inbox = asyncio.Queue()
    sent = []

    async def send_result(value):
        sent.append(value)
        await inbox.put(SimpleNamespace(root=SimpleNamespace(
            kind="result_ack", payload=ResultAckV1(
                schema_version="result_ack_v1", command_id=value.command_id, result_sequence=7,
            ),
        )))
        return 7

    async def execute(_):
        pytest.fail("interrupted execution must not be repeated")

    features = [COMMAND_JOURNAL_FEATURE]
    transport = SimpleNamespace(send_result=send_result, receive=inbox.get)
    hello = compatibility_agent_hello().model_copy(update={
        "device_id": command.device_id, "protocol_features": features,
    })
    gateway = SimpleNamespace(protocol_features=features, heartbeat_interval_seconds=60)
    task = asyncio.create_task(_run_connected(
        transport, SimpleNamespace(execute=execute), hello, gateway, asyncio.sleep, journal=journal,
    ))
    try:
        async with asyncio.timeout(3):
            while not sent or await journal.pending(command.device_id):
                if task.done():
                    task.result()
                await asyncio.sleep(0.01)
        assert [result.message for result in sent] == ["AGENT_COMMAND_OUTCOME_UNKNOWN"]
        assert await journal.begin(command, now=datetime.now(UTC)) == "completed"
    finally:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task


@pytest.mark.asyncio
@pytest.mark.parametrize("allowed", [False, True])
async def test_command_waits_for_gateway_start_decision(tmp_path, allowed):
    from pc_agent.runtime.lifecycle import ConnectedCommands

    path = tmp_path / "storage.db"
    await local_state.migrate_local_state(path)
    journal = local_state.CommandJournal(path)
    command = _command(datetime.now(UTC))
    requested = asyncio.Event()
    executed = []

    async def send_ack(ack):
        assert ack.status == "running"
        requested.set()

    async def execute(value):
        executed.append(value.command_id)
        return AgentResultV1(
            schema_version="agent_result_v1", command_id=value.command_id,
            device_id=value.device_id, status="succeeded", completed_at=datetime.now(UTC),
        )

    async def send_result(_):
        return 1

    state = ConnectedCommands(
        journal, SimpleNamespace(send_ack=send_ack, send_result=send_result), command.device_id,
    )
    async with asyncio.timeout(3):
        work = asyncio.create_task(state.execute(SimpleNamespace(execute=execute), command, None))
        await requested.wait()
        assert executed == []
        if allowed:
            state.authorize_start(command.command_id)
        else:
            await state.cancel(command.command_id)
        await work
    assert executed == ([command.command_id] if allowed else [])
    if not allowed:
        assert await journal.begin(command, now=datetime.now(UTC)) == "canceled"
        assert await journal.pending(command.device_id) == []
