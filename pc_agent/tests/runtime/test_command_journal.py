import asyncio
from contextlib import asynccontextmanager
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
@pytest.mark.parametrize(
    ("platform", "os_id", "alt_unit", "extra"),
    [
        ("linux", "altlinux", False, True),
        ("linux", "altlinux-workstation", False, True),
        ("linux", "altlinux-server", False, True),
        ("linux", "ubuntu", True, False),
        ("linux", None, True, True),
        ("linux", None, False, False),
        ("win32", "altlinux", True, False),
    ],
)
async def test_command_journal_connection_durability(tmp_path, monkeypatch, platform, os_id, alt_unit, extra):
    monkeypatch.setattr(local_state, "sys", SimpleNamespace(platform=platform), raising=False)
    if alt_unit:
        monkeypatch.setenv("ENDPOINT_AGENT_ALT_UPDATE_MODE", "1")
    else:
        monkeypatch.delenv("ENDPOINT_AGENT_ALT_UPDATE_MODE", raising=False)

    def read_os_release():
        if os_id is None:
            raise FileNotFoundError("os-release unavailable")
        return {"ID": os_id}

    monkeypatch.setattr(local_state, "freedesktop_os_release", read_os_release, raising=False)

    connect = local_state.aiosqlite.connect
    connections = []

    @asynccontextmanager
    async def observe_connection(*args, **kwargs):
        async with connect(*args, **kwargs) as connection:
            baseline = (await connection.execute_fetchall("PRAGMA synchronous"))[0][0]
            statements = []
            await connection.set_trace_callback(statements.append)
            yield connection
            actual = (await connection.execute_fetchall("PRAGMA synchronous"))[0][0]
            connections.append((baseline, actual, statements))

    monkeypatch.setattr(local_state.aiosqlite, "connect", observe_connection)
    now = datetime.now(UTC)
    command = _command(now)
    path = tmp_path / "storage.db"
    journal = local_state.CommandJournal(path)
    await local_state.migrate_local_state(path)
    assert await journal.begin(command, now=now) == "execute"
    await journal.mark_execution_started(command)
    result = AgentResultV1(
        schema_version="agent_result_v1", command_id=command.command_id,
        device_id=command.device_id, status="succeeded", completed_at=now,
    )
    await journal.complete(command, result)
    other = _command(now)
    await journal.cancel(other.device_id, other.command_id)
    reserved = _command(now)
    assert await journal.begin(reserved, now=now) == "execute"
    await journal.reject_start(reserved)
    # Reopen a populated database and use its existing outbox and schema.
    with sqlite3.connect(path) as connection:
        mode = connection.execute("PRAGMA journal_mode").fetchone()
    await local_state.migrate_local_state(path)
    await journal.recover_interrupted(now=now)
    assert await journal.pending(command.device_id) == [result]
    assert await journal.pending_result(command.device_id, command.command_id) == result
    assert await journal.acknowledge(result)
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA journal_mode").fetchone() == mode
        assert connection.execute("SELECT schema_version FROM endpoint_runtime_schema").fetchone() == (1,)

    assert sum("BEGIN IMMEDIATE" in sql for _, _, sql in connections) == 10
    assert sum("BEGIN IMMEDIATE" not in sql for _, _, sql in connections) == 2
    for baseline, actual, sql in connections:
        if extra and "BEGIN IMMEDIATE" in sql:
            assert actual == 3
            assert "PRAGMA synchronous=EXTRA" in sql[:sql.index("BEGIN IMMEDIATE")]
        else:
            assert actual == baseline
            assert "PRAGMA synchronous=EXTRA" not in sql


async def _journal_with_failing_commit(path, monkeypatch, operation, table):
    monkeypatch.setattr(local_state, "sys", SimpleNamespace(platform="linux"))
    monkeypatch.setattr(local_state, "freedesktop_os_release", lambda: {"ID": "altlinux"})
    await local_state.migrate_local_state(path)

    # The statement succeeds, but the deferred constraint fails at commit.
    with sqlite3.connect(path) as connection:
        connection.executescript(
            f"""
            CREATE TABLE test_parent (id INTEGER PRIMARY KEY);
            CREATE TABLE test_child (
                id INTEGER REFERENCES test_parent(id) DEFERRABLE INITIALLY DEFERRED
            );
            CREATE TRIGGER test_commit_failure AFTER {operation} ON {table}
            BEGIN
                INSERT INTO test_child VALUES (1);
            END;
            """
        )

    connect = local_state.aiosqlite.connect

    @asynccontextmanager
    async def enforce_foreign_keys(*args, **kwargs):
        async with connect(*args, **kwargs) as connection:
            await connection.execute("PRAGMA foreign_keys=ON")
            yield connection

    monkeypatch.setattr(local_state.aiosqlite, "connect", enforce_foreign_keys)
    return local_state.CommandJournal(path)


@pytest.mark.asyncio
async def test_alt_command_start_commit_failure_prevents_dispatch(tmp_path, monkeypatch):
    from pc_agent.runtime.lifecycle import ConnectedCommands

    path = tmp_path / "storage.db"
    journal = await _journal_with_failing_commit(
        path, monkeypatch, "DELETE", "endpoint_command_start_reservations",
    )
    command = _command(datetime.now(UTC))

    async def authorize(_):
        state.authorize_start(command.command_id)

    async def unexpected(*_):
        pytest.fail("a failed start commit must prevent dispatch and result delivery")

    state = ConnectedCommands(
        journal, SimpleNamespace(send_ack=authorize, send_result=unexpected), command.device_id,
    )
    with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY"):
        await state.execute(SimpleNamespace(execute=unexpected), command, None)
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT command_id FROM endpoint_command_start_reservations").fetchone() == (
            str(command.command_id),
        )
        connection.execute("DROP TRIGGER test_commit_failure")
    await journal.recover_interrupted(now=datetime.now(UTC))
    (result,) = await journal.pending(command.device_id)
    assert result.message == "AGENT_COMMAND_INTERRUPTED_BEFORE_START"


@pytest.mark.asyncio
async def test_alt_result_commit_failure_prevents_delivery_and_completion_marker(tmp_path, monkeypatch):
    from pc_agent.runtime.lifecycle import ConnectedCommands

    path = tmp_path / "storage.db"
    journal = await _journal_with_failing_commit(path, monkeypatch, "INSERT", "endpoint_pending_results")
    now = datetime.now(UTC)
    command = _command(now)
    executed = []
    marked = []

    async def authorize(_):
        state.authorize_start(command.command_id)

    async def execute(value):
        executed.append(value)
        return AgentResultV1(
            schema_version="agent_result_v1", command_id=value.command_id,
            device_id=value.device_id, status="succeeded", completed_at=now,
        )

    async def unexpected_result(_):
        pytest.fail("a failed result commit must prevent result delivery")

    state = ConnectedCommands(
        journal, SimpleNamespace(send_ack=authorize, send_result=unexpected_result), command.device_id,
    )
    with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY"):
        await state.execute(SimpleNamespace(execute=execute), command, marked.append)
    assert executed == [command]
    assert marked == []
    assert await journal.pending(command.device_id) == []

    with sqlite3.connect(path) as connection:
        connection.execute("DROP TRIGGER test_commit_failure")
    await journal.recover_interrupted(now=datetime.now(UTC))
    (result,) = await journal.pending(command.device_id)
    assert result.command_id == command.command_id
    assert result.message == "AGENT_COMMAND_OUTCOME_UNKNOWN"


@pytest.mark.asyncio
async def test_alt_result_ack_commit_failure_preserves_result_for_exact_retry(tmp_path, monkeypatch):
    from endpoint_contracts.gateway_ws import ResultAckV1
    from pc_agent.runtime.lifecycle import ConnectedCommands

    path = tmp_path / "storage.db"
    journal = await _journal_with_failing_commit(path, monkeypatch, "DELETE", "endpoint_pending_results")
    now = datetime.now(UTC)
    command = _command(now)
    result = AgentResultV1(
        schema_version="agent_result_v1", command_id=command.command_id,
        device_id=command.device_id, status="succeeded", completed_at=now,
    )
    sent = []

    async def authorize(_):
        state.authorize_start(command.command_id)

    async def execute(_):
        return result

    async def send_result(value):
        sent.append(value)
        return 1

    state = ConnectedCommands(
        journal, SimpleNamespace(send_ack=authorize, send_result=send_result), command.device_id,
    )
    await state.execute(SimpleNamespace(execute=execute), command, None)
    ack = ResultAckV1(
        schema_version="result_ack_v1", command_id=command.command_id, result_sequence=1,
    )
    with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY"):
        await state.acknowledge(ack)
    assert await journal.pending(command.device_id) == [result]

    with sqlite3.connect(path) as connection:
        connection.execute("DROP TRIGGER test_commit_failure")
    await state.acknowledge(ack)
    assert await journal.pending(command.device_id) == []
    assert sent == [result]


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
    with pytest.raises(local_state.LocalStateError, match="matching reservation"):
        await journal.mark_execution_started(changed)
    await journal.mark_execution_started(command)

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
async def test_start_reservation_migration_preserves_legacy_running_and_rollback(tmp_path):
    now = datetime.now(UTC)
    path = tmp_path / "storage.db"
    await local_state.migrate_local_state(path)
    legacy = _command(now)
    with sqlite3.connect(path) as connection:
        connection.execute("DROP TABLE endpoint_command_start_reservations")
        connection.execute(
            "INSERT INTO endpoint_command_inbox VALUES (?, ?, ?, ?, 'running')",
            (str(legacy.command_id), str(legacy.device_id), "legacy-digest", legacy.deadline_at.isoformat()),
        )

    await local_state.migrate_local_state(path)
    journal = local_state.CommandJournal(path)
    await journal.recover_interrupted(now=now)
    (legacy_result,) = await journal.pending(legacy.device_id)
    assert legacy_result.message == "AGENT_COMMAND_OUTCOME_UNKNOWN"

    settled = _command(now)
    reserved = _command(now)
    assert await journal.begin(settled, now=now) == "execute"
    assert await journal.begin(reserved, now=now) == "execute"
    with sqlite3.connect(path) as connection:
        # A rollback Core still uses the original inbox schema and can settle a reservation.
        assert connection.execute("SELECT schema_version FROM endpoint_runtime_schema").fetchone() == (1,)
        connection.execute(
            "UPDATE endpoint_command_inbox SET state = 'completed' WHERE command_id = ?",
            (str(settled.command_id),),
        )

    await local_state.migrate_local_state(path)
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT command_id FROM endpoint_command_start_reservations").fetchall() == [
            (str(reserved.command_id),),
        ]
    await journal.recover_interrupted(now=now)
    (result,) = await journal.pending(reserved.device_id)
    assert result.message == "AGENT_COMMAND_INTERRUPTED_BEFORE_START"


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
@pytest.mark.parametrize("expires_during", ["gateway_start", "journal_write"])
async def test_command_expiring_during_start_never_executes(tmp_path, monkeypatch, expires_during):
    from pc_agent.runtime import lifecycle

    command = _command(datetime.now(UTC))
    path = tmp_path / "storage.db"
    await local_state.migrate_local_state(path)
    journal = local_state.CommandJournal(path)
    sent = []

    def reach_deadline():
        monkeypatch.setattr(lifecycle, "datetime", SimpleNamespace(now=lambda tz: command.deadline_at))

    async def grant_start(ack):
        assert ack.status == "running" and ack.command_id == command.command_id
        if expires_during == "gateway_start":
            reach_deadline()
        session.authorize_start(ack.command_id)

    mark_started = journal.mark_execution_started

    async def record_start(value):
        assert expires_during == "journal_write"
        await mark_started(value)
        reach_deadline()

    async def execute(_):
        pytest.fail("an expired command reached the executor")

    async def send_result(result):
        sent.append(result)
        return 1

    monkeypatch.setattr(journal, "mark_execution_started", record_start)
    transport = SimpleNamespace(send_ack=grant_start, send_result=send_result)
    session = lifecycle.ConnectedCommands(journal, transport, command.device_id)
    await session.execute(SimpleNamespace(execute=execute), command, None)

    (result,) = sent
    assert result.command_id == command.command_id
    assert result.status == "expired" and result.message == "AGENT_COMMAND_DEADLINE_EXPIRED"
    reopened = local_state.CommandJournal(path)
    await reopened.recover_interrupted(now=command.deadline_at)
    assert await reopened.begin(command, now=command.deadline_at) == "completed"
    assert await reopened.pending(command.device_id) == [result]


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
async def test_capacity_preserves_acknowledged_unknown_outcome(tmp_path, monkeypatch):
    now = datetime.now(UTC)
    earlier = now - local_state._COMPLETED_RETENTION - timedelta(days=1)
    unknown = _command(earlier)
    settled = _command(earlier).model_copy(update={"device_id": unknown.device_id})
    incoming = _command(now).model_copy(update={"device_id": unknown.device_id})
    path = tmp_path / "storage.db"
    await local_state.migrate_local_state(path)
    monkeypatch.setattr(local_state, "_MAX_COMMAND_RECORDS", 2)

    journal = local_state.CommandJournal(path)
    assert await journal.begin(unknown, now=earlier) == "execute"
    await journal.mark_execution_started(unknown)
    reopened = local_state.CommandJournal(path)
    await reopened.recover_interrupted(now=earlier)
    (result,) = await reopened.pending(unknown.device_id)
    assert result.message == "AGENT_COMMAND_OUTCOME_UNKNOWN"
    assert await reopened.acknowledge(result)

    assert await reopened.begin(settled, now=earlier) == "execute"
    await reopened.mark_execution_started(settled)
    success = AgentResultV1(
        schema_version="agent_result_v1", command_id=settled.command_id,
        device_id=settled.device_id, status="succeeded", completed_at=earlier,
    )
    await reopened.complete(settled, success)
    assert await reopened.acknowledge(success)

    assert await reopened.begin(incoming, now=now) == "execute"
    assert await reopened.begin(settled, now=now) == "expired"
    assert await reopened.begin(unknown, now=now) == "completed"
    assert await reopened.pending(unknown.device_id) == []


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
    await journal.mark_execution_started(command)
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
async def test_restart_distinguishes_disconnect_before_gateway_start(tmp_path):
    from pc_agent.runtime.lifecycle import ConnectedCommands
    from pc_agent.transport.base import GatewayRetryableError

    path = tmp_path / "storage.db"
    await local_state.migrate_local_state(path)
    journal = local_state.CommandJournal(path)
    command = _command(datetime.now(UTC))

    async def send_ack(acknowledgement):
        assert acknowledgement.status == "running"
        raise GatewayRetryableError("connection lost while requesting permission")

    async def execute(_):
        pytest.fail("the handler must not run without permission")

    async def send_result(_):
        pytest.fail("the disconnected session must not send a result")

    transport = SimpleNamespace(send_ack=send_ack, send_result=send_result)
    state = ConnectedCommands(journal, transport, command.device_id)
    with pytest.raises(GatewayRetryableError, match="connection lost"):
        await state.execute(SimpleNamespace(execute=execute), command, None)

    restarted = local_state.CommandJournal(path)
    now = datetime.now(UTC)
    await restarted.recover_interrupted(now=now)
    (result,) = await restarted.pending(command.device_id)
    assert result.message == "AGENT_COMMAND_INTERRUPTED_BEFORE_START"
    assert result.status == "failed"
    assert result.command_id == command.command_id
    assert await restarted.begin(command, now=now) == "completed"
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT count(*) FROM endpoint_seen_commands").fetchone() == (0,)
    await restarted.recover_interrupted(now=now)
    assert await restarted.pending(command.device_id) == [result]


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
