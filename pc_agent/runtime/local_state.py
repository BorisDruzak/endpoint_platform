"""Endpoint Agent V2-owned SQLite schema, independent of Helpdesk Protocol V3."""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
import hashlib
import json
from pathlib import Path
from uuid import UUID

import aiosqlite

from endpoint_contracts.commands import AgentCommandV1, AgentResultV1

# The inbox is additive. Keep the marker readable by the rollback Core.
LOCAL_STATE_SCHEMA_VERSION = 1
_MAX_COMMAND_RECORDS = 4096
_COMPLETED_RETENTION = timedelta(days=1)


class LocalStateError(RuntimeError):
    """The V2 local-state schema cannot be opened safely."""


async def migrate_local_state(path: Path) -> None:
    """Create or validate only the tables owned by the neutral V2 runtime."""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    async with aiosqlite.connect(path) as connection:
        try:
            await connection.execute("BEGIN IMMEDIATE")
            await connection.execute(
                """
                CREATE TABLE IF NOT EXISTS endpoint_runtime_schema (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    schema_version INTEGER NOT NULL CHECK (schema_version >= 1)
                )
                """
            )
            cursor = await connection.execute(
                "SELECT schema_version FROM endpoint_runtime_schema WHERE singleton = 1"
            )
            row = await cursor.fetchone()
            await cursor.close()
            if row is None:
                await connection.execute(
                    "INSERT INTO endpoint_runtime_schema(singleton, schema_version) VALUES (1, ?)",
                    (LOCAL_STATE_SCHEMA_VERSION,),
                )
            elif row[0] != LOCAL_STATE_SCHEMA_VERSION:
                raise LocalStateError("unsupported Endpoint runtime local-state schema")

            await connection.execute(
                """
                CREATE TABLE IF NOT EXISTS endpoint_pending_results (
                    command_id TEXT PRIMARY KEY,
                    result_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0)
                )
                """
            )
            await connection.execute(
                """
                CREATE TABLE IF NOT EXISTS endpoint_seen_commands (
                    command_id TEXT PRIMARY KEY,
                    result_json TEXT NOT NULL,
                    completed_at TEXT NOT NULL
                )
                """
            )
            await connection.execute(
                """
                CREATE TABLE IF NOT EXISTS endpoint_command_inbox (
                    command_id TEXT PRIMARY KEY,
                    device_id TEXT NOT NULL,
                    digest TEXT,
                    deadline_at TEXT,
                    state TEXT NOT NULL CHECK (state IN ('running', 'completed', 'canceled'))
                )
                """
            )
            await connection.commit()
        except BaseException:
            await connection.rollback()
            raise


class CommandJournal:
    """Persist start authority and a result before either is acknowledged remotely."""

    def __init__(self, path: Path) -> None:
        self.path = path

    @asynccontextmanager
    async def _write(self):
        async with aiosqlite.connect(self.path, timeout=1) as connection:
            await connection.execute("BEGIN IMMEDIATE")
            try:
                yield connection
                await connection.commit()
            except BaseException:
                await connection.rollback()
                raise

    async def begin(self, command: AgentCommandV1, *, now: datetime) -> str:
        identity = str(command.command_id), str(command.device_id)
        digest = _command_digest(command)
        async with self._write() as connection:
            async with connection.execute(
                "SELECT device_id, digest, state FROM endpoint_command_inbox WHERE command_id = ?",
                identity[:1],
            ) as cursor:
                row = await cursor.fetchone()
            if row is not None:
                device, existing_digest, state = row
                if device != identity[1] or existing_digest not in (None, digest):
                    raise LocalStateError("command identity conflicts with journal")
                if existing_digest is None:
                    await connection.execute(
                        "UPDATE endpoint_command_inbox SET digest = ?, deadline_at = ? WHERE command_id = ?",
                        (digest, _utc(command.deadline_at), identity[0]),
                    )
                return state
            if command.deadline_at <= now:
                return "expired"
            await self._reserve_record(connection, now=now)
            await connection.execute(
                "INSERT INTO endpoint_command_inbox VALUES (?, ?, ?, ?, 'running')",
                (*identity, digest, _utc(command.deadline_at)),
            )
            return "execute"

    async def cancel(self, device_id: UUID, command_id: UUID) -> None:
        # A cancel fences work that has not started. A started operation retains
        # its actual or uncertain result even if the server cancels its request.
        async with self._write() as connection:
            key = str(command_id)
            async with connection.execute(
                "SELECT device_id FROM endpoint_command_inbox WHERE command_id = ?", (key,)
            ) as cursor:
                row = await cursor.fetchone()
            if row is not None:
                if row[0] != str(device_id):
                    raise LocalStateError("command identity conflicts with journal")
                return
            await self._reserve_record(connection, now=datetime.now(UTC))
            await connection.execute(
                "INSERT INTO endpoint_command_inbox VALUES (?, ?, NULL, NULL, 'canceled')",
                (key, str(device_id)),
            )

    @staticmethod
    async def _reserve_record(connection, *, now: datetime) -> None:
        async with connection.execute("SELECT count(*) FROM endpoint_command_inbox") as cursor:
            (count,) = await cursor.fetchone()
        if count < _MAX_COMMAND_RECORDS:
            return
        async with connection.execute(
            """
            SELECT i.command_id FROM endpoint_command_inbox AS i
                WHERE i.state IN ('completed', 'canceled') AND i.deadline_at < ?
                  AND NOT EXISTS (
                      SELECT 1 FROM endpoint_pending_results AS p WHERE p.command_id = i.command_id
                  )
                  AND NOT EXISTS (
                      SELECT 1 FROM endpoint_seen_commands AS s WHERE s.command_id = i.command_id
                  )
                ORDER BY i.deadline_at LIMIT 128
            """,
            (_utc(now - _COMPLETED_RETENTION),),
        ) as cursor:
            expired = await cursor.fetchall()
        if not expired:
            raise LocalStateError("command journal capacity reached")
        await connection.executemany(
            "DELETE FROM endpoint_command_inbox WHERE command_id = ?", expired,
        )

    async def complete(self, command: AgentCommandV1, result: AgentResultV1) -> None:
        if (command.command_id, command.device_id) != (result.command_id, result.device_id):
            raise LocalStateError("command result identity conflicts with journal")
        async with self._write() as connection:
            async with connection.execute(
                "SELECT digest, state FROM endpoint_command_inbox WHERE command_id = ? AND device_id = ?",
                (str(command.command_id), str(command.device_id)),
            ) as cursor:
                row = await cursor.fetchone()
            if row != (_command_digest(command), "running"):
                raise LocalStateError("command completion has no matching start")
            await _store_result(connection, result)

    async def recover_interrupted(self, *, now: datetime) -> None:
        async with self._write() as connection:
            async with connection.execute(
                "SELECT command_id, device_id FROM endpoint_command_inbox WHERE state = 'running'"
            ) as cursor:
                rows = await cursor.fetchall()
            for command_id, device_id in rows:
                await _store_result(connection, AgentResultV1(
                    schema_version="agent_result_v1", command_id=UUID(command_id),
                    device_id=UUID(device_id), status="failed", completed_at=now,
                    message="AGENT_COMMAND_OUTCOME_UNKNOWN",
                ))

    async def pending(self, device_id: UUID, *, limit: int = 32) -> list[AgentResultV1]:
        if not 1 <= limit <= 128:
            raise ValueError("pending result limit is invalid")
        async with aiosqlite.connect(self.path, timeout=1) as connection:
            async with connection.execute(
                """
                SELECT p.result_json FROM endpoint_pending_results AS p
                JOIN endpoint_command_inbox AS i ON i.command_id = p.command_id
                WHERE i.device_id = ? ORDER BY p.created_at, p.command_id LIMIT ?
                """,
                (str(device_id), limit),
            ) as cursor:
                return [AgentResultV1.model_validate_json(row[0]) async for row in cursor]

    async def pending_result(self, device_id: UUID, command_id: UUID) -> AgentResultV1 | None:
        async with aiosqlite.connect(self.path, timeout=1) as connection:
            async with connection.execute(
                """
                SELECT p.result_json FROM endpoint_pending_results AS p
                JOIN endpoint_command_inbox AS i ON i.command_id = p.command_id
                WHERE i.device_id = ? AND i.command_id = ?
                """,
                (str(device_id), str(command_id)),
            ) as cursor:
                row = await cursor.fetchone()
                return None if row is None else AgentResultV1.model_validate_json(row[0])

    async def acknowledge(self, result: AgentResultV1) -> bool:
        async with self._write() as connection:
            async with connection.execute(
                "DELETE FROM endpoint_pending_results WHERE command_id = ? AND result_json = ?",
                (str(result.command_id), result.model_dump_json()),
            ) as cursor:
                return cursor.rowcount == 1


def _utc(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds")


def _command_digest(command: AgentCommandV1) -> str:
    value = command.model_dump(mode="json")
    value.update(created_at=_utc(command.created_at), deadline_at=_utc(command.deadline_at))
    serialized = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(serialized.encode("ascii")).hexdigest()


async def _store_result(connection, result: AgentResultV1) -> None:
    command_id = str(result.command_id)
    await connection.execute(
        "INSERT INTO endpoint_pending_results (command_id, result_json, created_at) VALUES (?, ?, ?)",
        (command_id, result.model_dump_json(), _utc(result.completed_at)),
    )
    if result.message == "AGENT_COMMAND_OUTCOME_UNKNOWN":
        await connection.execute(
            "INSERT INTO endpoint_seen_commands VALUES (?, ?, ?)",
            (command_id, result.model_dump_json(), _utc(result.completed_at)),
        )
    await connection.execute(
        "UPDATE endpoint_command_inbox SET state = 'completed' WHERE command_id = ?", (command_id,)
    )
