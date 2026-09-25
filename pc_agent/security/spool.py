"""Protected SQLite spool for bounded SecurityEvent replay after reconnect."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import aiosqlite
from pydantic import TypeAdapter, ValidationError

from endpoint_contracts.security_events import (
    AgentSecurityEventBatchV1,
    SecurityEventAckV1,
    SecurityEventV1,
)
from pc_agent.policy.cache import _require_safe_directory


SPOOL_FILENAME = "security-events-v1.db"
MAX_SPOOL_EVENTS = 1000
MAX_SPOOL_PAYLOAD_BYTES = 5 * 1024 * 1024
MAX_SPOOL_AGE = timedelta(hours=24)
MAX_WSS_BATCH_PAYLOAD_BYTES = 60 * 1024
_REPARSE_ATTRIBUTE = 0x400
_EVENT_ADAPTER = TypeAdapter(SecurityEventV1)


class SecurityEventSpoolError(RuntimeError):
    """The protected event queue cannot be used safely."""


@dataclass(frozen=True, slots=True)
class SecurityEventSpoolStats:
    queued_events: int
    queued_payload_bytes: int
    dropped_overflow: int
    dropped_expired: int


class SecurityEventSpool:
    """Discard oldest first at capacity, and delete delivered events only on exact ACK.

    The 5 MiB limit applies to serialized event payloads. SQLite page and
    rollback-journal overhead is additional and remains inside the protected
    Agent data directory. Drop counts persist across Agent restarts.
    """

    def __init__(
        self,
        data_root: Path,
        *,
        max_events: int = MAX_SPOOL_EVENTS,
        max_payload_bytes: int = MAX_SPOOL_PAYLOAD_BYTES,
    ) -> None:
        if max_events < 1 or max_payload_bytes < 1:
            raise ValueError("spool bounds must be positive")
        self.path = Path(data_root) / SPOOL_FILENAME
        self._max_events = max_events
        self._max_payload_bytes = max_payload_bytes
        self._opened = False

    async def open(self) -> None:
        self._prepare_file()
        async with aiosqlite.connect(self.path) as connection:
            await connection.execute("PRAGMA secure_delete=ON")
            await connection.execute("PRAGMA synchronous=FULL")
            await connection.execute("PRAGMA journal_mode=DELETE")
            await connection.execute("PRAGMA auto_vacuum=FULL")
            await connection.execute("BEGIN IMMEDIATE")
            try:
                await connection.execute(
                    """CREATE TABLE IF NOT EXISTS security_event_spool (
                        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_identifier TEXT NOT NULL UNIQUE,
                        occurred_at TEXT NOT NULL,
                        payload_json TEXT NOT NULL
                    )"""
                )
                await connection.execute(
                    """CREATE TABLE IF NOT EXISTS security_event_spool_stats (
                        singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                        dropped_overflow INTEGER NOT NULL DEFAULT 0,
                        dropped_expired INTEGER NOT NULL DEFAULT 0
                    )"""
                )
                await connection.execute(
                    "INSERT OR IGNORE INTO security_event_spool_stats(singleton) VALUES (1)"
                )
                await connection.commit()
            except BaseException:
                await connection.rollback()
                raise
        self._opened = True

    async def enqueue(self, event: SecurityEventV1, *, now: datetime) -> bool:
        self._require_open()
        now = _utc(now)
        payload = event.model_dump_json()
        event_age = now - _utc(event.occurred_at)
        async with aiosqlite.connect(self.path) as connection:
            await connection.execute("PRAGMA secure_delete=ON")
            await connection.execute("BEGIN IMMEDIATE")
            try:
                await self._expire(connection, now)
                if event_age > MAX_SPOOL_AGE:
                    await self._increment(connection, "dropped_expired", 1)
                    await connection.commit()
                    return False
                if len(payload.encode("utf-8")) > self._max_payload_bytes:
                    await self._increment(connection, "dropped_overflow", 1)
                    await connection.commit()
                    return False
                cursor = await connection.execute(
                    """INSERT OR IGNORE INTO security_event_spool
                    (event_identifier, occurred_at, payload_json) VALUES (?, ?, ?)""",
                    (str(event.event_identifier), _utc(event.occurred_at).isoformat(), payload),
                )
                inserted = cursor.rowcount == 1
                await cursor.close()
                if inserted:
                    await self._trim(connection)
                await connection.commit()
                return inserted
            except BaseException:
                await connection.rollback()
                raise

    async def next_batch(self, *, now: datetime) -> AgentSecurityEventBatchV1 | None:
        self._require_open()
        async with aiosqlite.connect(self.path) as connection:
            await connection.execute("PRAGMA secure_delete=ON")
            await connection.execute("BEGIN IMMEDIATE")
            try:
                await self._expire(connection, _utc(now))
                async with connection.execute(
                    "SELECT payload_json FROM security_event_spool ORDER BY sequence LIMIT 50"
                ) as cursor:
                    rows = await cursor.fetchall()
                await connection.commit()
            except BaseException:
                await connection.rollback()
                raise
        if not rows:
            return None
        events = []
        batch_id = uuid4()
        for (payload,) in rows:
            event = _EVENT_ADAPTER.validate_json(payload)
            try:
                # Contract validation includes the entire envelope payload bound.
                candidate = AgentSecurityEventBatchV1(
                    schema_version="agent_security_event_batch_v1",
                    batch_id=batch_id,
                    events=[*events, event],
                )
            except ValidationError:
                if not events:
                    raise SecurityEventSpoolError("single security event exceeds batch bound")
                break
            if len(candidate.model_dump_json().encode("utf-8")) > MAX_WSS_BATCH_PAYLOAD_BYTES:
                break
            events.append(event)
        return AgentSecurityEventBatchV1(
            schema_version="agent_security_event_batch_v1",
            batch_id=batch_id,
            events=events,
        )

    async def acknowledge(
        self, batch: AgentSecurityEventBatchV1, ack: SecurityEventAckV1
    ) -> bool:
        self._require_open()
        identifiers = [event.event_identifier for event in batch.events]
        if ack.batch_id != batch.batch_id or ack.event_identifiers != identifiers:
            return False
        async with aiosqlite.connect(self.path) as connection:
            await connection.execute("PRAGMA secure_delete=ON")
            await connection.execute("BEGIN IMMEDIATE")
            try:
                placeholders = ",".join("?" for _ in identifiers)
                async with connection.execute(
                    f"SELECT event_identifier FROM security_event_spool "
                    f"WHERE event_identifier IN ({placeholders})",
                    tuple(str(identifier) for identifier in identifiers),
                ) as cursor:
                    present = {row[0] for row in await cursor.fetchall()}
                if present != {str(identifier) for identifier in identifiers}:
                    await connection.rollback()
                    return False
                await connection.execute(
                    f"DELETE FROM security_event_spool "
                    f"WHERE event_identifier IN ({placeholders})",
                    tuple(str(identifier) for identifier in identifiers),
                )
                await connection.commit()
                return True
            except BaseException:
                await connection.rollback()
                raise

    async def stats(self) -> SecurityEventSpoolStats:
        self._require_open()
        async with aiosqlite.connect(self.path) as connection:
            async with connection.execute(
                "SELECT COUNT(*), COALESCE(SUM(length(CAST(payload_json AS BLOB))), 0) "
                "FROM security_event_spool"
            ) as cursor:
                count, size = await cursor.fetchone()
            async with connection.execute(
                "SELECT dropped_overflow, dropped_expired "
                "FROM security_event_spool_stats WHERE singleton = 1"
            ) as cursor:
                overflow, expired = await cursor.fetchone()
        return SecurityEventSpoolStats(count, size, overflow, expired)

    async def _expire(self, connection: aiosqlite.Connection, now: datetime) -> None:
        cutoff = (now - MAX_SPOOL_AGE).isoformat()
        cursor = await connection.execute(
            "DELETE FROM security_event_spool WHERE occurred_at < ?", (cutoff,)
        )
        deleted = cursor.rowcount
        await cursor.close()
        if deleted:
            await self._increment(connection, "dropped_expired", deleted)

    async def _trim(self, connection: aiosqlite.Connection) -> None:
        async with connection.execute(
            "SELECT COUNT(*), COALESCE(SUM(length(CAST(payload_json AS BLOB))), 0) "
            "FROM security_event_spool"
        ) as cursor:
            count, size = await cursor.fetchone()
        dropped = 0
        while count > self._max_events or size > self._max_payload_bytes:
            async with connection.execute(
                "SELECT sequence, length(CAST(payload_json AS BLOB)) "
                "FROM security_event_spool ORDER BY sequence LIMIT 1"
            ) as cursor:
                sequence, payload_size = await cursor.fetchone()
            await connection.execute(
                "DELETE FROM security_event_spool WHERE sequence = ?", (sequence,)
            )
            count -= 1
            size -= payload_size
            dropped += 1
        if dropped:
            await self._increment(connection, "dropped_overflow", dropped)

    @staticmethod
    async def _increment(
        connection: aiosqlite.Connection, column: str, count: int
    ) -> None:
        # All column names are hard-coded by this module's two call sites.
        await connection.execute(
            f"UPDATE security_event_spool_stats SET {column} = {column} + ? "
            "WHERE singleton = 1", (count,)
        )

    def _prepare_file(self) -> None:
        _require_safe_directory(self.path.parent)
        try:
            details = self.path.lstat()
        except FileNotFoundError:
            descriptor = os.open(
                self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600
            )
            os.close(descriptor)
            if os.name == "nt":
                from pc_agent.platform.windows.acl import PyWin32AclAdapter

                PyWin32AclAdapter().protect_machine_data_file(self.path)
            details = self.path.lstat()
        if (
            not stat.S_ISREG(details.st_mode)
            or stat.S_ISLNK(details.st_mode)
            or getattr(details, "st_file_attributes", 0) & _REPARSE_ATTRIBUTE
        ):
            raise SecurityEventSpoolError("event spool path is unsafe")
        if os.name == "nt":
            from pc_agent.platform.windows.acl import PyWin32AclAdapter

            PyWin32AclAdapter().assert_protected_file(self.path)
        elif details.st_uid != os.getuid() or stat.S_IMODE(details.st_mode) & 0o077:
            raise SecurityEventSpoolError("event spool file is not private")

    def _require_open(self) -> None:
        if not self._opened:
            raise SecurityEventSpoolError("event spool is not open")


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("spool timestamps must have a timezone")
    return value.astimezone(UTC)
