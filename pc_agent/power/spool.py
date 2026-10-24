"""Independent protected queue; a native page and its cursor commit together."""

from __future__ import annotations

import os
import stat
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import aiosqlite

from endpoint_contracts.gateway_ws import PowerEventBatchEnvelopeV1
from endpoint_contracts.power_events import (
    PowerEventAckV1,
    PowerEventBatchV1,
    PowerEventV1,
    PowerSourceStatusV1,
)
from pc_agent.policy.cache import _require_safe_directory

from .native import NativePage

MAX_AGE = timedelta(days=30)


class PowerEventSpoolError(RuntimeError):
    """Unsafe file, corrupt queue or conflicting native identity."""


@dataclass(frozen=True, slots=True)
class PowerSpoolStats:
    queued_events: int
    queued_payload_bytes: int
    dropped_overflow: int
    dropped_expired: int
    rejected_permanent: int
    quarantined_events: int


def _utc(value):
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("power timestamps must be aware")
    return value.astimezone(UTC)


def _stable(event):
    return event.model_dump(mode="json", exclude={"observed_at"})


class PowerEventSpool:
    """Limits apply to live serialized payloads; SQLite pages are additional.

    Quarantine stores only the last 128 identifiers/reasons/times, never raw OS
    data or event payload. Counters persist independently of these bounded rows.
    """

    def __init__(
        self, data_root: Path, *, max_events=10000, max_payload_bytes=5 * 1024 * 1024
    ):
        if max_events < 1 or max_payload_bytes < 1:
            raise ValueError("power queue bounds must be positive")
        self.path = Path(data_root) / "power-events-v1.db"
        self._max_events = max_events
        self._max_bytes = max_payload_bytes
        self._opened = False

    async def open(self):
        self._prepare_file()
        async with aiosqlite.connect(self.path) as db:
            await db.execute("PRAGMA journal_mode=DELETE")
            await db.execute("PRAGMA auto_vacuum=FULL")
            await db.execute("PRAGMA synchronous=FULL")
            await db.execute("PRAGMA secure_delete=ON")
            await db.execute("BEGIN IMMEDIATE")
            try:
                await db.execute(
                    "CREATE TABLE IF NOT EXISTS power_queue (sequence INTEGER PRIMARY KEY AUTOINCREMENT, identifier TEXT UNIQUE NOT NULL, occurred_at TEXT NOT NULL, payload TEXT NOT NULL)"
                )
                await db.execute(
                    "CREATE TABLE IF NOT EXISTS power_state (singleton INTEGER PRIMARY KEY CHECK(singleton=1), checkpoint TEXT, status TEXT, overflow INTEGER NOT NULL DEFAULT 0, expired INTEGER NOT NULL DEFAULT 0, rejected INTEGER NOT NULL DEFAULT 0, loss INTEGER NOT NULL DEFAULT 0, resets INTEGER NOT NULL DEFAULT 0)"
                )
                await db.execute(
                    "CREATE TABLE IF NOT EXISTS power_quarantine (sequence INTEGER PRIMARY KEY AUTOINCREMENT, identifier TEXT NOT NULL, reason TEXT NOT NULL, rejected_at TEXT NOT NULL)"
                )
                await db.execute(
                    "INSERT OR IGNORE INTO power_state(singleton) VALUES (1)"
                )
                await db.commit()
            except BaseException:
                await db.rollback()
                raise
        self._opened = True

    @asynccontextmanager
    async def _transaction(self):
        if not self._opened:
            raise PowerEventSpoolError("power queue is not open")
        self._prepare_file()
        async with aiosqlite.connect(self.path) as db:
            await db.execute("PRAGMA synchronous=FULL")
            await db.execute("PRAGMA secure_delete=ON")
            await db.execute("BEGIN IMMEDIATE")
            try:
                yield db
                await db.commit()
            except BaseException:
                await db.rollback()
                raise

    async def checkpoint(self):
        async with self._transaction() as db:
            return (
                await (
                    await db.execute("SELECT checkpoint FROM power_state")
                ).fetchone()
            )[0]

    async def commit_page(self, page: NativePage, *, now: datetime):
        if len(page.events) > 128 or (
            page.checkpoint is not None and len(page.checkpoint) > 16384
        ):
            raise PowerEventSpoolError("native page exceeds bound")
        async with self._transaction() as db:
            await self._expire(db, now)
            for event in page.events:
                existing = await (
                    await db.execute(
                        "SELECT payload FROM power_queue WHERE identifier=?",
                        (str(event.event_identifier),),
                    )
                ).fetchone()
                if existing:
                    if _stable(
                        PowerEventV1.model_validate_json(existing[0])
                    ) != _stable(event):
                        raise PowerEventSpoolError("conflicting native power identity")
                    continue
                if _utc(event.occurred_at) < _utc(now) - MAX_AGE:
                    await db.execute("UPDATE power_state SET expired=expired+1")
                    continue
                await db.execute(
                    "INSERT INTO power_queue(identifier,occurred_at,payload) VALUES (?,?,?)",
                    (
                        str(event.event_identifier),
                        _utc(event.occurred_at).isoformat(),
                        event.model_dump_json(),
                    ),
                )
            await self._trim(db)
            await db.execute(
                "UPDATE power_state SET checkpoint=?,status=?,loss=loss+?,resets=resets+?",
                (
                    page.checkpoint,
                    page.status.model_dump_json(),
                    page.loss_count,
                    page.reset_count,
                ),
            )

    async def record(self, event: PowerEventV1, *, now: datetime):
        """Immediate callbacks must not overwrite the journal checkpoint/status."""
        async with self._transaction() as db:
            existing = await (
                await db.execute(
                    "SELECT payload FROM power_queue WHERE identifier=?",
                    (str(event.event_identifier),),
                )
            ).fetchone()
            if existing:
                if _stable(PowerEventV1.model_validate_json(existing[0])) != _stable(
                    event
                ):
                    raise PowerEventSpoolError("conflicting callback identity")
                return
            await self._expire(db, now)
            if _utc(event.occurred_at) < _utc(now) - MAX_AGE:
                await db.execute("UPDATE power_state SET expired=expired+1")
            else:
                await db.execute(
                    "INSERT INTO power_queue(identifier,occurred_at,payload) VALUES (?,?,?)",
                    (
                        str(event.event_identifier),
                        _utc(event.occurred_at).isoformat(),
                        event.model_dump_json(),
                    ),
                )
                await self._trim(db)

    async def set_unavailable(self, *, source, now):
        async with self._transaction() as db:
            row = await (await db.execute("SELECT status FROM power_state")).fetchone()
            previous = (
                PowerSourceStatusV1.model_validate_json(row[0]) if row[0] else None
            )
            status = PowerSourceStatusV1(
                schema_version="power_source_status_v1",
                source=source,
                availability="UNAVAILABLE",
                reported_at=now,
                coverage_started_at=previous.coverage_started_at if previous else None,
            )
            await db.execute(
                "UPDATE power_state SET status=?", (status.model_dump_json(),)
            )

    async def source_status(self):
        async with self._transaction() as db:
            row = await (
                await db.execute(
                    "SELECT status,overflow+expired+rejected+loss,resets FROM power_state"
                )
            ).fetchone()
        if not row[0]:
            return None
        return PowerSourceStatusV1.model_validate_json(row[0]).model_copy(
            update={"loss_count": row[1], "reset_count": row[2]}
        )

    async def next_batch(self, *, now):
        async with self._transaction() as db:
            await self._expire(db, now)
            rows = await (
                await db.execute(
                    "SELECT payload FROM power_queue ORDER BY sequence LIMIT 128"
                )
            ).fetchall()
            state = await (
                await db.execute(
                    "SELECT status,overflow+expired+rejected+loss,resets FROM power_state"
                )
            ).fetchone()
        if not state[0]:
            return None
        status = PowerSourceStatusV1.model_validate_json(state[0]).model_copy(
            update={"loss_count": state[1], "reset_count": state[2]}
        )
        batch = PowerEventBatchV1(
            schema_version="power_event_batch_v1",
            batch_id=uuid4(),
            events=[],
            source_status=status,
        )
        for (payload,) in rows:
            candidate = batch.model_copy(
                update={
                    "events": [*batch.events, PowerEventV1.model_validate_json(payload)]
                }
            )
            frame = PowerEventBatchEnvelopeV1(
                schema_version="gateway_ws_envelope_v1",
                kind="power_event_batch",
                sequence=2**63 - 1,
                payload=candidate,
            )
            if len(frame.model_dump_json().encode()) > 61440:
                break
            batch = candidate
        return batch

    async def acknowledge(self, batch: PowerEventBatchV1, ack: PowerEventAckV1):
        ids = [str(e.event_identifier) for e in batch.events]
        if (
            ack.batch_id != batch.batch_id
            or [str(r.event_identifier) for r in ack.results] != ids
        ):
            return False
        async with self._transaction() as db:
            for event in batch.events:
                row = await (
                    await db.execute(
                        "SELECT payload FROM power_queue WHERE identifier=?",
                        (str(event.event_identifier),),
                    )
                ).fetchone()
                if row and _stable(PowerEventV1.model_validate_json(row[0])) != _stable(
                    event
                ):
                    return False
            for result in ack.results:
                if result.disposition == "retry_later":
                    continue
                identifier = str(result.event_identifier)
                present = await (
                    await db.execute(
                        "SELECT 1 FROM power_queue WHERE identifier=?", (identifier,)
                    )
                ).fetchone()
                if not present:
                    # Independent retention/overflow may already have evicted
                    # an in-flight item. It cannot block unrelated later facts.
                    continue
                await db.execute(
                    "DELETE FROM power_queue WHERE identifier=?", (identifier,)
                )
                if result.disposition == "rejected":
                    await db.execute("UPDATE power_state SET rejected=rejected+1")
                    await db.execute(
                        "INSERT INTO power_quarantine(identifier,reason,rejected_at) VALUES (?,?,?)",
                        (
                            identifier,
                            result.reason_code,
                            _utc(ack.persisted_at).isoformat(),
                        ),
                    )
            await db.execute(
                "DELETE FROM power_quarantine WHERE sequence NOT IN (SELECT sequence FROM power_quarantine ORDER BY sequence DESC LIMIT 128)"
            )
            await db.execute(
                "DELETE FROM power_quarantine WHERE rejected_at < ?",
                ((_utc(ack.persisted_at) - MAX_AGE).isoformat(),),
            )
        return True

    async def stats(self):
        async with self._transaction() as db:
            queue = await (
                await db.execute(
                    "SELECT COUNT(*),COALESCE(SUM(length(CAST(payload AS BLOB))),0) FROM power_queue"
                )
            ).fetchone()
            counters = await (
                await db.execute("SELECT overflow,expired,rejected FROM power_state")
            ).fetchone()
            quarantine = (
                await (
                    await db.execute("SELECT COUNT(*) FROM power_quarantine")
                ).fetchone()
            )[0]
        return PowerSpoolStats(*queue, *counters, quarantine)

    async def _expire(self, db, now):
        await db.execute(
            "DELETE FROM power_quarantine WHERE rejected_at < ?",
            ((_utc(now) - MAX_AGE).isoformat(),),
        )
        cursor = await db.execute(
            "DELETE FROM power_queue WHERE occurred_at < ?",
            ((_utc(now) - MAX_AGE).isoformat(),),
        )
        await db.execute("UPDATE power_state SET expired=expired+?", (cursor.rowcount,))

    async def _trim(self, db):
        count, size = await (
            await db.execute(
                "SELECT COUNT(*),COALESCE(SUM(length(CAST(payload AS BLOB))),0) FROM power_queue"
            )
        ).fetchone()
        dropped = 0
        while count > self._max_events or size > self._max_bytes:
            sequence, amount = await (
                await db.execute(
                    "SELECT sequence,length(CAST(payload AS BLOB)) FROM power_queue ORDER BY sequence LIMIT 1"
                )
            ).fetchone()
            await db.execute("DELETE FROM power_queue WHERE sequence=?", (sequence,))
            count, size, dropped = count - 1, size - amount, dropped + 1
        await db.execute("UPDATE power_state SET overflow=overflow+?", (dropped,))

    def _prepare_file(self):
        _require_safe_directory(self.path.parent)
        try:
            details = self.path.lstat()
        except FileNotFoundError:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
            if os.name == "nt":
                from pc_agent.platform.windows.acl import PyWin32AclAdapter

                PyWin32AclAdapter().protect_machine_data_file(self.path)
            details = self.path.lstat()
        if (
            not stat.S_ISREG(details.st_mode)
            or stat.S_ISLNK(details.st_mode)
            or getattr(details, "st_file_attributes", 0) & 0x400
        ):
            raise PowerEventSpoolError("power spool path is unsafe")
        if os.name == "nt":
            from pc_agent.platform.windows.acl import PyWin32AclAdapter

            PyWin32AclAdapter().assert_protected_file(self.path)
        elif details.st_uid != os.getuid() or stat.S_IMODE(details.st_mode) & 0o077:
            raise PowerEventSpoolError("power spool is not private")
