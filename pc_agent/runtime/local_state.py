"""Endpoint Agent V2-owned SQLite schema, independent of Helpdesk Protocol V3."""

from __future__ import annotations

from pathlib import Path

import aiosqlite


LOCAL_STATE_SCHEMA_VERSION = 1


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
            await connection.commit()
        except BaseException:
            await connection.rollback()
            raise
