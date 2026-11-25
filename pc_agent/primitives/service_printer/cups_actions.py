"""Fixed local CUPS operations with a durable at-most-once delivery journal."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import subprocess
import sys
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory

from endpoint_contracts.commands import AgentCommandV1, AgentResultV1
from endpoint_contracts.cups_actions import (
    CUPS_ACTION_PARAMETERS,
    CUPS_QUEUE_CONFIGURE,
    CupsActionResultV1,
    CupsQueueConfigureParametersV1,
    CupsQueueStateV1,
)
from pc_agent.context_profiles.probe import _execute_bounded_command


_SOCKET = Path("/run/cups/cups.sock")
_PROGRAMS = {
    "lpstat": "/usr/bin/lpstat",
    "lp": "/usr/bin/lp",
    "cupsenable": "/usr/sbin/cupsenable",
    "cupsdisable": "/usr/sbin/cupsdisable",
    "cupsaccept": "/usr/sbin/cupsaccept",
    "cupsreject": "/usr/sbin/cupsreject",
}
_TEST_PAGE = "Endpoint Platform\n\nPrinter test page\n\nIf this page printed, the queue can print a document.\n"
_COMMAND_ERRORS = (OSError, ValueError, subprocess.TimeoutExpired)


def cups_actions_available() -> bool:
    return sys.platform == "linux" and _SOCKET.is_socket() and all(Path(path).is_file() for path in _PROGRAMS.values())


def _run_cups(program: str, *arguments: str) -> str:
    if not _SOCKET.is_socket():
        raise OSError("local CUPS scheduler is unavailable")
    result = _execute_bounded_command(
        (_PROGRAMS[program], "-h", str(_SOCKET), *arguments), 10.0, 16384,
        check_exit=True, env={"PATH": "/usr/bin:/usr/sbin", "LC_ALL": "C"},
    )
    return result.decode("utf-8", errors="replace")


def _matching_state(output: str, prefix: str) -> str:
    lines = [line[len(prefix):] for line in output.splitlines() if line.lower().startswith(prefix.lower())]
    if len(lines) != 1:
        raise ValueError("expected one local CUPS printer state")
    return lines[0]


def _queue_state(queue: str) -> CupsQueueStateV1:
    enabled = _matching_state(_run_cups("lpstat", "-p", queue), f"printer {queue} ")
    accepting = _matching_state(_run_cups("lpstat", "-a", queue), f"{queue} ")
    if enabled.startswith("disabled since "):
        is_enabled = False
    elif "enabled since " in enabled and enabled.startswith(("is idle.", "is holding new jobs.", "now printing ")):
        is_enabled = True
    else:
        raise ValueError("unexpected CUPS enabled state")
    if not accepting.startswith(("accepting requests since ", "not accepting requests since ")):
        raise ValueError("unexpected CUPS acceptance state")
    return CupsQueueStateV1(enabled=is_enabled, accepting=accepting.startswith("accepting "))


def _update_queue(
    parameters: CupsQueueConfigureParametersV1, before: CupsQueueStateV1, deadline: datetime,
) -> CupsQueueStateV1:
    enabled = parameters.enabled
    accepting = parameters.accepting
    if enabled != "keep" and before.enabled != (enabled == "on"):
        if datetime.now(UTC) >= deadline:
            raise TimeoutError
        _run_cups("cupsenable" if enabled == "on" else "cupsdisable", parameters.queue)
    if accepting != "keep" and before.accepting != (accepting == "on"):
        if datetime.now(UTC) >= deadline:
            raise TimeoutError
        _run_cups("cupsaccept" if accepting == "on" else "cupsreject", parameters.queue)
    after = _queue_state(parameters.queue)
    if (enabled != "keep" and after.enabled != (enabled == "on")) or (
        accepting != "keep" and after.accepting != (accepting == "on")
    ):
        raise ValueError("CUPS settings could not be verified")
    return after


def _submit_page(queue: str, command: AgentCommandV1) -> str:
    with TemporaryDirectory(prefix="endpoint-cups-") as directory:
        page = Path(directory) / "test-page.txt"
        page.write_text(_TEST_PAGE, encoding="ascii")
        output = _run_cups(
            "lp", "-d", queue, "-n", "1", "-P", "1",
            "-o", "job-sheets=none", "-o", "sides=one-sided",
            "-t", f"Endpoint test page {command.command_id}", "--", str(page),
        )
    match = re.match(rf"^request id is ({re.escape(queue)}-[1-9][0-9]{{0,9}})(?:\s|$)", output, re.IGNORECASE)
    if match is None:
        raise ValueError("CUPS did not return a usable job ID")
    return match[1]


def _connect(path: Path):
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA synchronous=FULL")
    return connection


def _claim(path: Path, key: str, digest: str) -> tuple[bool, str | None, str]:
    path.parent.mkdir(parents=True, exist_ok=True)
    with closing(_connect(path)) as connection, connection:
        connection.execute(
            """CREATE TABLE IF NOT EXISTS cups_actions (
                action_key TEXT PRIMARY KEY, digest TEXT NOT NULL, result_json TEXT
            )"""
        )
        inserted = connection.execute(
            "INSERT INTO cups_actions VALUES (?, ?, NULL) ON CONFLICT DO NOTHING", (key, digest),
        ).rowcount == 1
        stored_digest, result_json = connection.execute(
            "SELECT digest, result_json FROM cups_actions WHERE action_key = ?", (key,),
        ).fetchone()
    return inserted, result_json, stored_digest


def _store(path: Path, key: str, result: AgentResultV1) -> None:
    with closing(_connect(path)) as connection, connection:
        connection.execute("UPDATE cups_actions SET result_json = ? WHERE action_key = ?", (result.model_dump_json(), key))


def execute_cups_action(command: AgentCommandV1, journal: Path | None) -> AgentResultV1:
    parameters = CUPS_ACTION_PARAMETERS[command.capability].model_validate(command.parameters)

    def result(outcome, error_code=None, **fields) -> AgentResultV1:
        action = CupsActionResultV1(capability=command.capability, queue=parameters.queue,
                                    outcome=outcome, error_code=error_code, **fields)
        return AgentResultV1(
            schema_version="agent_result_v1", command_id=command.command_id, device_id=command.device_id,
            status="succeeded" if error_code is None else "failed",
            result_items=[action.model_dump(mode="json")], completed_at=datetime.now(UTC),
        )

    if journal is None or sys.platform != "linux":
        return result("rejected", "cups_unavailable")
    key = command.idempotency_key
    identity = json.dumps(
        [str(command.device_id), str(command.command_id), command.capability, parameters.model_dump(mode="json")],
        sort_keys=True, separators=(",", ":"),
    )
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()
    try:
        new, stored, stored_digest = _claim(journal, key, digest)
    except (OSError, sqlite3.Error):
        return result("rejected", "cups_local_journal_unavailable")
    if stored_digest != digest:
        return result("rejected", "cups_request_conflict")
    if not new:
        if stored is not None:
            try:
                return AgentResultV1.model_validate_json(stored)
            except ValueError:
                pass
        return result("unknown", "cups_outcome_unknown")

    if command.deadline_at <= datetime.now(UTC):
        completed = result("rejected", "cups_deadline_expired")
    else:
        try:
            before = _queue_state(parameters.queue)
        except _COMMAND_ERRORS:
            completed = result("rejected", "cups_queue_unavailable")
        else:
            try:
                if command.deadline_at <= datetime.now(UTC):
                    completed = result("rejected", "cups_deadline_expired", before=before)
                elif command.capability == CUPS_QUEUE_CONFIGURE:
                    completed = result("configured", before=before, after=_update_queue(parameters, before, command.deadline_at))
                elif not before.accepting:
                    completed = result("rejected", "cups_queue_rejecting", before=before)
                else:
                    completed = result("submitted", before=before, job_id=_submit_page(parameters.queue, command))
            except _COMMAND_ERRORS:
                completed = result("unknown", "cups_outcome_unknown", before=before)
    try:
        _store(journal, key, completed)
    except (OSError, sqlite3.Error):
        return result("unknown", "cups_outcome_unknown")
    return completed
