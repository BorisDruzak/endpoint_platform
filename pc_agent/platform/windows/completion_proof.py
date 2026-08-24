"""Protected, bounded Windows command-completion evidence."""

from __future__ import annotations

import json
import os
import stat
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from endpoint_contracts import AgentCommandV1, AgentResultV1


COMPLETION_PROOF_FILENAME = "command-completions.jsonl"
MAX_RECORDS = 128
_FIELDS = frozenset(
    {"command_id", "capability", "status", "duration_ms", "result_item_count", "timestamp"}
)


class CompletionProofError(RuntimeError):
    """The fixed completion-proof path cannot be safely used."""


def _regular_nonreparse(path: Path, *, name: str) -> None:
    try:
        details = path.lstat()
    except FileNotFoundError as error:
        raise CompletionProofError(f"{name} is missing") from error
    if stat.S_ISLNK(details.st_mode) or not stat.S_ISREG(details.st_mode):
        raise CompletionProofError(f"{name} must be a regular non-reparse file")


def _data_root(path: Path) -> None:
    details = path.lstat()
    if stat.S_ISLNK(details.st_mode) or not stat.S_ISDIR(details.st_mode):
        raise CompletionProofError("data root must be a non-reparse directory")


def _record(command: AgentCommandV1, result: AgentResultV1, duration_ms: int) -> dict[str, object]:
    if duration_ms < 0:
        raise CompletionProofError("duration must be non-negative")
    return {
        "command_id": str(command.command_id),
        "capability": command.capability,
        "status": result.status,
        "duration_ms": duration_ms,
        "result_item_count": len(result.result_items),
        "timestamp": result.completed_at.isoformat(),
    }


def _validate_record(value: object) -> dict[str, object]:
    if not isinstance(value, Mapping) or set(value) != _FIELDS:
        raise CompletionProofError("completion proof schema is invalid")
    if not isinstance(value["command_id"], str) or not isinstance(value["capability"], str):
        raise CompletionProofError("completion proof identity is invalid")
    if not isinstance(value["status"], str) or not isinstance(value["timestamp"], str):
        raise CompletionProofError("completion proof status is invalid")
    if not isinstance(value["duration_ms"], int) or not isinstance(value["result_item_count"], int):
        raise CompletionProofError("completion proof counts are invalid")
    return dict(value)


def read_completion_proofs(data_root: Path) -> tuple[dict[str, object], ...]:
    """Read the fixed local proof file without returning unvalidated content."""
    _data_root(data_root)
    path = data_root / COMPLETION_PROOF_FILENAME
    if not path.exists():
        return ()
    _regular_nonreparse(path, name="completion proof")
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
        records = tuple(_validate_record(json.loads(line)) for line in lines if line)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CompletionProofError("completion proof cannot be read") from error
    if len(records) > MAX_RECORDS:
        raise CompletionProofError("completion proof record count is invalid")
    return records


class WindowsCompletionProofWriter:
    """Append one bounded record through an atomic replacement of a fixed file."""

    def __init__(self, data_root: Path) -> None:
        self._data_root = data_root

    def append(self, command: AgentCommandV1, result: AgentResultV1, duration_ms: int) -> None:
        self.append_marker(_record(command, result, duration_ms))

    def append_marker(self, marker: Mapping[str, object]) -> None:
        _data_root(self._data_root)
        records = [*read_completion_proofs(self._data_root), _validate_record(marker)]
        encoded = "".join(json.dumps(item, sort_keys=True, separators=(",", ":")) + "\n" for item in records[-MAX_RECORDS:]).encode("utf-8")
        target = self._data_root / COMPLETION_PROOF_FILENAME
        temporary = self._data_root / f".{COMPLETION_PROOF_FILENAME}.tmp"
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, target)
        except BaseException:
            try:
                temporary.unlink()
            except OSError:
                pass
            raise


__all__ = [
    "COMPLETION_PROOF_FILENAME",
    "CompletionProofError",
    "WindowsCompletionProofWriter",
    "read_completion_proofs",
]
