"""Agent-side, operation-bound proof written only after a gateway handshake."""

from __future__ import annotations

import json
import os
import uuid
from datetime import UTC, datetime

from .update_paths import WindowsUpdatePaths


class StartupProofWriter:
    """Publish a fresh local proof for the updater after server connectivity."""

    def __init__(self, paths: WindowsUpdatePaths) -> None:
        self._paths = paths

    def record_after_server_handshake(self) -> bool:
        try:
            pending = json.loads(self._paths.pending_path.read_text(encoding="utf-8"))
            current = json.loads(self._paths.current_path.read_text(encoding="utf-8"))
            attempt = json.loads((self._paths.updates_root / "startup-attempt.json").read_text(encoding="utf-8"))
            version = pending["version"]
            operation_id = pending["operation_id"]
            if (
                not isinstance(version, str)
                or not isinstance(operation_id, str)
                or current != {"version": version}
                or attempt.get("operation_id") != operation_id
                or attempt.get("version") != version
                or not isinstance(attempt.get("attempt_id"), str)
            ):
                return False
        except (OSError, ValueError, json.JSONDecodeError, KeyError):
            return False
        self._paths.updates_root.mkdir(parents=True, exist_ok=True)
        path = self._paths.updates_root / "startup-confirmation.json"
        temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
        try:
            temporary.write_text(
                json.dumps(
                    {
                        "attempt_id": attempt["attempt_id"],
                        "confirmed_at": datetime.now(UTC).isoformat(),
                        "operation_id": operation_id,
                        "status": "confirmed",
                        "version": version,
                    },
                    separators=(",", ":"),
                ),
                encoding="utf-8",
            )
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)
        return True


__all__ = ["StartupProofWriter"]
