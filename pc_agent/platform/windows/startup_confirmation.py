"""Agent-side, operation-bound proof written only after a gateway handshake."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from pc_agent.version import AGENT_VERSION

from .update_paths import WindowsUpdatePaths
from .acl import PyWin32AclAdapter
from .durable_state import write_json_atomic
from .update_transaction import _read_state


class StartupProofWriter:
    """Publish a fresh local proof for the updater after server connectivity."""

    def __init__(self, paths: WindowsUpdatePaths) -> None:
        self._paths = paths

    def record_after_server_handshake(self) -> bool:
        try:
            pending = _read_state(self._paths.pending_path, 16384)
            current = _read_state(self._paths.current_path, 4096)
            attempt = _read_state(self._paths.updates_root / "startup-attempt.json", 4096)
            if not all(isinstance(value, dict) for value in (pending, current, attempt)):
                return False
            version = pending["version"]
            operation_id = pending["operation_id"]
            if (
                not isinstance(version, str)
                or not isinstance(operation_id, str)
                or not isinstance(current, dict)
                or current.get("version") != version
                or version != AGENT_VERSION
                or attempt.get("operation_id") != operation_id
                or attempt.get("version") != version
                or not isinstance(attempt.get("attempt_id"), str)
            ):
                return False
        except (OSError, ValueError, json.JSONDecodeError, KeyError):
            return False
        path = self._paths.updates_root / "startup-confirmation.json"
        write_json_atomic(
            path,
            {
                "attempt_id": attempt["attempt_id"],
                "confirmed_at": datetime.now(UTC).isoformat(),
                "operation_id": operation_id,
                "status": "confirmed",
                "version": version,
            },
            trusted_root=self._paths.updates_root,
            max_bytes=4096,
            protect=PyWin32AclAdapter().protect_update_path,
        )
        return True


__all__ = ["StartupProofWriter"]
