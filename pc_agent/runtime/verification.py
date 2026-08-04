"""Network-free verification for the neutral headless runtime."""

from __future__ import annotations

import ast
import asyncio
import json
import re
from pathlib import Path

from pc_agent import endpoint_gateway
from pc_agent.context_profiles.registry import CONTEXT_COLLECTION_CAPABILITIES
from pc_agent.device_credential import read_device_credential
from pc_agent.enrollment_identity import (
    ENROLLMENT_IDENTITY_FILENAME,
    read_enrollment_device_id,
)

from .application import RuntimeSettings
from .local_state import migrate_local_state


_EXPECTED_CONTEXT_CAPABILITIES = frozenset(
    {
        "context.baseline.collect",
        "context.health.collect",
        "context.network.collect",
        "context.diagnostic.collect",
    }
)
_FORBIDDEN_IMPORT_PREFIXES = (
    "PySide6",
    "qasync",
    "pc_agent.ui_gui",
    "pc_agent.ui_bridge",
    "pc_agent.ws_agent",
    "pc_agent.auth",
    "pc_agent.core.database",
    "pc_agent.core.job_manager",
    "pc_agent.core.orchestrator",
    "pc_agent.core.sender",
    "helpdesk",
)
_WINDOWS_SELECTOR_VERSION = re.compile(
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$"
)


def run_verify(settings: RuntimeSettings) -> int:
    """Validate durable local state and migrate SQLite without network access."""
    try:
        settings.validate()
        read_device_credential(settings.data_root / "device-credential")
        read_enrollment_device_id(
            settings.data_root / ENROLLMENT_IDENTITY_FILENAME
        )
        _verify_current_selector(settings.install_root / "current.json")
        _verify_collector_registry()
        _verify_import_boundaries(Path(__file__).resolve().parent)
        asyncio.run(migrate_local_state(settings.data_root / "storage.db"))
    except Exception:
        return 1
    return 0


def _verify_current_selector(path: Path) -> None:
    """Accept only the immutable selector schema for either supported host."""
    try:
        endpoint_gateway.read_gateway_current_version(path)
        return
    except ValueError:
        pass
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError("invalid Windows release selector") from error
    if (
        not isinstance(payload, dict)
        or set(payload) != {"version"}
        or not isinstance(payload.get("version"), str)
        or _WINDOWS_SELECTOR_VERSION.fullmatch(payload["version"]) is None
    ):
        raise ValueError("invalid Windows release selector")

def _verify_collector_registry() -> None:
    if CONTEXT_COLLECTION_CAPABILITIES != _EXPECTED_CONTEXT_CAPABILITIES:
        raise ValueError("invalid Device Context collector registry")


def _verify_import_boundaries(runtime_root: Path) -> None:
    for path in runtime_root.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        imported: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.append(node.module)
        if any(
            module == forbidden or module.startswith(f"{forbidden}.")
            for module in imported
            for forbidden in _FORBIDDEN_IMPORT_PREFIXES
        ):
            raise ValueError("headless runtime import boundary violated")
