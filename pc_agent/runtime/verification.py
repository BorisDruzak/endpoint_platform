"""Network-free verification for the neutral headless runtime."""

from __future__ import annotations

import ast
import asyncio
import json
from pathlib import Path
from uuid import UUID

from pc_agent import endpoint_gateway
from pc_agent.context_profiles.registry import CONTEXT_COLLECTION_CAPABILITIES
from pc_agent.device_credential import read_device_credential

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


def run_verify(settings: RuntimeSettings) -> int:
    """Validate durable local state and migrate SQLite without network access."""
    try:
        settings.validate()
        read_device_credential(settings.data_root / "device-credential")
        _verify_identity(settings.data_root / "identity.json")
        endpoint_gateway.read_gateway_current_version(
            settings.install_root / "current.json"
        )
        _verify_collector_registry()
        _verify_import_boundaries(Path(__file__).resolve().parent)
        asyncio.run(migrate_local_state(settings.data_root / "storage.db"))
    except Exception:
        return 1
    return 0


def _verify_identity(path: Path) -> None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError("invalid Endpoint identity file") from error
    required = {
        "version",
        "uuid",
        "machine_id",
        "install_id",
        "machine_id_source",
        "token",
    }
    if not isinstance(payload, dict) or not required.issubset(payload):
        raise ValueError("invalid Endpoint identity file")
    try:
        machine_id = UUID(payload["machine_id"])
        legacy_uuid = UUID(payload["uuid"])
        UUID(payload["install_id"])
    except (TypeError, ValueError, AttributeError) as error:
        raise ValueError("invalid Endpoint identity file") from error
    if (
        payload["version"] != 2
        or machine_id != legacy_uuid
        or not isinstance(payload["machine_id_source"], str)
        or not payload["machine_id_source"].strip()
        or payload["token"] is not None
    ):
        raise ValueError("invalid Endpoint identity file")


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
