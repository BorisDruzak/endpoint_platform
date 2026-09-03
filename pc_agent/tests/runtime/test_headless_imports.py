"""Import boundaries for the neutral Endpoint Agent runtime."""

from __future__ import annotations

import builtins
import importlib
import sys
from pathlib import Path


_FORBIDDEN_IMPORTS = (
    "PySide6",
    "qasync",
    "pc_agent.ui_gui",
    "pc_agent.ui_bridge",
    "pc_agent.ui_gui.server_api",
    "pc_agent.ws_agent",
    "pc_agent.auth",
    "pc_agent.core.database",
    "pc_agent.core.job_manager",
    "pc_agent.core.orchestrator",
    "pc_agent.core.sender",
    "helpdesk",
)


def _is_forbidden(module_name: str) -> bool:
    return any(
        module_name == forbidden or module_name.startswith(f"{forbidden}.")
        for forbidden in _FORBIDDEN_IMPORTS
    )


def test_runtime_main_imports_without_gui_helpdesk_or_protocol_v3(monkeypatch) -> None:
    """Adding a forbidden dependency to the core must make its public import fail."""
    original_import = builtins.__import__

    def guarded_import(name, *args, **kwargs):
        if _is_forbidden(name):
            raise AssertionError(f"forbidden headless runtime import: {name}")
        return original_import(name, *args, **kwargs)

    for module_name in list(sys.modules):
        if module_name == "pc_agent.runtime" or module_name.startswith(
            "pc_agent.runtime."
        ):
            sys.modules.pop(module_name)
    monkeypatch.setattr(builtins, "__import__", guarded_import)

    runtime_main = importlib.import_module("pc_agent.runtime.main")

    assert runtime_main.RuntimeSettings.__module__ == "pc_agent.runtime.application"
    assert callable(runtime_main.run_runtime)
    assert callable(runtime_main.run_verify)


def test_retired_gui_and_helpdesk_transport_sources_are_absent() -> None:
    """The released Endpoint agent must not retain a dormant legacy branch."""
    root = Path(__file__).resolve().parents[2]

    for relative_path in ("ui_gui", "ui_bridge"):
        assert not any((root / relative_path).rglob("*.py"))
    for relative_path in ("ws_agent.py", "ws_agent_runtime_helpers.py"):
        assert not (root / relative_path).exists()
