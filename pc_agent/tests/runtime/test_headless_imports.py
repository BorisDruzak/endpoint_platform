"""Import boundaries for the neutral Endpoint Agent runtime."""

from __future__ import annotations

import builtins
import subprocess
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
    # Use a fresh interpreter: replacing runtime modules in the pytest process
    # creates different exception/dataclass identities for later lifecycle tests.
    code = f"""
import builtins
import importlib
forbidden = {_FORBIDDEN_IMPORTS!r}
original = builtins.__import__
def guarded(name, *args, **kwargs):
    if any(name == item or name.startswith(item + '.') for item in forbidden):
        raise AssertionError('forbidden headless runtime import: ' + name)
    return original(name, *args, **kwargs)
builtins.__import__ = guarded
module = importlib.import_module('pc_agent.runtime.main')
assert module.RuntimeSettings.__module__ == 'pc_agent.runtime.application'
assert callable(module.run_runtime)
assert callable(module.run_verify)
"""
    result = subprocess.run([sys.executable, "-c", code], capture_output=True,
        text=True, timeout=30, check=False)
    assert result.returncode == 0, result.stderr


def test_retired_gui_and_helpdesk_transport_sources_are_absent() -> None:
    """The released Endpoint agent must not retain a dormant legacy branch."""
    root = Path(__file__).resolve().parents[2]

    for relative_path in ("ui_gui", "ui_bridge"):
        assert not any((root / relative_path).rglob("*.py"))
    for relative_path in ("ws_agent.py", "ws_agent_runtime_helpers.py"):
        assert not (root / relative_path).exists()
