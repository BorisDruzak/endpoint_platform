"""Import boundaries for the neutral Endpoint Agent runtime."""

from __future__ import annotations

import builtins
import importlib
import sys


_FORBIDDEN_IMPORTS = (
    "PySide6",
    "qasync",
    "pc_agent.ui_gui",
    "pc_agent.ui_bridge",
    "pc_agent.ui_gui.server_api",
    "helpdesk",
)


def _is_forbidden(module_name: str) -> bool:
    return any(
        module_name == forbidden or module_name.startswith(f"{forbidden}.")
        for forbidden in _FORBIDDEN_IMPORTS
    )


def test_runtime_main_imports_without_gui_bridge_or_helpdesk(monkeypatch) -> None:
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
