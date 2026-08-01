"""Architecture guards for Endpoint Platform's agent-control boundary."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest


FORBIDDEN_ROUTE_FRAGMENTS = {
    "/proxy",
    "/relay",
    "/invoke-service",
    "/forward",
}

FORBIDDEN_RUNTIME_IMPORTS = {
    "pc_agent.ui_gui",
    "pc_agent.ui_bridge",
    "pc_agent.ui_gui.server_api",
}

_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
_SERVER_ROOT = _REPOSITORY_ROOT / "endpoint_server"
_RUNTIME_ROOT = _REPOSITORY_ROOT / "pc_agent" / "runtime"
_ROUTE_METHODS = {"get", "post", "put", "patch", "delete", "api_route", "websocket"}
_FORBIDDEN_OUTBOUND_CALLS = {
    ("requests", "request"),
    ("requests", "get"),
    ("requests", "post"),
    ("requests", "put"),
    ("requests", "patch"),
    ("requests", "delete"),
    ("httpx", "request"),
    ("httpx", "get"),
    ("httpx", "post"),
    ("httpx", "put"),
    ("httpx", "patch"),
    ("httpx", "delete"),
    ("urllib.request", "urlopen"),
}


def _python_files(root: Path) -> list[Path]:
    return sorted(root.rglob("*.py"))


def _route_paths(tree: ast.AST) -> list[str]:
    paths: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue
            if not isinstance(decorator.func, ast.Attribute):
                continue
            if decorator.func.attr not in _ROUTE_METHODS or not decorator.args:
                continue
            route = decorator.args[0]
            if isinstance(route, ast.Constant) and isinstance(route.value, str):
                paths.append(route.value)
    return paths


def _outbound_calls(tree: ast.AST) -> list[tuple[str, str]]:
    calls: list[tuple[str, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if not isinstance(node.func.value, ast.Name):
            continue
        calls.append((node.func.value.id, node.func.attr))
    return calls


def test_endpoint_server_rejects_generic_relay_routes_and_outbound_url_execution() -> None:
    """A generic service relay or URL executor would violate the control-plane boundary."""
    forbidden_routes: list[str] = []
    forbidden_calls: list[str] = []

    for path in _python_files(_SERVER_ROOT):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        forbidden_routes.extend(
            f"{path.relative_to(_REPOSITORY_ROOT)}:{route}"
            for route in _route_paths(tree)
            if any(fragment in route.lower() for fragment in FORBIDDEN_ROUTE_FRAGMENTS)
        )
        forbidden_calls.extend(
            f"{path.relative_to(_REPOSITORY_ROOT)}:{module}.{method}"
            for module, method in _outbound_calls(tree)
            if (module, method) in _FORBIDDEN_OUTBOUND_CALLS
        )

    assert not forbidden_routes, f"generic relay routes are forbidden: {forbidden_routes}"
    assert not forbidden_calls, f"generic outbound URL execution is forbidden: {forbidden_calls}"


@pytest.mark.xfail(
    reason="Task 2 must create pc_agent/runtime before this headless-import guard can pass",
    strict=True,
)
def test_future_runtime_package_is_headless() -> None:
    """Task 2 must provide a headless runtime with no GUI or bridge dependency."""
    assert _RUNTIME_ROOT.is_dir(), "Task 2 must create pc_agent/runtime"

    forbidden_imports: list[str] = []
    for path in _python_files(_RUNTIME_ROOT):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_modules = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_modules = [node.module]
            else:
                continue
            forbidden_imports.extend(
                f"{path.relative_to(_REPOSITORY_ROOT)}:{module}"
                for module in imported_modules
                if module in FORBIDDEN_RUNTIME_IMPORTS
            )

    assert not forbidden_imports, f"runtime imports GUI or bridge modules: {forbidden_imports}"
