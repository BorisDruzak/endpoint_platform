"""Architecture guards for Endpoint Platform's agent-control boundary."""

from __future__ import annotations

import ast
import sys
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

_FORBIDDEN_RUNTIME_IMPORT_PREFIXES = FORBIDDEN_RUNTIME_IMPORTS | {"helpdesk"}

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
            if decorator.func.attr not in _ROUTE_METHODS:
                continue
            route = decorator.args[0] if decorator.args else _keyword_value(decorator, "path")
            if isinstance(route, ast.Constant) and isinstance(route.value, str):
                paths.append(route.value)

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if (_call_name(node.func) or "").split(".")[-1] == "APIRouter":
            prefix = node.args[0] if node.args else _keyword_value(node, "prefix")
        elif isinstance(node.func, ast.Attribute) and node.func.attr == "include_router":
            prefix = _keyword_value(node, "prefix")
        else:
            continue
        if isinstance(prefix, ast.Constant) and isinstance(prefix.value, str):
            paths.append(prefix.value)
    return paths


def _keyword_value(call: ast.Call, name: str) -> ast.expr | None:
    return next((keyword.value for keyword in call.keywords if keyword.arg == name), None)


def _call_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else None
    return None


def _import_aliases(tree: ast.AST) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                aliases[alias.asname or alias.name.split(".")[0]] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return aliases


def _expression_name(node: ast.expr, aliases: dict[str, str]) -> str | None:
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        parent = _expression_name(node.value, aliases)
        return f"{parent}.{node.attr}" if parent else None
    if isinstance(node, ast.Call):
        return _expression_name(node.func, aliases)
    return None


def _normalize_outbound_receiver(receiver: str) -> str:
    if receiver.startswith("httpx."):
        return "httpx"
    if receiver.startswith("requests."):
        return "requests"
    return receiver


def _outbound_calls(tree: ast.AST) -> list[tuple[str, str]]:
    aliases = _import_aliases(tree)
    calls: list[tuple[str, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        call_name = _expression_name(node.func, aliases)
        if call_name is None or "." not in call_name:
            continue
        receiver, method = call_name.rsplit(".", maxsplit=1)
        call = (_normalize_outbound_receiver(receiver), method)
        if call in _FORBIDDEN_OUTBOUND_CALLS:
            calls.append(call)
    return calls


def _forbidden_runtime_imports(tree: ast.AST) -> list[str]:
    imported_modules: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_modules.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_modules.append(node.module)
    return [
        module
        for module in imported_modules
        if any(
            module == forbidden or module.startswith(f"{forbidden}.")
            for forbidden in _FORBIDDEN_RUNTIME_IMPORT_PREFIXES
        )
    ]


@pytest.mark.parametrize(
    ("source", "expected_paths"),
    [
        (
            '@router.get(path="/relay")\ndef relay() -> None:\n    pass\n',
            ["/relay"],
        ),
        ('router = APIRouter(prefix="/proxy")\n', ["/proxy"]),
        ('router = fastapi.APIRouter(prefix="/forward")\n', ["/forward"]),
        ('app.include_router(router, prefix="/invoke-service")\n', ["/invoke-service"]),
    ],
)
def test_route_paths_detect_keyword_routes_and_router_prefixes(
    source: str, expected_paths: list[str]
) -> None:
    """Keyword paths and router prefixes must be subject to the relay-route ban."""
    assert _route_paths(ast.parse(source)) == expected_paths


@pytest.mark.parametrize(
    ("source", "expected_call"),
    [
        ('import httpx as client\nclient.get("https://example.test")\n', ("httpx", "get")),
        ('from urllib import request\nrequest.urlopen("https://example.test")\n', ("urllib.request", "urlopen")),
        ('import httpx\nhttpx.Client().get("https://example.test")\n', ("httpx", "get")),
        ('from httpx import get\nget("https://example.test")\n', ("httpx", "get")),
    ],
)
def test_outbound_calls_resolve_aliases_and_client_instances(
    source: str, expected_call: tuple[str, str]
) -> None:
    """Aliasing or a client instance must not bypass the outbound URL-execution ban."""
    assert _outbound_calls(ast.parse(source)) == [expected_call]


@pytest.mark.parametrize(
    "source",
    [
        "from pc_agent.ui_gui.main import run_gui\n",
        "import pc_agent.ui_bridge.models\n",
        "import helpdesk\n",
    ],
)
def test_future_runtime_guard_rejects_gui_bridge_and_helpdesk_submodules(
    source: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Headless runtime imports must reject GUI, bridge, and Helpdesk dependencies."""
    runtime_root = tmp_path / "pc_agent" / "runtime"
    runtime_root.mkdir(parents=True)
    (runtime_root / "forbidden_import.py").write_text(source, encoding="utf-8")
    module = sys.modules[__name__]
    monkeypatch.setattr(module, "_REPOSITORY_ROOT", tmp_path)
    monkeypatch.setattr(module, "_RUNTIME_ROOT", runtime_root)

    with pytest.raises(AssertionError, match="runtime imports GUI, bridge, or Helpdesk modules"):
        test_future_runtime_package_is_headless()


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
        forbidden_imports.extend(
            f"{path.relative_to(_REPOSITORY_ROOT)}:{module}"
            for module in _forbidden_runtime_imports(tree)
        )

    assert not forbidden_imports, (
        f"runtime imports GUI, bridge, or Helpdesk modules: {forbidden_imports}"
    )
