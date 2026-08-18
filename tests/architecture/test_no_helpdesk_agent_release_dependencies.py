"""Release-surface guards for the Endpoint Platform headless agent.

Legacy Helpdesk modules intentionally remain in the source tree.  These tests
therefore start at the Linux/Windows release entrypoints and package manifests,
then follow only imports that those artifacts can include.
"""

from __future__ import annotations

import ast
from collections import deque
from collections.abc import Iterable
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]

RELEASED_PATHS = (
    REPOSITORY_ROOT / "pc_agent" / "runtime",
    REPOSITORY_ROOT / "pc_agent" / "transport",
    REPOSITORY_ROOT / "pc_agent" / "pyinstaller_endpoint_core_linux.spec",
    REPOSITORY_ROOT / "pc_agent" / "pyinstaller_endpoint_core_windows.spec",
    REPOSITORY_ROOT / "pc_agent" / "pyinstaller_windows_service_launcher.spec",
    REPOSITORY_ROOT / "pc_agent" / "platform" / "windows" / "service_launcher.py",
    REPOSITORY_ROOT / "packaging" / "alt" / "build-rpm.sh",
    REPOSITORY_ROOT / "packaging" / "alt" / "endpoint-agent.spec",
    REPOSITORY_ROOT / "packaging" / "alt" / "SOURCES" / "endpoint-agent.service",
    REPOSITORY_ROOT / "packaging" / "windows" / "build-msi.ps1",
    REPOSITORY_ROOT / "packaging" / "windows" / "wix" / "Services.wxs",
)

_SPEC_ENTRYPOINTS = {
    "pc_agent/pyinstaller_endpoint_core_linux.spec": ("pc_agent.runtime.main",),
    "pc_agent/pyinstaller_endpoint_core_windows.spec": ("pc_agent.runtime.main",),
    "pc_agent/pyinstaller_windows_service_launcher.spec": (
        "pc_agent.platform.windows.service_launcher",
    ),
}
_CORE_SPECS = (
    REPOSITORY_ROOT / "pc_agent" / "pyinstaller_endpoint_core_linux.spec",
    REPOSITORY_ROOT / "pc_agent" / "pyinstaller_endpoint_core_windows.spec",
)

_FORBIDDEN_MODULE_PREFIXES = (
    "helpdesk",
    "pc_agent.auth",
    "pc_agent.core.account_session",
    "pc_agent.core.database",
    "pc_agent.core.identity",
    "pc_agent.core.job_manager",
    "pc_agent.core.orchestrator",
    "pc_agent.core.sender",
    "pc_agent.ui_bridge",
    "pc_agent.ui_gui",
    "pc_agent.ws_agent",
    "pc_agent.ws_agent_runtime_helpers",
)
_FORBIDDEN_LEGACY_NAMES = {
    "account_session",
    "browser_pairing",
    "connection_request",
    "exec_script",
    "helpdesk_api",
    "helpdesk_url",
    "machine_token",
    "run_recipe",
    "run_tool",
    "ticketapiclient",
    "ws_ticket_v3",
}
_DIAGNOSTIC_IMPORTS = {
    "pc_agent.context_profiles.command_execution",
    "pc_agent.context_profiles.probe",
    "pc_agent.context_profiles.registry",
}
_TYPED_DIAGNOSTIC_REFERENCES = {
    "endpoint_contracts.commands.AgentCommandV1",
    "endpoint_contracts.commands.AgentResultV1",
    "endpoint_contracts.context.DeviceContextDiagnosticV1",
    "pc_agent.context_profiles.diagnostic",
}
_ARBITRARY_EXECUTION_COMMANDS = {"exec_script", "run_recipe", "run_tool"}


def _python_files(path: Path) -> tuple[Path, ...]:
    if path.is_dir():
        return tuple(sorted(path.rglob("*.py")))
    return (path,) if path.suffix == ".py" or _is_pyinstaller_spec(path) else ()


def _is_pyinstaller_spec(path: Path) -> bool:
    return path.relative_to(REPOSITORY_ROOT).as_posix() in _SPEC_ENTRYPOINTS


def _module_name(path: Path) -> str | None:
    try:
        relative = path.relative_to(REPOSITORY_ROOT).with_suffix("")
    except ValueError:
        return None
    parts = relative.parts
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts) if parts else None


def _module_path(module: str) -> Path | None:
    if not module.startswith("pc_agent."):
        return None
    module_path = REPOSITORY_ROOT.joinpath(*module.split("."))
    candidates = (module_path.with_suffix(".py"), module_path / "__init__.py")
    return next((candidate for candidate in candidates if candidate.is_file()), None)


def _relative_import_base(
    node: ast.ImportFrom, current_module: str, *, is_package: bool
) -> str:
    if not node.level:
        return node.module or ""
    package = current_module.split(".")
    if not is_package:
        package = package[:-1]
    package = package[: len(package) - node.level + 1]
    if node.module:
        package.extend(node.module.split("."))
    return ".".join(package)


def _import_references(
    tree: ast.AST, current_module: str, *, is_package: bool
) -> set[str]:
    references: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            references.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            base = _relative_import_base(node, current_module, is_package=is_package)
            if base:
                references.add(base)
            references.update(
                f"{base}.{alias.name}"
                for alias in node.names
                if base and alias.name != "*"
            )
    return references


def _spec_hiddenimports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
            continue
        if node.func.id != "Analysis":
            continue
        for keyword in node.keywords:
            if keyword.arg != "hiddenimports":
                continue
            values = ast.literal_eval(keyword.value)
            return {value for value in values if isinstance(value, str)}
    raise AssertionError(f"{path.relative_to(REPOSITORY_ROOT)} has no Analysis.hiddenimports")


def _operation_references(tree: ast.AST) -> set[str]:
    references: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            references.add(node.id)
        elif isinstance(node, ast.Attribute):
            references.add(node.attr)
        elif (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and node.value.casefold() in _ARBITRARY_EXECUTION_COMMANDS | {"ws_ticket_v3"}
        ):
            references.add(node.value)
    return references


def _is_forbidden(reference: str) -> bool:
    normalized = reference.casefold()
    return any(
        normalized == prefix or normalized.startswith(f"{prefix}.")
        for prefix in _FORBIDDEN_MODULE_PREFIXES
    ) or any(name in normalized for name in _FORBIDDEN_LEGACY_NAMES)


def _release_package_references(paths: Iterable[Path]) -> set[tuple[Path, str]]:
    references: set[tuple[Path, str]] = set()
    for path in paths:
        if path.suffix != ".py" and not _is_pyinstaller_spec(path):
            continue
        if _is_pyinstaller_spec(path):
            references.update((path, value) for value in _spec_hiddenimports(path))
        elif path.suffix == ".py":
            tree = ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))
            references.update((path, value) for value in _operation_references(tree))
    return references


def _released_python_surface(paths: Iterable[Path]) -> tuple[set[Path], set[tuple[Path, str]]]:
    pending: deque[Path] = deque()
    references: set[tuple[Path, str]] = set()
    visited: set[Path] = set()

    for path in paths:
        pending.extend(_python_files(path))
        relative = path.relative_to(REPOSITORY_ROOT).as_posix()
        for module in _SPEC_ENTRYPOINTS.get(relative, ()):
            module_path = _module_path(module)
            assert module_path is not None, f"missing release entrypoint {module}"
            pending.append(module_path)
        if _is_pyinstaller_spec(path):
            for module in _spec_hiddenimports(path):
                module_path = _module_path(module)
                if module_path is not None:
                    pending.append(module_path)

    while pending:
        path = pending.popleft()
        if path in visited or path.suffix != ".py":
            continue
        visited.add(path)
        current_module = _module_name(path)
        if current_module is None:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))
        imported = _import_references(
            tree, current_module, is_package=path.name == "__init__.py"
        )
        references.update((path, value) for value in imported)
        references.update((path, value) for value in _operation_references(tree))
        for module in imported:
            imported_path = _module_path(module)
            if imported_path is not None:
                pending.append(imported_path)

    return visited, references


def scan_released_paths(paths: Iterable[Path]) -> list[str]:
    """Return forbidden names reachable from release roots and package manifests."""
    _visited, python_references = _released_python_surface(paths)
    package_references = _release_package_references(paths)
    forbidden = python_references | package_references
    return sorted(
        f"{path.relative_to(REPOSITORY_ROOT)}:{reference}"
        for path, reference in forbidden
        if _is_forbidden(reference)
    )


def test_released_surfaces_exclude_helpdesk_runtime() -> None:
    """A release root importing a legacy Ticket/UI/execution path must fail CI."""
    assert scan_released_paths(RELEASED_PATHS) == []


def test_release_packaging_uses_only_headless_entrypoints() -> None:
    """Linux RPM and Windows MSI must package the core runtime, never ws_agent."""
    rpm_builder = (REPOSITORY_ROOT / "packaging" / "alt" / "build-rpm.sh").read_text(
        encoding="utf-8"
    )
    msi_builder = (REPOSITORY_ROOT / "packaging" / "windows" / "build-msi.ps1").read_text(
        encoding="utf-8"
    )
    rpm_spec = (REPOSITORY_ROOT / "packaging" / "alt" / "endpoint-agent.spec").read_text(
        encoding="utf-8"
    )
    systemd_unit = (
        REPOSITORY_ROOT / "packaging" / "alt" / "SOURCES" / "endpoint-agent.service"
    ).read_text(encoding="utf-8")
    wix_services = (
        REPOSITORY_ROOT / "packaging" / "windows" / "wix" / "Services.wxs"
    ).read_text(encoding="utf-8")

    assert "pyinstaller_endpoint_core_linux.spec" in rpm_builder
    assert "pyinstaller_endpoint_core_windows.spec" in msi_builder
    assert "pyinstaller_windows_service_launcher.spec" in msi_builder
    assert "pyinstaller_agent_linux.spec" not in rpm_builder
    assert "pyinstaller_agent_win" not in msi_builder
    assert "ws_agent" not in rpm_builder
    assert "ws_agent" not in msi_builder
    assert "endpoint-agent.service" in rpm_spec
    assert "ExecStart=/usr/lib/endpoint-agent/start-endpoint-agent" in systemd_unit
    assert 'Name="EndpointAgent"' in wix_services
    assert "endpoint-agent-service.exe" in wix_services


def test_linux_and_windows_core_specs_include_typed_diagnostics_without_gui() -> None:
    """Both core artifacts expose the bounded typed diagnostic capability headlessly."""
    for spec in _CORE_SPECS:
        assert _DIAGNOSTIC_IMPORTS <= _spec_hiddenimports(spec)

    visited, references = _released_python_surface(_CORE_SPECS)
    visited_modules = {_module_name(path) for path in visited}
    imported_names = {reference for _path, reference in references}

    assert "pc_agent.runtime.command_executor" in visited_modules
    assert _TYPED_DIAGNOSTIC_REFERENCES <= imported_names
    assert not [
        reference
        for _path, reference in references
        if reference.startswith(("pc_agent.ui_gui", "pc_agent.ui_bridge", "pc_agent.ws_agent", "helpdesk"))
    ]
