"""Release-surface guards for the Endpoint Platform headless agent.

Legacy Helpdesk modules intentionally remain in the source tree.  These tests
therefore start at the Linux/Windows release entrypoints and package manifests,
then follow only imports that those artifacts can include.
"""

from __future__ import annotations

import asyncio
import ast
from collections import deque
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from pathlib import Path
import sys
from uuid import UUID

import pytest

from endpoint_contracts.commands import AgentCommandV1
from pc_agent.runtime.command_executor import CommandExecutor


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
_WINDOWS_INITIAL_RUNTIME_MANIFESTS = tuple(
    sorted((REPOSITORY_ROOT / "packaging" / "windows").glob("initial-runtime*.json"))
)

RELEASED_PATHS = (
    REPOSITORY_ROOT / "pc_agent" / "runtime",
    REPOSITORY_ROOT / "pc_agent" / "transport",
    REPOSITORY_ROOT / "pc_agent" / "pyinstaller_endpoint_core_linux.spec",
    REPOSITORY_ROOT / "pc_agent" / "pyinstaller_launcher_linux.spec",
    REPOSITORY_ROOT / "pc_agent" / "pyinstaller_endpoint_core_windows.spec",
    REPOSITORY_ROOT / "pc_agent" / "pyinstaller_launcher_win.spec",
    REPOSITORY_ROOT / "pc_agent" / "pyinstaller_windows_service_launcher.spec",
    REPOSITORY_ROOT / "pc_agent" / "pyinstaller_windows_provision.spec",
    REPOSITORY_ROOT / "pc_agent" / "platform" / "windows" / "service_launcher.py",
    REPOSITORY_ROOT / "pc_agent" / "platform" / "windows" / "provision_entry.py",
    REPOSITORY_ROOT / "packaging" / "alt" / "build-rpm.sh",
    REPOSITORY_ROOT / "packaging" / "alt" / "endpoint-agent.spec",
    REPOSITORY_ROOT / "packaging" / "alt" / "SOURCES" / "endpoint-agent.service",
    REPOSITORY_ROOT / "packaging" / "alt" / "SOURCES" / "endpoint-agent.tmpfiles",
    REPOSITORY_ROOT / "packaging" / "alt" / "SOURCES" / "endpoint-agent.logrotate",
    REPOSITORY_ROOT / "packaging" / "alt" / "SOURCES" / "start-endpoint-agent.py",
    REPOSITORY_ROOT / "packaging" / "alt" / "SOURCES" / "check-start-prerequisites.py",
    REPOSITORY_ROOT / "deploy" / "agent" / "alt" / "endpoint-agent-update.service",
    REPOSITORY_ROOT / "deploy" / "agent" / "alt" / "endpoint-agent-update.path",
    REPOSITORY_ROOT / "deploy" / "agent" / "alt" / "apply-pending-alt-update.sh",
    REPOSITORY_ROOT / "packaging" / "windows" / "build-msi.ps1",
    REPOSITORY_ROOT / "packaging" / "windows" / "wix" / "Services.wxs",
) + _WINDOWS_INITIAL_RUNTIME_MANIFESTS

_SPEC_ENTRYPOINTS = {
    "pc_agent/pyinstaller_endpoint_core_linux.spec": ("pc_agent.runtime.main",),
    "pc_agent/pyinstaller_endpoint_core_windows.spec": ("pc_agent.runtime.main",),
    "pc_agent/pyinstaller_windows_service_launcher.spec": (
        "pc_agent.platform.windows.service_launcher",
    ),
    "pc_agent/pyinstaller_launcher_linux.spec": ("pc_agent.launcher.launcher_main",),
    "pc_agent/pyinstaller_launcher_win.spec": ("pc_agent.launcher.launcher_main",),
    "pc_agent/pyinstaller_windows_provision.spec": (
        "pc_agent.platform.windows.provision_entry",
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
_FORBIDDEN_TEXT_MARKERS = frozenset(
    (*_FORBIDDEN_MODULE_PREFIXES, *_FORBIDDEN_LEGACY_NAMES, "pyside6", "qasync")
)
_RELEASED_ARTIFACT_PATHS = tuple(path for path in RELEASED_PATHS if path.is_file())


@pytest.mark.parametrize(
    "source",
    _RELEASED_ARTIFACT_PATHS,
    ids=lambda path: path.relative_to(REPOSITORY_ROOT).as_posix(),
)
def test_every_shipped_package_artifact_rejects_a_forbidden_marker(
    source: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Each shipped artifact must be scanned instead of bypassing the release guard."""
    relative = source.relative_to(REPOSITORY_ROOT)
    marker = tmp_path / relative
    marker.parent.mkdir(parents=True)
    source_text = source.read_text(encoding="utf-8-sig")
    if _is_pyinstaller_spec(source):
        source_text = source_text.replace(
            "hiddenimports=[", 'hiddenimports=["TicketApiClient",', 1
        )
    else:
        source_text += "\nTicketApiClient\n"
    marker.write_text(source_text, encoding="utf-8")
    monkeypatch.setattr(sys.modules[__name__], "REPOSITORY_ROOT", tmp_path)

    assert any(
        value.casefold() == "ticketapiclient"
        for _path, value in _release_package_references((marker,))
    )


def _python_files(path: Path) -> tuple[Path, ...]:
    if path.is_dir():
        return tuple(sorted(path.rglob("*.py")))
    return (path,) if path.suffix == ".py" or _is_pyinstaller_spec(path) else ()


def _is_pyinstaller_spec(path: Path) -> bool:
    try:
        relative = path.relative_to(REPOSITORY_ROOT).as_posix()
    except ValueError:
        return False
    return relative in _SPEC_ENTRYPOINTS


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


def _text_references(path: Path) -> set[str]:
    text = path.read_text(encoding="utf-8-sig", errors="replace").casefold()
    return {marker for marker in _FORBIDDEN_TEXT_MARKERS if marker in text}


def _is_forbidden(reference: str) -> bool:
    normalized = reference.casefold()
    return any(
        normalized == prefix or normalized.startswith(f"{prefix}.")
        for prefix in _FORBIDDEN_MODULE_PREFIXES
    ) or any(name in normalized for name in _FORBIDDEN_LEGACY_NAMES)


def _release_package_references(paths: Iterable[Path]) -> set[tuple[Path, str]]:
    references: set[tuple[Path, str]] = set()
    for path in paths:
        if path.is_dir():
            continue
        if _is_pyinstaller_spec(path):
            references.update((path, value) for value in _spec_hiddenimports(path))
            continue
        references.update((path, value) for value in _text_references(path))
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
    assert "pyinstaller_launcher_win.spec" in msi_builder
    assert "pyinstaller_windows_service_launcher.spec" in msi_builder
    assert "pyinstaller_agent_linux.spec" not in rpm_builder
    assert "pyinstaller_agent_win" not in msi_builder
    assert "ws_agent" not in rpm_builder
    assert "ws_agent" not in msi_builder
    assert "endpoint-agent.service" in rpm_spec
    assert "ExecStart=/usr/lib/endpoint-agent/start-endpoint-agent" in systemd_unit
    assert 'Name="EndpointAgent"' in wix_services
    assert "endpoint-agent-service.exe" in wix_services


def test_windows_msi_launcher_spec_is_a_guarded_release_root() -> None:
    """The launcher built by the MSI must participate in release-surface scanning."""
    assert (
        REPOSITORY_ROOT / "pc_agent" / "pyinstaller_launcher_win.spec"
    ) in RELEASED_PATHS


class _DiagnosticProbe:
    platform_name = "linux"

    def run(self, command: tuple[str, ...], _timeout: float, _limit: int) -> str:
        if command[0] == "ps":
            return "101 R\n"
        return "Authorization: Bearer release-guard-secret"


def _diagnostic_command() -> AgentCommandV1:
    created_at = datetime(2026, 8, 18, tzinfo=UTC)
    return AgentCommandV1(
        schema_version="agent_command_v1",
        command_id=UUID("00000000-0000-4000-8000-000000000501"),
        device_id=UUID("00000000-0000-4000-8000-000000000502"),
        capability="context.diagnostic.collect",
        parameters={"reason": "release guard"},
        requested_by_service="architecture-test",
        idempotency_key="release-guard-diagnostic-501",
        created_at=created_at,
        deadline_at=created_at + timedelta(minutes=5),
    )


def test_released_command_executor_runs_a_bounded_typed_diagnostic() -> None:
    """The released headless command path must execute the typed diagnostic contract."""

    async def execute() -> object:
        executor = CommandExecutor(probe_factory=_DiagnosticProbe)
        await executor.start()
        try:
            return await executor.execute(_diagnostic_command())
        finally:
            await executor.stop()

    result = asyncio.run(execute())

    assert result.status == "succeeded"
    assert result.result_items[0]["profile"] == "diagnostic_v1"
    assert result.result_items[0]["sections"]["reason"] == "release guard"
    assert result.result_items[0]["sections"]["log_excerpt"] == "Authorization: Bearer <redacted>"


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
