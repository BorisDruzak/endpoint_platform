"""Executable catalog cannot drift from Gateway, Agent and persistence."""

from __future__ import annotations

import importlib
import ast
import re
from pathlib import Path
from typing import get_args

from endpoint_contracts.capabilities import MODULE_CAPABILITY_REGISTRY, ModuleCapabilityNameV1
from endpoint_contracts.modules import ModuleStepSafeResultV1
from endpoint_server.db.models.operations import MODULE_OPERATION_STEP_CAPABILITIES, _MODULE_STEP_CAPABILITY_CHECK
from endpoint_server.gateway.ws_routes import _SUPPORTED_CAPABILITIES
from pc_agent.runtime.command_executor import BUILTIN_ENDPOINT_CAPABILITIES
from pc_agent.primitives.network.command_execution import _NETWORK_COMMANDS
from pc_agent.primitives.read_only.command_execution import _READ_ONLY_COMMANDS
from pc_agent.transport.protocol import compatibility_agent_hello


def test_executable_registry_matches_runtime_and_model_check() -> None:
    catalog = set(MODULE_CAPABILITY_REGISTRY)
    assert catalog == set(MODULE_OPERATION_STEP_CAPABILITIES)
    assert catalog == set(re.findall(r"'([^']+)'", _MODULE_STEP_CAPABILITY_CHECK))
    assert catalog <= _SUPPORTED_CAPABILITIES
    assert catalog <= set(BUILTIN_ENDPOINT_CAPABILITIES)
    command_bindings = {**_NETWORK_COMMANDS, **_READ_ONLY_COMMANDS}
    assert catalog == set(command_bindings)
    for capability, (_, parameter_type, _) in command_bindings.items():
        assert parameter_type is MODULE_CAPABILITY_REGISTRY[capability].parameter_model
    for platform in ("linux_amd64", "windows_amd64"):
        advertised = set(compatibility_agent_hello(platform=platform).capabilities)
        expected = {name for name, descriptor in MODULE_CAPABILITY_REGISTRY.items() if platform in descriptor.metadata.platforms}
        assert expected <= advertised
        assert not (catalog - expected) & advertised


def test_latest_migration_installs_every_executable_capability() -> None:
    migration = importlib.import_module("endpoint_server.db.migrations.versions.0028_capability_platform_v2")
    assert set(migration.CAPABILITY_NAMES) == set(MODULE_CAPABILITY_REGISTRY)


def test_manual_literal_and_typed_result_union_cover_registry() -> None:
    assert set(get_args(ModuleCapabilityNameV1)) == set(MODULE_CAPABILITY_REGISTRY)
    result_types = set(get_args(get_args(ModuleStepSafeResultV1)[0]))
    assert result_types == {descriptor.result_model for descriptor in MODULE_CAPABILITY_REGISTRY.values()}


def test_new_platform_handlers_contain_no_generic_execution_surface() -> None:
    root = Path(__file__).resolve().parents[2] / "pc_agent" / "primitives"
    for group in ("system_process", "service_printer", "software", "filesystem", "eventlog"):
        source = (root / group / "handlers.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in {"eval", "exec", "__import__"}
            if isinstance(node, ast.keyword) and node.arg == "shell":
                assert node.value is not None and isinstance(node.value, ast.Constant) and node.value.value is False
