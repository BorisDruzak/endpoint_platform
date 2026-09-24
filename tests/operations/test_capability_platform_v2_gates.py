"""Server policy and typed operation projection for new capabilities."""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

from endpoint_contracts.capabilities import MODULE_CAPABILITY_REGISTRY
from endpoint_contracts.modules import ModuleOperationStepV1
from endpoint_server.operations.capabilities import compatible_module_capabilities, module_capability_is_compatible, module_capability_incompatibility_reason


def test_system_and_process_require_new_group_flags_and_agent_version() -> None:
    settings = SimpleNamespace(
        endpoint_system_primitives_enabled=False,
        endpoint_process_primitives_enabled=False,
    )
    system = MODULE_CAPABILITY_REGISTRY["system.resource_snapshot"]
    process = MODULE_CAPABILITY_REGISTRY["process.find"]
    assert not module_capability_is_compatible(settings, system, agent_version="3.2.67", platform="windows_amd64")
    settings.endpoint_system_primitives_enabled = True
    assert not module_capability_is_compatible(settings, system, agent_version="3.2.66", platform="windows_amd64")
    assert module_capability_is_compatible(settings, system, agent_version="3.2.67", platform="windows_amd64")
    assert not module_capability_is_compatible(settings, process, agent_version="3.2.67", platform="windows_amd64")
    settings.endpoint_process_primitives_enabled = True
    assert module_capability_is_compatible(settings, process, agent_version="3.2.67", platform="linux_amd64")


def test_incompatibility_reason_identifies_old_agent_before_dispatch() -> None:
    settings = SimpleNamespace(endpoint_system_primitives_enabled=True)
    old = SimpleNamespace(platform="windows_amd64", agent_version="3.2.66", effective_capabilities=frozenset())
    capability = MODULE_CAPABILITY_REGISTRY["system.resource_snapshot"]
    assert module_capability_incompatibility_reason(settings, None, capability) == "Устройство не в сети"
    assert module_capability_incompatibility_reason(settings, old, capability) == "Требуется Agent ≥ 3.2.67"
    old.effective_capabilities = frozenset({"system.resource_snapshot"})
    assert "system.resource_snapshot" not in compatible_module_capabilities(settings, old)
    old.agent_version = "3.2.67"
    old.effective_capabilities = frozenset()
    assert module_capability_incompatibility_reason(settings, old, capability) == "Agent не объявил возможность system.resource_snapshot"


def test_module_step_accepts_typed_system_result() -> None:
    step = ModuleOperationStepV1.model_validate({
        "sequence": 0,
        "capability": "system.resource_snapshot",
        "status": "succeeded",
        "safe_result": {
            "schema_version": "system_resource_snapshot_result_v1",
            "uptime_seconds": 100,
            "cpu_percent": 5.0,
            "memory_total_bytes": 1024,
            "memory_available_bytes": 512,
            "system_drive_free_bytes": 2048,
            "status": "succeeded",
            "collected_at": datetime.now(UTC).isoformat(),
        },
    })
    assert step.safe_result.schema_version == "system_resource_snapshot_result_v1"
