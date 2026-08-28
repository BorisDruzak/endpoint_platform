"""Handler tests for fixed read-only Endpoint diagnostics."""

from __future__ import annotations

from datetime import UTC, datetime

from endpoint_contracts import AgentCommandV1
from endpoint_contracts.read_only_primitives import (
    AdapterListParametersV1,
    RouteGetParametersV1,
    SystemServiceStatusParametersV1,
)
from pc_agent.primitives.read_only.command_execution import execute_read_only_agent_command
from pc_agent.primitives.read_only.handlers import adapter_list, route_get, system_service_status
from pc_agent.primitives.network.policy import AgentNetworkProbePolicy


NOW = datetime(2026, 8, 28, tzinfo=UTC)


def _command(capability: str, parameters: dict[str, object]) -> AgentCommandV1:
    return AgentCommandV1.model_validate(
        {
            "schema_version": "agent_command_v1",
            "command_id": "00000000-0000-4000-8000-000000000801",
            "device_id": "00000000-0000-4000-8000-000000000802",
            "capability": capability,
            "parameters": parameters,
            "requested_by_service": "endpoint-platform",
            "idempotency_key": "read-only-primitive-801",
            "created_at": "2026-08-28T00:00:00Z",
            "deadline_at": "2026-08-28T00:05:00Z",
        }
    )


def test_route_get_returns_only_selected_local_route_values() -> None:
    result = route_get(
        RouteGetParametersV1(
            schema_version="route_get_parameters_v1", target="api.example.test"
        ),
        route_source=lambda _target: ("ipv4", "192.0.2.10"),
        collected_at=NOW,
    )

    assert result.model_dump(mode="json") == {
        "schema_version": "route_get_result_v1",
        "target": "api.example.test",
        "family": "ipv4",
        "local_address": "192.0.2.10",
        "status": "succeeded",
        "error_code": None,
        "collected_at": "2026-08-28T00:00:00Z",
    }


def test_adapter_list_bounds_and_normalizes_interface_values() -> None:
    result = adapter_list(
        AdapterListParametersV1(schema_version="adapter_list_parameters_v1"),
        list_interfaces=lambda: [(2, "eth0"), (1, "lo"), (3, "eth0")],
        collected_at=NOW,
    )

    assert result.adapter_count == 2
    assert [(item.index, item.name) for item in result.adapters] == [(1, "lo"), (2, "eth0")]


def test_service_status_uses_fixed_key_and_sanitizes_package_version() -> None:
    result = system_service_status(
        SystemServiceStatusParametersV1(
            schema_version="system_service_status_parameters_v1", service_key="endpoint_agent"
        ),
        platform_name="linux",
        linux_service_status=lambda _unit: "active",
        alt_package_version=lambda: "3.2.29\nignored-package-manager-output",
        collected_at=NOW,
    )

    assert result.service_key == "endpoint_agent"
    assert result.state == "active"
    assert result.package_kind == "alt_rpm"
    assert result.package_version is None
    assert "endpoint-agent.service" not in result.model_dump_json()


def test_service_status_projects_fixed_windows_service_and_msi_version() -> None:
    requested_services: list[str] = []

    def read_windows_service(service_name: str) -> str:
        requested_services.append(service_name)
        return "inactive"

    result = system_service_status(
        SystemServiceStatusParametersV1(
            schema_version="system_service_status_parameters_v1",
            service_key="endpoint_agent_updater",
        ),
        platform_name="windows",
        windows_service_status=read_windows_service,
        windows_package_version=lambda: "3.2.31",
        collected_at=NOW,
    )

    assert result.service_key == "endpoint_agent_updater"
    assert result.platform == "windows_amd64"
    assert result.state == "inactive"
    assert result.package_kind == "windows_msi"
    assert result.package_version == "3.2.31"
    assert requested_services == ["EndpointAgentUpdater"]
    assert "EndpointAgentUpdater" not in result.model_dump_json()


def test_route_command_checks_network_policy_before_route_handler() -> None:
    called = False

    def forbidden_route_handler(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError("a disallowed target reached the route handler")

    result = execute_read_only_agent_command(
        _command("route.get", {"target": "198.51.100.10"}),
        policy=AgentNetworkProbePolicy.from_values(allowed_cidrs=(), allowed_suffixes=()),
        route_handler=forbidden_route_handler,
        completed_at=NOW,
    )

    assert result.status == "failed"
    assert result.message == "network_target_policy_not_configured"
    assert called is False


def test_service_status_command_never_accepts_a_raw_service_name() -> None:
    result = execute_read_only_agent_command(
        _command("system.service_status", {"service_name": "sshd"}),
        policy=AgentNetworkProbePolicy.from_values(allowed_cidrs=(), allowed_suffixes=()),
        completed_at=NOW,
    )

    assert result.status == "failed"
    assert result.message == "read_only_capability_rejected"
