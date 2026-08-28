"""Default-closed projection for typed safe-read primitives."""

from __future__ import annotations

import ipaddress
from pathlib import Path
from uuid import UUID, uuid4

from endpoint_server.config import Settings
from endpoint_server.gateway.connection_registry import GatewayConnection
from endpoint_server.operations.capabilities import project_available_capabilities


def _settings(*, enabled: bool) -> Settings:
    return Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        public_base_url="https://endpoint.sosnadmin.local",
        session_secret=b"session-secret",
        service_token_pepper=b"service-pepper",
        device_token_pepper=b"device-pepper",
        allowed_agent_cidrs=(ipaddress.ip_network("127.0.0.0/8"),),
        allowed_admin_cidrs=(ipaddress.ip_network("127.0.0.0/8"),),
        artifact_root=Path("artifacts"),
        endpoint_read_only_primitives_enabled=enabled,
        endpoint_network_probe_allowed_cidrs=(ipaddress.ip_network("10.20.0.0/16"),),
    )


def _connection(capabilities: frozenset[str]) -> GatewayConnection:
    return GatewayConnection(
        device_id=UUID("00000000-0000-4000-8000-000000000831"),
        session_id=uuid4(),
        websocket=object(),
        agent_version="3.2.29",
        platform="linux_amd64",
        effective_capabilities=capabilities,
    )


def test_safe_read_primitives_remain_hidden_until_enabled_and_reported() -> None:
    all_capabilities = frozenset(
        {"route.get", "adapter.list", "system.service_status"}
    )
    disabled = project_available_capabilities(_settings(enabled=False), _connection(all_capabilities))
    enabled = project_available_capabilities(_settings(enabled=True), _connection(all_capabilities))
    not_reported = project_available_capabilities(_settings(enabled=True), _connection(frozenset()))

    assert {item["capability"] for item in disabled} == {"context.diagnostic.collect"}
    assert {item["capability"] for item in not_reported} == {"context.diagnostic.collect"}
    assert {item["capability"] for item in enabled} == {
        "context.diagnostic.collect",
        "route.get",
        "adapter.list",
        "system.service_status",
    }
    by_name = {item["capability"]: item for item in enabled}
    assert by_name["route.get"]["parameter_schema_version"] == "route_get_parameters_v1"
    assert by_name["adapter.list"]["parameter_schema_version"] == "adapter_list_parameters_v1"
    assert by_name["system.service_status"]["parameter_schema_version"] == "system_service_status_parameters_v1"
