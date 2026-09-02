"""Availability projection for opt-in typed network primitives."""

from __future__ import annotations

import ipaddress
from pathlib import Path
from uuid import UUID, uuid4

from endpoint_server.config import Settings
from endpoint_server.gateway.connection_registry import GatewayConnection
from endpoint_server.operations.capabilities import project_available_capabilities


def _settings(*, enabled: bool, allowed: bool = True) -> Settings:
    return Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        public_base_url="https://endpoint.sosnadmin.local",
        session_secret=b"session-secret",
        service_token_pepper=b"service-pepper",
        device_token_pepper=b"device-pepper",
        allowed_agent_cidrs=(ipaddress.ip_network("127.0.0.0/8"),),
        allowed_admin_cidrs=(ipaddress.ip_network("127.0.0.0/8"),),
        artifact_root=Path("artifacts"),
        endpoint_operations_api_enabled=True,
        endpoint_network_primitives_enabled=enabled,
        endpoint_network_probe_allowed_cidrs=(
            (ipaddress.ip_network("10.20.0.0/16"),) if allowed else ()
        ),
    )


def _connection(
    *,
    version: str = "3.2.27",
    platform: str = "linux_amd64",
    capabilities: frozenset[str] = frozenset({"network.ping"}),
) -> GatewayConnection:
    return GatewayConnection(
        device_id=UUID("00000000-0000-4000-8000-000000000601"),
        session_id=uuid4(),
        websocket=object(),
        agent_version=version,
        platform=platform,
        effective_capabilities=capabilities,
    )


def test_network_capability_requires_full_opt_in_and_matching_agent() -> None:
    baseline = project_available_capabilities(_settings(enabled=False), _connection())
    no_allowlist = project_available_capabilities(
        _settings(enabled=True, allowed=False), _connection()
    )
    too_old = project_available_capabilities(
        _settings(enabled=True), _connection(version="3.2.26")
    )
    unsupported_platform = project_available_capabilities(
        _settings(enabled=True), _connection(platform="other")
    )
    not_reported = project_available_capabilities(
        _settings(enabled=True), _connection(capabilities=frozenset())
    )
    enabled = project_available_capabilities(_settings(enabled=True), _connection())

    assert [item["capability"] for item in baseline] == [
        "context.diagnostic.collect"
    ]
    assert no_allowlist == baseline
    assert too_old == baseline
    assert unsupported_platform == baseline
    assert not_reported == baseline
    assert enabled == [
        {
            "capability": "context.diagnostic.collect",
            "available": True,
            "transport": "gateway_wss",
            "risk": "read_only",
            "consent_required": False,
            "parameter_schema_version": "diagnostic_collection_parameters_v1",
        },
        {
            "capability": "network.ping",
            "available": True,
            "transport": "gateway_wss",
            "risk": "safe_read",
            "consent_required": False,
            "parameter_schema_version": "network_ping_parameters_v1",
        },
    ]
