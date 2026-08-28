"""Gateway registration tests for the closed safe-read primitive set."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from endpoint_contracts.gateway_ws import GatewayCommandV1
from pc_agent.transport.protocol import compatibility_agent_hello


def _gateway_command(capability: str, parameters: dict[str, object]) -> dict[str, object]:
    return {
        "schema_version": "agent_command_v1",
        "command_id": "00000000-0000-4000-8000-000000000821",
        "device_id": "00000000-0000-4000-8000-000000000822",
        "capability": capability,
        "parameters": parameters,
        "requested_by_service": "endpoint-platform",
        "idempotency_key": "read-only-registration-821",
        "created_at": datetime(2026, 8, 28, tzinfo=UTC),
        "deadline_at": datetime(2026, 8, 28, 0, 5, tzinfo=UTC),
    }


def test_gateway_accepts_only_the_closed_read_only_parameter_sets() -> None:
    route = GatewayCommandV1.model_validate(
        _gateway_command("route.get", {"target": "api.example.test"})
    )
    adapter = GatewayCommandV1.model_validate(_gateway_command("adapter.list", {}))
    service = GatewayCommandV1.model_validate(
        _gateway_command("system.service_status", {"service_key": "endpoint_agent"})
    )

    assert (route.capability, adapter.capability, service.capability) == (
        "route.get",
        "adapter.list",
        "system.service_status",
    )
    with pytest.raises(ValidationError):
        GatewayCommandV1.model_validate(
            _gateway_command("route.get", {"target": "https://example.test"})
        )
    with pytest.raises(ValidationError):
        GatewayCommandV1.model_validate(
            _gateway_command("system.service_status", {"service_name": "sshd.service"})
        )


def test_compatibility_hello_reports_only_fixed_read_only_capabilities() -> None:
    capabilities = compatibility_agent_hello().capabilities

    assert {"route.get", "adapter.list", "system.service_status"} <= set(capabilities)
    assert not any("shell" in capability or "exec" in capability for capability in capabilities)
