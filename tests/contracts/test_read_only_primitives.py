"""Approved bounded contracts for Endpoint read-only primitives."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from endpoint_contracts.read_only_primitives import (
    AdapterListParametersV1,
    AdapterListResultV1,
    AdapterSummaryItemV1,
    RouteGetParametersV1,
    RouteGetResultV1,
    ServiceStatusParametersV1,
    ServiceStatusResultV1,
)


NOW = datetime(2026, 8, 28, tzinfo=UTC)


def test_route_get_contract_requires_a_bounded_route_selection() -> None:
    parameters = RouteGetParametersV1.model_validate(
        {
            "schema_version": "route_get_parameters_v1",
            "target": "router.example.test",
            "port": 443,
            "family": "ipv4",
            "timeout_ms": 1000,
        }
    )
    result = RouteGetResultV1.model_validate(
        {
            "schema_version": "route_get_result_v1",
            "target": "router.example.test",
            "resolved_ip": "10.20.0.15",
            "family": "ipv4",
            "port": 443,
            "source_ip": "10.20.0.20",
            "interface_name": "eth0",
            "strategy": "udp_socket_inference",
            "status": "succeeded",
            "error_code": None,
            "collected_at": NOW,
        }
    )

    assert parameters.timeout_ms == 1000
    assert result.strategy == "udp_socket_inference"
    with pytest.raises(ValidationError):
        RouteGetParametersV1.model_validate(
            {
                "schema_version": "route_get_parameters_v1",
                "target": "https://example.test/run",
                "port": 443,
                "family": "any",
                "timeout_ms": 1000,
            }
        )
    with pytest.raises(ValidationError):
        RouteGetParametersV1.model_validate(
            {
                "schema_version": "route_get_parameters_v1",
                "target": "router.example.test",
                "port": 0,
                "family": "ipv4",
                "timeout_ms": 99,
            }
        )


def test_adapter_list_contract_bounds_privacy_safe_adapter_facts() -> None:
    item = AdapterSummaryItemV1.model_validate(
        {
            "name": "Ethernet 2",
            "state": "up",
            "kind": "ethernet",
            "primary": True,
            "ipv4_addresses": ["10.20.0.20"],
            "ipv6_addresses": ["2001:db8::20"],
            "mtu": 1500,
            "speed_mbps": 1000,
        }
    )
    result = AdapterListResultV1.model_validate(
        {
            "schema_version": "adapter_list_result_v1",
            "adapters": [item.model_dump()],
            "adapter_count": 1,
            "up_count": 1,
            "status": "succeeded",
            "error_code": None,
            "collected_at": NOW,
        }
    )

    AdapterListParametersV1.model_validate({"schema_version": "adapter_list_parameters_v1"})
    assert result.adapters[0].ipv6_addresses == ["2001:db8::20"]
    with pytest.raises(ValidationError):
        AdapterSummaryItemV1.model_validate(
            {
                **item.model_dump(),
                "mac_address": "00:11:22:33:44:55",
            }
        )
    with pytest.raises(ValidationError):
        AdapterListResultV1.model_validate(
            {
                "schema_version": "adapter_list_result_v1",
                "adapters": [item.model_dump()] * 33,
                "adapter_count": 33,
                "up_count": 33,
                "status": "succeeded",
                "error_code": None,
                "collected_at": NOW,
            }
        )


def test_service_status_contract_accepts_only_logical_keys_and_safe_state() -> None:
    result = ServiceStatusResultV1.model_validate(
        {
            "schema_version": "service_status_result_v1",
            "service_key": "endpoint_agent",
            "installed": True,
            "state": "running",
            "start_mode": "automatic",
            "status": "succeeded",
            "error_code": None,
            "collected_at": NOW,
        }
    )

    assert result.service_key == "endpoint_agent"
    with pytest.raises(ValidationError):
        ServiceStatusParametersV1.model_validate(
            {
                "schema_version": "service_status_parameters_v1",
                "service_name": "sshd.service",
            }
        )


def test_failed_route_results_never_expose_a_selected_address() -> None:
    with pytest.raises(ValidationError):
        RouteGetResultV1.model_validate(
            {
                "schema_version": "route_get_result_v1",
                "target": "router.example.test",
                "resolved_ip": "10.20.0.15",
                "family": "ipv4",
                "port": 443,
                "source_ip": "10.20.0.20",
                "strategy": "udp_socket_inference",
                "status": "failed",
                "error_code": "network_target_denied",
                "collected_at": NOW,
            }
        )
    with pytest.raises(ValidationError):
        ServiceStatusParametersV1.model_validate(
            {
                "schema_version": "service_status_parameters_v1",
                "service_key": "sshd",
            }
        )
