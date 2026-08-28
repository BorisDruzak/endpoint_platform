"""Closed contracts for the second Endpoint safe-read primitive set."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from endpoint_contracts.read_only_primitives import (
    AdapterListParametersV1,
    RouteGetParametersV1,
    SystemServiceStatusParametersV1,
    SystemServiceStatusResultV1,
)


def test_route_get_parameters_reject_url_and_extra_fields() -> None:
    """A route lookup is a target lookup, never a URL or an arbitrary option bag."""
    with pytest.raises(ValidationError):
        RouteGetParametersV1.model_validate(
            {"schema_version": "route_get_parameters_v1", "target": "https://example.test"}
        )
    with pytest.raises(ValidationError):
        RouteGetParametersV1.model_validate(
            {
                "schema_version": "route_get_parameters_v1",
                "target": "router.example.test",
                "command": "ip route",
            }
        )


def test_adapter_list_accepts_only_the_empty_parameter_object() -> None:
    AdapterListParametersV1.model_validate({"schema_version": "adapter_list_parameters_v1"})

    with pytest.raises(ValidationError):
        AdapterListParametersV1.model_validate(
            {
                "schema_version": "adapter_list_parameters_v1",
                "path": "/etc/network/interfaces",
            }
        )


def test_service_status_accepts_only_fixed_endpoint_service_keys() -> None:
    accepted = SystemServiceStatusParametersV1.model_validate(
        {
            "schema_version": "system_service_status_parameters_v1",
            "service_key": "endpoint_agent",
        }
    )
    assert accepted.service_key == "endpoint_agent"

    with pytest.raises(ValidationError):
        SystemServiceStatusParametersV1.model_validate(
            {
                "schema_version": "system_service_status_parameters_v1",
                "service_name": "sshd.service",
            }
        )
    with pytest.raises(ValidationError):
        SystemServiceStatusParametersV1.model_validate(
            {
                "schema_version": "system_service_status_parameters_v1",
                "service_key": "sshd",
            }
        )


def test_service_status_result_keeps_packaging_analysis_bounded() -> None:
    result = SystemServiceStatusResultV1.model_validate(
        {
            "schema_version": "system_service_status_result_v1",
            "service_key": "endpoint_agent",
            "platform": "linux_amd64",
            "state": "active",
            "package_kind": "alt_rpm",
            "package_version": "3.2.29",
            "status": "succeeded",
            "collected_at": datetime(2026, 8, 28, tzinfo=UTC),
        }
    )
    assert "endpoint-agent.service" not in result.model_dump_json()

    with pytest.raises(ValidationError):
        SystemServiceStatusResultV1.model_validate(
            {
                "schema_version": "system_service_status_result_v1",
                "service_key": "endpoint_agent",
                "platform": "linux_amd64",
                "state": "active",
                "package_kind": "alt_rpm",
                "package_version": "3.2.29; rm -rf /",
                "status": "succeeded",
                "collected_at": datetime(2026, 8, 28, tzinfo=UTC),
            }
        )
    with pytest.raises(ValidationError):
        SystemServiceStatusResultV1.model_validate(
            {
                "schema_version": "system_service_status_result_v1",
                "service_key": "endpoint_agent",
                "platform": "linux_amd64",
                "state": "active",
                "package_kind": "windows_msi",
                "package_version": "3.2.29",
                "status": "succeeded",
                "collected_at": datetime(2026, 8, 28, tzinfo=UTC),
            }
        )
