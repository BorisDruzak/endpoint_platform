"""Public contract for the closed Endpoint module-capability catalog."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

def test_parameter_descriptor_is_exported_from_the_public_contract_package() -> None:
    """Consumers use the stable contract package, not a private registry path."""
    from endpoint_contracts import EndpointCapabilityParameterDescriptorV1

    assert EndpointCapabilityParameterDescriptorV1.__name__ == "EndpointCapabilityParameterDescriptorV1"


@pytest.mark.parametrize(
    "override",
    [
        {"secret": True},
        {"required": "true"},
        {"command": "powershell -Command whoami"},
    ],
)
def test_parameter_descriptor_rejects_secret_or_execution_metadata(
    override: dict[str, object],
) -> None:
    """Catalog descriptors are declarative constraints, never executable inputs."""
    from endpoint_contracts import EndpointCapabilityParameterDescriptorV1

    payload: dict[str, object] = {
        "name": "service_key",
        "value_type": "enum",
        "required": True,
        "allowed_sources": ["literal"],
        "enum_values": ["endpoint_agent", "endpoint_agent_updater"],
        "minimum": None,
        "maximum": None,
        "default_literal": None,
        "secret": False,
    }
    payload.update(override)

    with pytest.raises(ValidationError):
        EndpointCapabilityParameterDescriptorV1.model_validate(payload)


def test_parameter_descriptor_requires_every_public_shape_field() -> None:
    """Consumers can rely on nullable fields being present rather than inferred."""
    from endpoint_contracts import EndpointCapabilityParameterDescriptorV1

    payload: dict[str, object] = {
        "name": "target",
        "value_type": "string",
        "required": True,
        "allowed_sources": ["input", "literal"],
        "enum_values": None,
        "minimum": None,
        "maximum": None,
        "default_literal": None,
        "secret": False,
    }
    payload.pop("default_literal")

    with pytest.raises(ValidationError):
        EndpointCapabilityParameterDescriptorV1.model_validate(payload)


def _parameter(
    name: str,
    value_type: str,
    allowed_sources: list[str],
    *,
    enum_values: list[str] | None = None,
    minimum: int | None = None,
    maximum: int | None = None,
) -> dict[str, object]:
    return {
        "name": name,
        "value_type": value_type,
        "required": True,
        "allowed_sources": allowed_sources,
        "enum_values": enum_values,
        "minimum": minimum,
        "maximum": maximum,
        "default_literal": None,
        "secret": False,
    }


def test_module_capability_catalog_publishes_closed_authoring_descriptors() -> None:
    """Workbench clients receive every bounded recipe input without a local catalog."""
    from endpoint_contracts.capabilities import module_capability_catalog

    catalog = module_capability_catalog().model_dump(mode="json")

    assert catalog["schema_version"] == "endpoint_module_capability_catalog_v1"
    items = catalog["items"]
    assert [item["capability"] for item in items] == [
        "dns.resolve",
        "network.ping",
        "tcp.connect",
        "route.get",
        "adapter.list",
        "system.service_status",
    ]
    assert [item["parameters"] for item in items] == [
        [
            _parameter("target", "string", ["input", "literal"]),
            _parameter(
                "family",
                "enum",
                ["input", "literal"],
                enum_values=["any", "ipv4", "ipv6"],
            ),
        ],
        [
            _parameter("target", "string", ["input", "literal"]),
            _parameter("count", "integer", ["input", "literal"], minimum=1, maximum=5),
            _parameter(
                "timeout_ms", "integer", ["input", "literal"], minimum=100, maximum=5000
            ),
        ],
        [
            _parameter("target", "string", ["input", "literal"]),
            _parameter("port", "integer", ["input", "literal"], minimum=1, maximum=65535),
            _parameter(
                "timeout_ms", "integer", ["input", "literal"], minimum=100, maximum=10000
            ),
        ],
        [
            _parameter("target", "string", ["input", "literal"]),
            _parameter("port", "integer", ["input", "literal"], minimum=1, maximum=65535),
            _parameter(
                "family",
                "enum",
                ["input", "literal"],
                enum_values=["any", "ipv4", "ipv6"],
            ),
            _parameter(
                "timeout_ms", "integer", ["input", "literal"], minimum=100, maximum=5000
            ),
        ],
        [],
        [
            _parameter(
                "service_key",
                "enum",
                ["literal"],
                enum_values=["endpoint_agent", "endpoint_agent_updater"],
            )
        ],
    ]
    expected_item_fields = {
        "capability",
        "parameter_schema_version",
        "result_schema_version",
        "platforms",
        "minimum_agent_version",
        "risk",
        "consent_required",
        "feature_flag",
        "policy",
        "parameters",
    }
    descriptor_fields = {
        "name",
        "value_type",
        "required",
        "allowed_sources",
        "enum_values",
        "minimum",
        "maximum",
        "default_literal",
        "secret",
    }
    assert all(set(item) == expected_item_fields for item in items)
    assert all(
        set(parameter) == descriptor_fields
        for item in items
        for parameter in item["parameters"]
    )
    assert not {
        "command",
        "shell",
        "powershell",
        "python",
        "executable",
        "path",
        "url",
        "service_name",
    }.intersection(str(catalog))
