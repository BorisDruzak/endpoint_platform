"""Public contract for the closed Endpoint module-capability catalog."""

from __future__ import annotations


def test_module_capability_catalog_is_closed_and_fully_versioned() -> None:
    """Reject accidental generic execution or missing primitive provenance."""
    from endpoint_contracts.capabilities import module_capability_catalog

    catalog = module_capability_catalog().model_dump(mode="json")

    assert catalog == {
        "schema_version": "module_capability_catalog_v1",
        "capabilities": [
            {
                "capability": "dns.resolve",
                "parameter_schema_version": "dns_resolve_parameters_v1",
                "result_schema_version": "dns_resolve_result_v1",
                "platforms": ["linux_amd64", "windows_amd64"],
                "minimum_agent_version": "3.2.27",
                "risk": "safe_read",
                "consent_required": False,
                "feature_flag": "endpoint_network_primitives_enabled",
                "policy": "network_target_policy",
            },
            {
                "capability": "network.ping",
                "parameter_schema_version": "network_ping_parameters_v1",
                "result_schema_version": "network_ping_result_v1",
                "platforms": ["linux_amd64", "windows_amd64"],
                "minimum_agent_version": "3.2.27",
                "risk": "safe_read",
                "consent_required": False,
                "feature_flag": "endpoint_network_primitives_enabled",
                "policy": "network_target_policy",
            },
            {
                "capability": "tcp.connect",
                "parameter_schema_version": "tcp_connect_parameters_v1",
                "result_schema_version": "tcp_connect_result_v1",
                "platforms": ["linux_amd64", "windows_amd64"],
                "minimum_agent_version": "3.2.27",
                "risk": "safe_read",
                "consent_required": False,
                "feature_flag": "endpoint_network_primitives_enabled",
                "policy": "network_target_policy",
            },
            {
                "capability": "route.get",
                "parameter_schema_version": "route_get_parameters_v1",
                "result_schema_version": "route_get_result_v1",
                "platforms": ["linux_amd64", "windows_amd64"],
                "minimum_agent_version": "3.2.29",
                "risk": "safe_read",
                "consent_required": False,
                "feature_flag": "endpoint_read_only_primitives_enabled",
                "policy": "network_target_policy",
            },
            {
                "capability": "adapter.list",
                "parameter_schema_version": "adapter_list_parameters_v1",
                "result_schema_version": "adapter_list_result_v1",
                "platforms": ["linux_amd64", "windows_amd64"],
                "minimum_agent_version": "3.2.29",
                "risk": "safe_read",
                "consent_required": False,
                "feature_flag": "endpoint_read_only_primitives_enabled",
                "policy": "none",
            },
            {
                "capability": "system.service_status",
                "parameter_schema_version": "service_status_parameters_v1",
                "result_schema_version": "service_status_result_v1",
                "platforms": ["linux_amd64", "windows_amd64"],
                "minimum_agent_version": "3.2.29",
                "risk": "safe_read",
                "consent_required": False,
                "feature_flag": "endpoint_read_only_primitives_enabled",
                "policy": "none",
            },
        ],
    }
    assert not {
        "command",
        "shell",
        "powershell",
        "python",
        "executable",
        "path",
        "url",
        "service_name",
    }.intersection(catalog["capabilities"][0])
