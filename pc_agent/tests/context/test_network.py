from __future__ import annotations

from datetime import timedelta
import json
from uuid import uuid4

from endpoint_contracts.commands import AgentCommandV1
from endpoint_contracts.json_types import MAX_JSON_LIST_ITEMS
from pc_agent.context_profiles.command_execution import execute_context_agent_command
from pc_agent.context_profiles.network import collect_network
from pc_agent.context_profiles.probe import IP_ADDRESS_COMMAND

from .conftest import FIXED_TIME


def test_network_uses_default_route_not_public_connect(fake_probe) -> None:
    """Network facts come from local route state and never a public endpoint."""
    result = collect_network(fake_probe, collected_at=FIXED_TIME)

    assert result.sections.default_route.interface == "eth0"
    assert result.sections.default_route.gateway == "192.0.2.1"
    assert fake_probe.network_connect_calls == []
    assert all(command[0][0] != "curl" for command in fake_probe.commands)


def test_virtual_interfaces_fit_gateway_result_and_keep_default_route(fake_probe):
    fake_probe.outputs[IP_ADDRESS_COMMAND] = json.dumps(
        [{"ifname": f"tap{index}", "addr_info": []} for index in range(48)]
        + [{"ifname": "eth0", "addr_info": [{"local": "192.0.2.10"}]}]
    )
    command = AgentCommandV1(
        schema_version="agent_command_v1", command_id=uuid4(), device_id=uuid4(),
        capability="context.network.collect", requested_by_service="endpoint-platform",
        idempotency_key="proxmox-network-interfaces", created_at=FIXED_TIME,
        deadline_at=FIXED_TIME + timedelta(minutes=1),
    )
    result = execute_context_agent_command(command, probe=fake_probe, completed_at=FIXED_TIME)
    assert result.status == "succeeded"
    payload = result.result_items[0]
    assert len(payload["sections"]["interfaces"]) == MAX_JSON_LIST_ITEMS
    assert payload["sections"]["interfaces"][0]["name"] == "eth0"
    assert "data_truncated" in payload["warnings"]
