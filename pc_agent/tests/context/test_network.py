from __future__ import annotations

from pc_agent.context_profiles.network import collect_network

from .conftest import FIXED_TIME


def test_network_uses_default_route_not_public_connect(fake_probe) -> None:
    """Network facts come from local route state and never a public endpoint."""
    result = collect_network(fake_probe, collected_at=FIXED_TIME)

    assert result.sections.default_route.interface == "eth0"
    assert result.sections.default_route.gateway == "192.0.2.1"
    assert fake_probe.network_connect_calls == []
    assert all(command[0][0] != "curl" for command in fake_probe.commands)
