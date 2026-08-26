"""Agent hello advertises only built-in typed primitive handlers."""

from pc_agent.transport.protocol import compatibility_agent_hello


def test_compatibility_hello_advertises_typed_network_capabilities() -> None:
    capabilities = compatibility_agent_hello().capabilities

    assert "dns.resolve" in capabilities
    assert "network.ping" in capabilities
    assert "tcp.connect" in capabilities
