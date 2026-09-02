import pytest

from pc_agent.primitives.network.policy import AgentNetworkProbePolicy, NetworkProbeDenied


def test_agent_policy_fails_closed_until_allowlist_is_configured() -> None:
    policy = AgentNetworkProbePolicy.from_values(allowed_cidrs=(), allowed_suffixes=())

    with pytest.raises(NetworkProbeDenied, match="network_target_policy_not_configured"):
        policy.require_allowed("10.20.1.10")


def test_agent_policy_rechecks_concrete_ip_and_hostname_targets() -> None:
    policy = AgentNetworkProbePolicy.from_values(
        allowed_cidrs=("10.20.0.0/16",), allowed_suffixes=(".example.test",)
    )

    policy.require_allowed("10.20.1.10")
    policy.require_allowed("api.example.test")
    with pytest.raises(NetworkProbeDenied, match="network_target_forbidden_address"):
        policy.require_allowed("127.0.0.1")
    with pytest.raises(NetworkProbeDenied, match="network_target_disallowed"):
        policy.require_allowed("8.8.8.8")
