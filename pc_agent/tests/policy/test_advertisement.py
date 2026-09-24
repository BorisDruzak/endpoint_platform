"""Policy feature negotiation is tied to a compatible WSS Windows runtime."""

from pc_agent.runtime.application import _policy_protocol_features


def test_policy_feature_advertisement_requires_new_windows_wss_agent() -> None:
    assert _policy_protocol_features("3.2.67", "windows_amd64", "gateway_wss", False) == []
    assert _policy_protocol_features("3.2.68", "windows_amd64", "gateway_wss", False) == ["endpoint.policy.v1"]
    assert _policy_protocol_features("3.2.69", "linux_amd64", "gateway_wss", False) == []
    assert _policy_protocol_features("3.2.69", "windows_amd64", "gateway_http_pull", False) == []
    assert _policy_protocol_features("3.2.69", "windows_amd64", "gateway_wss", True) == []
