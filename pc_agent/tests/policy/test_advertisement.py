"""Policy feature negotiation is tied to a compatible WSS Windows runtime."""

from pc_agent.runtime.application import _policy_protocol_features
from pc_agent.version import AGENT_VERSION


def test_policy_feature_advertisement_requires_new_windows_wss_agent() -> None:
    assert _policy_protocol_features("3.2.67", "windows_amd64", "gateway_wss", False) == []
    assert _policy_protocol_features("3.2.68", "windows_amd64", "gateway_wss", False) == ["endpoint.policy.v1"]
    assert _policy_protocol_features("3.2.69", "linux_amd64", "gateway_wss", False) == []
    assert _policy_protocol_features("3.2.69", "windows_amd64", "gateway_http_pull", False) == []
    assert _policy_protocol_features("3.2.69", "windows_amd64", "gateway_wss", True) == []
    assert _policy_protocol_features("3.2.70", "windows_amd64", "gateway_wss", False) == [
        "endpoint.policy.v1", "endpoint.activity.v1", "endpoint.security-events.v1",
        "endpoint.browser-status.v1",
        "endpoint.sensor-health.v1",
    ]


def test_current_release_candidate_advertises_all_policy_sensor_features() -> None:
    assert AGENT_VERSION == "3.2.73"
    assert _policy_protocol_features(
        AGENT_VERSION, "windows_amd64", "gateway_wss", False,
    ) == [
        "endpoint.policy.v1", "endpoint.activity.v1", "endpoint.security-events.v1",
        "endpoint.browser-status.v1", "endpoint.sensor-health.v1",
    ]
