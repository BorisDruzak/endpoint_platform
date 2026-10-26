"""Policy readiness is explicit for opted-in peers and absent on legacy wire."""

import json

import pytest
from pydantic import ValidationError

from endpoint_contracts import gateway_ws
from tests.contracts.test_gateway_ws_contract import _agent_hello, _gateway_hello

FEATURE = "endpoint.policy-readiness.v1"


def test_agent_accepts_all_nine_unique_protocol_features() -> None:
    assert getattr(gateway_ws, "POLICY_READINESS_FEATURE", None) == FEATURE
    features = [
        "endpoint.policy.v1", "endpoint.activity.v1", "endpoint.security-events.v1",
        "endpoint.browser-status.v1", "endpoint.sensor-health.v1",
        "endpoint.recovery-update.v2", "endpoint.telemetry-results.v1",
        "endpoint.power-events.v1", FEATURE,
    ]
    hello = gateway_ws.AgentHelloV1.model_validate(
        {**_agent_hello(), "protocol_features": features}
    )
    assert hello.protocol_features == features
    with pytest.raises(ValidationError):
        gateway_ws.AgentHelloV1.model_validate(
            {**_agent_hello(), "protocol_features": features + [FEATURE]}
        )


@pytest.mark.parametrize("readiness", ["required", "not_required"])
def test_gateway_readiness_is_explicit_and_nested_when_present(readiness) -> None:
    hello = gateway_ws.GatewayHelloV1.model_validate({
        **_gateway_hello(), "protocol_features": [FEATURE],
        "policy_readiness": readiness,
    })
    frame = gateway_ws.GatewayHelloEnvelopeV1(
        schema_version="gateway_ws_envelope_v1", sequence=0,
        kind="gateway_hello", payload=hello,
    )
    assert frame.model_dump(mode="json")["payload"]["policy_readiness"] == readiness


@pytest.mark.parametrize("readiness", ["optional", "none", "", True, 0, []])
def test_gateway_rejects_noncanonical_policy_readiness(readiness) -> None:
    with pytest.raises(ValidationError):
        gateway_ws.GatewayHelloV1.model_validate({
            **_gateway_hello(), "policy_readiness": readiness,
        })


@pytest.mark.parametrize("explicit_none", [False, True])
def test_absent_readiness_preserves_exact_legacy_gateway_payload(explicit_none) -> None:
    payload = _gateway_hello()
    hello = gateway_ws.GatewayHelloV1.model_validate(
        payload | ({"policy_readiness": None} if explicit_none else {})
    )
    frame = gateway_ws.GatewayHelloEnvelopeV1(
        schema_version="gateway_ws_envelope_v1", sequence=0,
        kind="gateway_hello", payload=hello,
    )
    assert hello.policy_readiness is None
    assert frame.model_dump(mode="json")["payload"] == payload
    assert json.loads(frame.model_dump_json())["payload"] == payload
