"""Endpoint Policy frames stay separate from capability policy_update_v1."""

from __future__ import annotations

from datetime import UTC, datetime
import json
from pathlib import Path
from uuid import UUID

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from pydantic import ValidationError

from endpoint_contracts.endpoint_policy import EndpointPolicyV1, policy_digest
from endpoint_contracts.gateway_ws import (
    AgentHelloV1,
    EndpointPolicyAckV1,
    EndpointPolicyAckEnvelopeV1,
    EndpointPolicyDeliveryV1,
    GatewayInboundV1,
    GatewayWsEnvelopeV1,
)
from endpoint_server.gateway.protocol import GatewayProtocolError, parse_agent_envelope
from tests.contracts.test_endpoint_policy_v1 import _policy


def _legacy_hello() -> dict[str, object]:
    return {
        "schema_version": "agent_hello_v1",
        "device_id": "11111111-1111-4111-8111-111111111111",
        "agent_instance_id": "22222222-2222-4222-8222-222222222222",
        "agent_version": "3.2.67",
        "launcher_version": "3.2.67",
        "platform": "windows_amd64",
        "boot_id": "legacy-boot",
        "capabilities": [],
        "last_result_sequence": 0,
        "last_policy_revision": 0,
    }


def test_legacy_hello_defaults_to_no_protocol_features() -> None:
    hello = AgentHelloV1.model_validate(_legacy_hello())
    assert hello.protocol_features == []


def test_policy_protocol_features_are_typed_unique_and_not_module_capabilities() -> None:
    hello = AgentHelloV1.model_validate({
        **_legacy_hello(),
        "protocol_features": ["endpoint.policy.v1"],
    })
    assert hello.protocol_features == ["endpoint.policy.v1"]
    assert hello.capabilities == []
    for features in (
        ["endpoint.policy.v1", "endpoint.policy.v1"],
        ["endpoint.policy.v2"],
        ["shell.exec"],
        "endpoint.policy.v1",
    ):
        with pytest.raises(ValidationError):
            AgentHelloV1.model_validate({**_legacy_hello(), "protocol_features": features})


def test_policy_delivery_is_digest_bound_and_distinct_from_capability_update() -> None:
    policy = EndpointPolicyV1.model_validate(_policy())
    delivery = EndpointPolicyDeliveryV1(
        schema_version="endpoint_policy_delivery_v1",
        policy_version_id=UUID("11111111-1111-4111-8111-111111111111"),
        policy=policy,
        policy_digest=policy_digest(policy),
        issued_at=datetime.now(UTC),
    )
    envelope = GatewayWsEnvelopeV1.model_validate({
        "schema_version": "gateway_ws_envelope_v1",
        "kind": "endpoint_policy_delivery",
        "sequence": 0,
        "payload": delivery.model_dump(mode="json"),
    })
    assert isinstance(GatewayInboundV1(root=envelope.root).root.payload, EndpointPolicyDeliveryV1)
    with pytest.raises(ValidationError):
        EndpointPolicyDeliveryV1.model_validate({
            **delivery.model_dump(mode="json"), "policy_digest": "0" * 64,
        })


def test_policy_ack_requires_applied_time_and_bounded_error_code() -> None:
    base = {
        "schema_version": "endpoint_policy_ack_v1",
        "policy_id": str(_policy()["policy_id"]),
        "policy_version": 1,
        "policy_digest": "a" * 64,
        "received_at": datetime.now(UTC).isoformat(),
    }
    with pytest.raises(ValidationError):
        EndpointPolicyAckV1.model_validate({**base, "status": "APPLIED"})
    applied = EndpointPolicyAckV1.model_validate({
        **base, "status": "APPLIED", "applied_at": datetime.now(UTC).isoformat(),
    })
    assert applied.error_code is None
    with pytest.raises(ValidationError):
        EndpointPolicyAckV1.model_validate({
            **base, "status": "ERROR", "error_code": "x" * 65,
        })

    ack_envelope = EndpointPolicyAckEnvelopeV1(
        schema_version="gateway_ws_envelope_v1", kind="endpoint_policy_ack",
        sequence=1, payload=applied,
    )
    parsed = parse_agent_envelope(
        ack_envelope.model_dump_json(), maximum_message_bytes=64 * 1024,
    )
    assert isinstance(parsed, EndpointPolicyAckEnvelopeV1)
    with pytest.raises(GatewayProtocolError, match="invalid_direction"):
        parse_agent_envelope(
            GatewayWsEnvelopeV1.model_validate({
                "schema_version": "gateway_ws_envelope_v1",
                "kind": "endpoint_policy_delivery", "sequence": 0,
                "payload": EndpointPolicyDeliveryV1(
                    schema_version="endpoint_policy_delivery_v1",
                    policy_version_id=UUID("11111111-1111-4111-8111-111111111111"),
                    policy=EndpointPolicyV1.model_validate(_policy()),
                    policy_digest=policy_digest(EndpointPolicyV1.model_validate(_policy())),
                    issued_at=datetime.now(UTC),
                ).model_dump(mode="json"),
            }).model_dump_json(), maximum_message_bytes=64 * 1024,
        )


def test_published_policy_schemas_reject_untyped_modes_and_incomplete_ack() -> None:
    schema_root = Path("contracts/jsonschema")
    policy_schema = json.loads((schema_root / "endpoint_policy_v1.json").read_text(encoding="utf-8"))
    ack_schema = json.loads((schema_root / "endpoint_policy_ack_v1.json").read_text(encoding="utf-8"))
    policy_validator = Draft202012Validator(policy_schema, format_checker=FormatChecker())
    ack_validator = Draft202012Validator(ack_schema, format_checker=FormatChecker())
    assert policy_validator.is_valid(_policy())
    assert not policy_validator.is_valid(_policy(browser_sensor={
        "required": True, "deployment_mode": "manual",
    }))
    incomplete_ack = {
        "schema_version": "endpoint_policy_ack_v1",
        "policy_id": str(_policy()["policy_id"]),
        "policy_version": 1, "policy_digest": "a" * 64,
        "received_at": datetime.now(UTC).isoformat(),
        "status": "APPLIED",
    }
    assert not ack_validator.is_valid(incomplete_ack)
