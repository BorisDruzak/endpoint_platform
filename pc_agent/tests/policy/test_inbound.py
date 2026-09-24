"""Connected Agent runtime ACKs only after the policy applicator returns."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from endpoint_contracts.endpoint_policy import EndpointPolicyV1, policy_digest
from endpoint_contracts.gateway_ws import (
    EndpointPolicyDeliveryEnvelopeV1, EndpointPolicyDeliveryV1, GatewayInboundV1,
)
from pc_agent.policy.cache import AppliedPolicyCache
from pc_agent.policy.runtime import PolicyRuntime
from pc_agent.runtime.lifecycle import _handle_inbound
from pc_agent.transport.base import GatewayTerminalError
from tests.contracts.test_endpoint_policy_v1 import _policy


def _inbound() -> GatewayInboundV1:
    policy = EndpointPolicyV1.model_validate(_policy())
    return GatewayInboundV1(root=EndpointPolicyDeliveryEnvelopeV1(
        schema_version="gateway_ws_envelope_v1", kind="endpoint_policy_delivery",
        sequence=0, payload=EndpointPolicyDeliveryV1(
            schema_version="endpoint_policy_delivery_v1", policy_version_id=uuid4(),
            policy=policy, policy_digest=policy_digest(policy), issued_at=datetime.now(UTC),
        ),
    ))


class _Transport:
    def __init__(self) -> None:
        self.acks = []

    async def send_policy_ack(self, ack) -> None:
        self.acks.append(ack)


@pytest.mark.asyncio
async def test_inbound_policy_uses_runtime_before_sending_ack(tmp_path) -> None:
    transport = _Transport()
    runtime = PolicyRuntime(AppliedPolicyCache(
        tmp_path, protector=lambda _: None, inspector=lambda _: None,
    ))
    await _handle_inbound(
        transport, object(), _inbound(), policy_handler=runtime.apply_delivery,
    )
    assert len(transport.acks) == 1
    assert transport.acks[0].status == "ERROR"
    assert transport.acks[0].error_code == "SENSOR_NOT_READY"


@pytest.mark.asyncio
async def test_inbound_policy_without_runtime_fails_closed() -> None:
    with pytest.raises(GatewayTerminalError):
        await _handle_inbound(_Transport(), object(), _inbound())
