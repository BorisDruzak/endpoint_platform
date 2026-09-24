"""Agent never acknowledges an active sensor policy before sensors are ready."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from endpoint_contracts.endpoint_policy import EndpointPolicyV1, policy_digest
from endpoint_contracts.gateway_ws import EndpointPolicyDeliveryV1
from pc_agent.policy.cache import AppliedPolicyCache
from pc_agent.policy.runtime import PolicyRuntime
from tests.contracts.test_endpoint_policy_v1 import _policy


def _delivery(*, active: bool) -> EndpointPolicyDeliveryV1:
    payload = _policy()
    if not active:
        payload["activity"] = {
            "enabled": False, "idle_threshold_seconds": 600,
            "foreground_application": False, "browser_context": False,
        }
        payload["dlp"] = {
            "usb_device_events": "disabled", "removable_write_events": "disabled",
            "print_events": "disabled", "browser_upload_events": "disabled",
            "browser_paste_events": "disabled",
        }
        payload["browser_sensor"] = {
            "required": False, "deployment_mode": "external_managed",
        }
    policy = EndpointPolicyV1.model_validate(payload)
    return EndpointPolicyDeliveryV1(
        schema_version="endpoint_policy_delivery_v1", policy_version_id=uuid4(),
        policy=policy, policy_digest=policy_digest(policy), issued_at=datetime.now(UTC),
    )


@pytest.mark.asyncio
async def test_disabled_policy_is_applied_cached_and_restored_offline(tmp_path) -> None:
    cache = AppliedPolicyCache(tmp_path, protector=lambda _: None, inspector=lambda _: None)
    runtime = PolicyRuntime(cache)
    delivery = _delivery(active=False)
    ack = await runtime.apply_delivery(delivery)
    assert ack.status == "APPLIED"
    assert ack.policy_digest == delivery.policy_digest
    assert cache.load() is not None
    assert await PolicyRuntime(cache).restore_offline() is True


@pytest.mark.asyncio
async def test_active_policy_without_sensor_components_is_not_falsely_applied(tmp_path) -> None:
    cache = AppliedPolicyCache(tmp_path, protector=lambda _: None, inspector=lambda _: None)
    runtime = PolicyRuntime(cache)
    ack = await runtime.apply_delivery(_delivery(active=True))
    assert ack.status == "ERROR"
    assert ack.error_code == "SENSOR_NOT_READY"
    assert cache.load() is None


@pytest.mark.asyncio
async def test_optional_agent_managed_browser_still_requires_policy_applicator(tmp_path) -> None:
    cache = AppliedPolicyCache(tmp_path, protector=lambda _: None, inspector=lambda _: None)
    delivery = _delivery(active=False)
    policy = delivery.policy.model_copy(update={
        "browser_sensor": delivery.policy.browser_sensor.model_copy(update={
            "deployment_mode": "agent_managed",
        }),
    })
    managed = EndpointPolicyDeliveryV1(
        schema_version="endpoint_policy_delivery_v1",
        policy_version_id=delivery.policy_version_id,
        policy=policy, policy_digest=policy_digest(policy),
        issued_at=delivery.issued_at,
    )
    ack = await PolicyRuntime(cache).apply_delivery(managed)
    assert ack.status == "ERROR" and ack.error_code == "SENSOR_NOT_READY"


@pytest.mark.asyncio
async def test_local_sensor_sees_only_last_successfully_applied_policy(tmp_path) -> None:
    cache = AppliedPolicyCache(tmp_path, protector=lambda _: None, inspector=lambda _: None)
    runtime = PolicyRuntime(cache)
    assert runtime.current_policy is None
    disabled = _delivery(active=False)
    assert (await runtime.apply_delivery(disabled)).status == "APPLIED"
    assert runtime.current_policy == disabled.policy
    assert (await runtime.apply_delivery(_delivery(active=True))).status == "ERROR"
    assert runtime.current_policy == disabled.policy

    restored = PolicyRuntime(cache)
    assert restored.current_policy is None
    assert await restored.restore_offline() is True
    assert restored.current_policy == disabled.policy
