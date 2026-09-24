"""Endpoint Policy is a bounded, immutable continuous-sensor contract."""

from __future__ import annotations

from uuid import UUID

import pytest
from pydantic import ValidationError

from endpoint_contracts.endpoint_policy import EndpointPolicyV1, policy_digest


POLICY_ID = UUID("d7000000-0000-4000-8000-000000000001")


def _policy(**changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": "endpoint_policy_v1",
        "policy_id": str(POLICY_ID),
        "policy_version": 1,
        "activity": {
            "enabled": True,
            "idle_threshold_seconds": 600,
            "foreground_application": True,
            "browser_context": True,
        },
        "dlp": {
            "usb_device_events": "audit",
            "removable_write_events": "disabled",
            "print_events": "audit",
            "browser_upload_events": "audit",
            "browser_paste_events": "audit",
        },
        "browser_sensor": {
            "required": True,
            "deployment_mode": "agent_managed",
        },
        "event_retention": {"security_event_days": 30},
    }
    value.update(changes)
    return value


def test_policy_accepts_typed_agent_managed_browser_ownership() -> None:
    policy = EndpointPolicyV1.model_validate(_policy())
    assert policy.browser_sensor.deployment_mode == "agent_managed"
    assert policy.dlp.usb_device_events == "audit"
    assert policy.policy_version == 1


def test_policy_accepts_external_management_without_changing_sensor_contract() -> None:
    value = _policy(browser_sensor={"required": True, "deployment_mode": "external_managed"})
    policy = EndpointPolicyV1.model_validate(value)
    assert policy.browser_sensor.deployment_mode == "external_managed"
    assert policy.browser_sensor.required is True


@pytest.mark.parametrize("mode", ["manual", "AGENT_MANAGED", "", 1, None])
def test_policy_rejects_untyped_browser_ownership(mode: object) -> None:
    with pytest.raises(ValidationError):
        EndpointPolicyV1.model_validate(_policy(browser_sensor={"required": True, "deployment_mode": mode}))


@pytest.mark.parametrize("seconds", [59, 3601, "600", True])
def test_policy_rejects_invalid_idle_threshold(seconds: object) -> None:
    with pytest.raises(ValidationError):
        EndpointPolicyV1.model_validate(_policy(activity={
            "enabled": True,
            "idle_threshold_seconds": seconds,
            "foreground_application": True,
            "browser_context": True,
        }))


def test_policy_rejects_content_fields_and_enforcement_modes() -> None:
    with pytest.raises(ValidationError):
        EndpointPolicyV1.model_validate(_policy(browser_sensor={
            "required": True,
            "deployment_mode": "agent_managed",
            "browser_history": True,
        }))
    with pytest.raises(ValidationError):
        EndpointPolicyV1.model_validate(_policy(dlp={
            "usb_device_events": "block",
            "removable_write_events": "disabled",
            "print_events": "audit",
            "browser_upload_events": "audit",
            "browser_paste_events": "audit",
        }))


def test_policy_rejects_unimplemented_removable_write_audit() -> None:
    value = _policy()
    value["dlp"] = {**value["dlp"], "removable_write_events": "audit"}  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        EndpointPolicyV1.model_validate(value)


def test_policy_digest_is_stable_across_input_key_order_and_changes_with_ownership() -> None:
    first = EndpointPolicyV1.model_validate(_policy())
    second = EndpointPolicyV1.model_validate(dict(reversed(list(_policy().items()))))
    external = EndpointPolicyV1.model_validate(_policy(browser_sensor={
        "required": True, "deployment_mode": "external_managed",
    }))
    assert len(policy_digest(first)) == 64
    assert policy_digest(first) == policy_digest(second)
    assert policy_digest(first) != policy_digest(external)
