"""Strict server-owned policy for continuous Endpoint sensors."""

from __future__ import annotations

import hashlib
import json
from typing import Annotated, Literal
from uuid import UUID

from pydantic import Field, StrictBool

from .base import ContractModelV1


DlpAuditModeV1 = Literal["disabled", "audit"]
BrowserDeploymentModeV1 = Literal["agent_managed", "external_managed"]


class ActivityPolicyV1(ContractModelV1):
    enabled: StrictBool
    idle_threshold_seconds: Annotated[int, Field(strict=True, ge=60, le=3600)]
    foreground_application: StrictBool
    browser_context: StrictBool


class DlpPolicyV1(ContractModelV1):
    usb_device_events: DlpAuditModeV1
    removable_write_events: Literal["disabled"]
    print_events: DlpAuditModeV1
    browser_upload_events: DlpAuditModeV1
    browser_paste_events: DlpAuditModeV1


class BrowserSensorPolicyV1(ContractModelV1):
    required: StrictBool
    deployment_mode: BrowserDeploymentModeV1


class EventRetentionPolicyV1(ContractModelV1):
    security_event_days: Annotated[int, Field(strict=True, ge=7, le=365)]


class EndpointPolicyV1(ContractModelV1):
    schema_version: Literal["endpoint_policy_v1"]
    policy_id: UUID
    policy_version: Annotated[int, Field(strict=True, ge=1, le=2**31 - 1)]
    activity: ActivityPolicyV1
    dlp: DlpPolicyV1
    browser_sensor: BrowserSensorPolicyV1
    event_retention: EventRetentionPolicyV1


def policy_digest(policy: EndpointPolicyV1) -> str:
    """Identify the complete, validated policy independent of input key order."""
    encoded = json.dumps(
        policy.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


__all__ = [
    "ActivityPolicyV1",
    "BrowserDeploymentModeV1",
    "BrowserSensorPolicyV1",
    "DlpAuditModeV1",
    "DlpPolicyV1",
    "EndpointPolicyV1",
    "EventRetentionPolicyV1",
    "policy_digest",
]
