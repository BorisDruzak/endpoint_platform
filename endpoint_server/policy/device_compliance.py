"""Derive fleet Policy compliance from current server and Agent observations."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Literal

from endpoint_contracts.activity import ActivityStateV1
from endpoint_contracts.browser_status import BrowserStatusReportV1
from endpoint_contracts.endpoint_policy import EndpointPolicyV1
from endpoint_contracts.sensor_health import PolicySensorHealthReportV1

from .compliance import DeviceComplianceState, derive_browser_compliance


SensorState = Literal[
    "NOT_APPLICABLE", "ACTIVE", "UNKNOWN", "UNAVAILABLE", "STALE", "UNSUPPORTED"
]
PolicyStatus = Literal["PENDING", "APPLIED", "STALE", "UNSUPPORTED", "ERROR"]
_FRESHNESS = timedelta(minutes=2)
_HEALTH_FRESHNESS = timedelta(minutes=3)


@dataclass(frozen=True, slots=True)
class ActivityEvidence:
    last_observed_at: datetime
    session_state: ActivityStateV1


@dataclass(frozen=True, slots=True)
class DevicePolicyCompliance:
    overall: DeviceComplianceState
    activity: SensorState
    browser: SensorState
    dlp: SensorState


def _fresh(when: datetime, *, now: datetime, window: timedelta) -> bool:
    return when.tzinfo is not None and when.utcoffset() is not None and (
        timedelta(0) <= now - when <= window
    )


def _source_state(value: str) -> SensorState:
    return "ACTIVE" if value == "READY" else (
        "UNAVAILABLE" if value == "UNAVAILABLE" else "UNKNOWN"
    )


def derive_device_compliance(
    policy: EndpointPolicyV1,
    policy_status: PolicyStatus,
    health: PolicySensorHealthReportV1 | None,
    browser_report: BrowserStatusReportV1 | None,
    activity_evidence: ActivityEvidence | None,
    *,
    online: bool,
    protocol_features: frozenset[str],
    now: datetime,
) -> DevicePolicyCompliance:
    """A policy ACK alone cannot prove a continuous sensor is active."""
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("compliance time must be timezone-aware")
    browser_audit = (
        policy.dlp.browser_upload_events == "audit"
        or policy.dlp.browser_paste_events == "audit"
    )
    browser_needed = policy.browser_sensor.required or browser_audit
    dlp_needed = any(value == "audit" for value in (
        policy.dlp.usb_device_events, policy.dlp.print_events,
        policy.dlp.browser_upload_events, policy.dlp.browser_paste_events,
    ))
    requested = (policy.activity.enabled, browser_needed, dlp_needed)

    def all_requested(state: SensorState) -> DevicePolicyCompliance:
        values = tuple(state if needed else "NOT_APPLICABLE" for needed in requested)
        overall: DeviceComplianceState = (
            "UNSUPPORTED" if state == "UNSUPPORTED" else
            "STALE" if state == "STALE" else "NON_COMPLIANT"
        )
        return DevicePolicyCompliance(overall, *values)

    if policy_status == "UNSUPPORTED":
        return all_requested("UNSUPPORTED")
    if not online or policy_status == "STALE":
        return all_requested("STALE")
    if "endpoint.policy.v1" not in protocol_features:
        return all_requested("UNSUPPORTED")
    if policy_status != "APPLIED":
        return all_requested("UNKNOWN")

    activity: SensorState = "NOT_APPLICABLE"
    browser: SensorState = "NOT_APPLICABLE"
    dlp: SensorState = "NOT_APPLICABLE"
    health_state: SensorState = "UNKNOWN"
    if health is not None:
        if (
            health.policy_id != policy.policy_id
            or health.policy_version != policy.policy_version
            or not _fresh(health.observed_at, now=now, window=_HEALTH_FRESHNESS)
        ):
            health_state = "STALE"
        else:
            health_state = "ACTIVE"

    if policy.activity.enabled:
        if not {"endpoint.activity.v1", "endpoint.sensor-health.v1"} <= protocol_features:
            activity = "UNSUPPORTED"
        elif health_state != "ACTIVE":
            activity = health_state
        else:
            assert health is not None
            activity = _source_state(health.activity_listener_state)
            if activity == "ACTIVE":
                sampled_at = health.user_sensor_last_seen_at
                if sampled_at is None:
                    activity = "UNKNOWN"
                elif not _fresh(sampled_at, now=now, window=_FRESHNESS):
                    activity = "STALE"
                elif activity_evidence is None:
                    activity = "UNKNOWN"
                elif not _fresh(
                    activity_evidence.last_observed_at, now=now, window=_FRESHNESS,
                ):
                    activity = "STALE"
                elif (
                    activity_evidence.last_observed_at < sampled_at
                    or activity_evidence.session_state == "UNKNOWN"
                ):
                    activity = "UNKNOWN"

    if browser_needed:
        if "endpoint.browser-status.v1" not in protocol_features:
            browser = "UNSUPPORTED"
        else:
            required_policy = (
                policy if policy.browser_sensor.required else policy.model_copy(update={
                    "browser_sensor": policy.browser_sensor.model_copy(update={"required": True}),
                })
            )
            result = derive_browser_compliance(
                required_policy, "APPLIED", browser_report, now=now,
            )
            if result.overall == "COMPLIANT":
                browser = "ACTIVE"
            elif result.overall == "NON_COMPLIANT":
                browser = "UNAVAILABLE"
            elif result.overall == "STALE" or any(
                item.state == "STALE" for item in result.browsers
            ):
                browser = "STALE"
            else:
                browser = "UNKNOWN"

    if dlp_needed:
        if not {"endpoint.security-events.v1", "endpoint.sensor-health.v1"} <= protocol_features:
            dlp = "UNSUPPORTED"
        elif health_state != "ACTIVE":
            dlp = health_state
        else:
            assert health is not None
            sources = [_source_state(health.security_spool_state)]
            if policy.dlp.usb_device_events == "audit":
                sources.append(_source_state(health.usb_source_state))
            if policy.dlp.print_events == "audit":
                sources.append(_source_state(health.print_source_state))
            if browser_audit:
                sources.append(_source_state(health.activity_listener_state))
                sources.append(browser)
            dlp = (
                "UNAVAILABLE" if "UNAVAILABLE" in sources else
                "UNSUPPORTED" if "UNSUPPORTED" in sources else
                "STALE" if "STALE" in sources else
                "UNKNOWN" if "UNKNOWN" in sources else "ACTIVE"
            )

    states = (activity, browser, dlp)
    overall: DeviceComplianceState = (
        "NON_COMPLIANT" if "UNAVAILABLE" in states else
        "UNSUPPORTED" if "UNSUPPORTED" in states else
        "STALE" if "STALE" in states else
        "PARTIAL" if "UNKNOWN" in states else "COMPLIANT"
    )
    return DevicePolicyCompliance(overall, activity, browser, dlp)


__all__ = ["ActivityEvidence", "DevicePolicyCompliance", "derive_device_compliance"]
