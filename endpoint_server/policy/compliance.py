"""Derive browser compliance from server policy and bounded Agent observations."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Literal

from endpoint_contracts.browser_status import (
    BrowserFamilyStatusV1, BrowserStatusReportV1,
)
from endpoint_contracts.endpoint_policy import EndpointPolicyV1


_STATUS_FRESHNESS = timedelta(minutes=3)
_HEARTBEAT_FRESHNESS = timedelta(minutes=3)
_CLOCK_SKEW = timedelta(minutes=5)

BrowserComplianceState = Literal[
    "NOT_APPLICABLE", "UNKNOWN", "NEVER_SEEN", "ACTIVE", "STALE", "ERROR"
]
DeviceComplianceState = Literal[
    "COMPLIANT", "PARTIAL", "NON_COMPLIANT", "STALE", "UNSUPPORTED"
]


@dataclass(frozen=True, slots=True)
class BrowserCompliance:
    browser_family: Literal["chrome", "yandex"]
    state: BrowserComplianceState
    reason: str | None
    extension_version: str | None = None
    extension_last_seen_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class DeviceBrowserCompliance:
    overall: DeviceComplianceState
    browsers: tuple[BrowserCompliance, BrowserCompliance]


def _empty(state: BrowserComplianceState, reason: str | None) -> tuple[
    BrowserCompliance, BrowserCompliance
]:
    return (
        BrowserCompliance("chrome", state, reason),
        BrowserCompliance("yandex", state, reason),
    )


def _family_compliance(
    observed: BrowserFamilyStatusV1,
    policy: EndpointPolicyV1,
    *,
    now: datetime,
) -> BrowserCompliance:
    family = observed.browser_family
    version = observed.extension_version
    seen = observed.extension_last_seen_at

    def result(state: BrowserComplianceState, reason: str | None = None) -> BrowserCompliance:
        return BrowserCompliance(family, state, reason, version, seen)

    if observed.policy_owner == "CONFLICT" or observed.installation_policy_state == "CONFLICT":
        return result("ERROR", "POLICY_CONFLICT")
    if observed.browser_state == "ABSENT":
        return result("NOT_APPLICABLE", "BROWSER_ABSENT")
    if observed.browser_state == "UNKNOWN":
        return result("UNKNOWN", "BROWSER_DETECTION_UNKNOWN")
    expected_owner = (
        "ENDPOINT" if policy.browser_sensor.deployment_mode == "agent_managed"
        else "EXTERNAL"
    )
    if observed.policy_owner != expected_owner:
        return result("ERROR", "POLICY_OWNER_MISMATCH")
    if observed.installation_policy_state != "APPLIED":
        return result("ERROR", "INSTALLATION_POLICY_NOT_APPLIED")
    if observed.native_host_state != "READY":
        return result("ERROR", "NATIVE_HOST_UNAVAILABLE")
    if seen is None:
        # An unobserved process launch is not proof that no launch occurred.
        return result("NEVER_SEEN", "EXTENSION_NEVER_SEEN")
    if observed.running_state == "CLOSED":
        return result("STALE", "BROWSER_CLOSED")
    if observed.running_state == "UNKNOWN":
        return result("UNKNOWN", "BROWSER_RUNNING_UNKNOWN")
    if not timedelta(0) <= now - seen <= _HEARTBEAT_FRESHNESS:
        return result("STALE", "EXTENSION_STALE")
    if observed.extension_install_type == "OTHER":
        return result("ERROR", "EXTENSION_NOT_MANAGED")
    if observed.extension_install_type != "ADMIN":
        return result("UNKNOWN", "BROWSER_POLICY_EFFECT_UNKNOWN")
    return result("ACTIVE")


def derive_browser_compliance(
    policy: EndpointPolicyV1,
    policy_status: Literal["PENDING", "APPLIED", "STALE", "UNSUPPORTED", "ERROR"],
    report: BrowserStatusReportV1 | None,
    *,
    now: datetime,
) -> DeviceBrowserCompliance:
    """Keep a missing or stale Agent report from becoming a compliant claim."""
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("compliance time must be timezone-aware")
    if policy_status == "UNSUPPORTED":
        return DeviceBrowserCompliance("UNSUPPORTED", _empty("UNKNOWN", "AGENT_UNSUPPORTED"))
    if policy_status == "STALE":
        return DeviceBrowserCompliance("STALE", _empty("UNKNOWN", "POLICY_STALE"))
    if policy_status not in {"APPLIED", "ERROR"}:
        return DeviceBrowserCompliance(
            "NON_COMPLIANT", _empty("UNKNOWN", "POLICY_NOT_APPLIED"),
        )
    if not policy.browser_sensor.required:
        return DeviceBrowserCompliance(
            "COMPLIANT" if policy_status == "APPLIED" else "NON_COMPLIANT",
            _empty("NOT_APPLICABLE", None),
        )
    if report is None:
        return DeviceBrowserCompliance(
            "PARTIAL" if policy_status == "APPLIED" else "NON_COMPLIANT",
            _empty("UNKNOWN", "STATUS_NOT_REPORTED"),
        )
    if report.policy_id != policy.policy_id or report.policy_version != policy.policy_version:
        return DeviceBrowserCompliance(
            "STALE", _empty("UNKNOWN", "STATUS_POLICY_MISMATCH"),
        )
    if not -_CLOCK_SKEW <= now - report.observed_at <= _STATUS_FRESHNESS:
        return DeviceBrowserCompliance(
            "STALE", _empty("UNKNOWN", "STATUS_STALE"),
        )
    by_family = {item.browser_family: item for item in report.browsers}
    browsers = (
        _family_compliance(by_family["chrome"], policy, now=now),
        _family_compliance(by_family["yandex"], policy, now=now),
    )
    states = {item.state for item in browsers}
    if policy_status == "ERROR" or "ERROR" in states:
        overall: DeviceComplianceState = "NON_COMPLIANT"
    elif states <= {"ACTIVE", "NOT_APPLICABLE"}:
        overall = "COMPLIANT"
    else:
        overall = "PARTIAL"
    return DeviceBrowserCompliance(overall, browsers)
