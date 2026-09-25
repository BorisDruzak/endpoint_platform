"""Overall policy compliance is server-derived from current sensor evidence."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from endpoint_contracts.browser_status import BrowserStatusReportV1
from endpoint_contracts.endpoint_policy import EndpointPolicyV1
from endpoint_contracts.sensor_health import PolicySensorHealthReportV1
from endpoint_server.policy.device_compliance import (
    ActivityEvidence, derive_device_compliance,
)
from tests.contracts.test_endpoint_policy_v1 import _policy
from tests.policy.test_browser_compliance import _status


NOW = datetime(2026, 9, 25, 12, tzinfo=UTC)
FEATURES = frozenset({
    "endpoint.policy.v1", "endpoint.activity.v1",
    "endpoint.browser-status.v1", "endpoint.security-events.v1",
    "endpoint.sensor-health.v1",
})


def _configured_policy() -> EndpointPolicyV1:
    value = _policy()
    value["activity"]["enabled"] = True
    value["browser_sensor"] = {
        "required": True, "deployment_mode": "agent_managed",
    }
    value["dlp"].update({
        "usb_device_events": "audit", "print_events": "audit",
        "browser_upload_events": "audit", "browser_paste_events": "audit",
    })
    return EndpointPolicyV1.model_validate(value)


def _health(policy: EndpointPolicyV1) -> PolicySensorHealthReportV1:
    from uuid import uuid4

    return PolicySensorHealthReportV1(
        schema_version="policy_sensor_health_report_v1",
        observation_id=uuid4(), policy_id=policy.policy_id,
        policy_version=policy.policy_version, observed_at=NOW,
        activity_listener_state="READY",
        user_sensor_last_seen_at=NOW - timedelta(seconds=10),
        security_spool_state="READY", usb_source_state="READY",
        print_source_state="READY",
    )


def _activity() -> ActivityEvidence:
    return ActivityEvidence(
        last_observed_at=NOW - timedelta(seconds=5), session_state="ACTIVE",
    )


def _derive(
    policy: EndpointPolicyV1, *,
    health: PolicySensorHealthReportV1 | None = None,
    browser: BrowserStatusReportV1 | None = None,
    activity: ActivityEvidence | None = None,
    status: str = "APPLIED",
    online: bool = True,
    features: frozenset[str] = FEATURES,
    now: datetime = NOW,
):
    return derive_device_compliance(
        policy, status, health, browser, activity,
        online=online, protocol_features=features, now=now,
    )


def test_all_required_live_evidence_can_be_compliant() -> None:
    policy = _configured_policy()
    result = _derive(
        policy, health=_health(policy), browser=_status(policy),
        activity=_activity(),
    )
    assert result.overall == "COMPLIANT"
    assert (result.activity, result.browser, result.dlp) == (
        "ACTIVE", "ACTIVE", "ACTIVE",
    )


def test_policy_ack_alone_is_partial_and_failed_ack_is_noncompliant() -> None:
    policy = _configured_policy()
    partial = _derive(policy)
    assert partial.overall == "PARTIAL"
    assert partial.activity == "UNKNOWN"
    assert partial.dlp == "UNKNOWN"
    failed = _derive(policy, status="ERROR", health=_health(policy),
                     browser=_status(policy), activity=_activity())
    assert failed.overall == "NON_COMPLIANT"


def test_unavailable_required_source_is_noncompliant() -> None:
    policy = _configured_policy()
    value = _health(policy).model_copy(update={"usb_source_state": "UNAVAILABLE"})
    result = _derive(policy, health=value, browser=_status(policy),
                     activity=_activity())
    assert result.overall == "NON_COMPLIANT"
    assert result.dlp == "UNAVAILABLE"


def test_stale_sample_activity_projection_and_health_never_look_active() -> None:
    policy = _configured_policy()
    stale_sample = _health(policy).model_copy(update={
        "user_sensor_last_seen_at": NOW - timedelta(minutes=5),
    })
    result = _derive(policy, health=stale_sample, browser=_status(policy),
                     activity=_activity())
    assert result.activity == "STALE"
    assert result.overall == "STALE"
    stale_activity = ActivityEvidence(
        last_observed_at=NOW - timedelta(minutes=5), session_state="ACTIVE",
    )
    result = _derive(policy, health=_health(policy), browser=_status(policy),
                     activity=stale_activity)
    assert result.activity == "STALE"
    stale_health = _derive(policy, health=_health(policy), browser=_status(policy),
                           activity=_activity(), now=NOW + timedelta(minutes=4))
    assert stale_health.overall == "STALE"


def test_no_connection_or_missing_negotiated_feature_cannot_be_compliant() -> None:
    policy = _configured_policy()
    health, browser, activity = _health(policy), _status(policy), _activity()
    offline = _derive(policy, health=health, browser=browser, activity=activity,
                      online=False)
    assert offline.overall == "STALE"
    old_agent = _derive(policy, health=health, browser=browser,
                        activity=activity, features=frozenset({"endpoint.policy.v1"}))
    assert old_agent.overall == "UNSUPPORTED"


def test_browser_audit_requires_browser_even_when_browser_required_is_false() -> None:
    value = _configured_policy().model_dump(mode="python")
    value["browser_sensor"]["required"] = False
    policy = EndpointPolicyV1.model_validate(value)
    result = _derive(policy, health=_health(policy), activity=_activity())
    assert result.overall == "PARTIAL"
    assert result.browser == "UNKNOWN"
    assert result.dlp == "UNKNOWN"


def test_disabled_channels_do_not_need_sensor_health() -> None:
    value = _policy()
    value["activity"]["enabled"] = False
    value["browser_sensor"]["required"] = False
    for channel in (
        "usb_device_events", "print_events", "browser_upload_events",
        "browser_paste_events",
    ):
        value["dlp"][channel] = "disabled"
    policy = EndpointPolicyV1.model_validate(value)
    result = _derive(policy, features=frozenset({"endpoint.policy.v1"}))
    assert result.overall == "COMPLIANT"
    assert (result.activity, result.browser, result.dlp) == (
        "NOT_APPLICABLE", "NOT_APPLICABLE", "NOT_APPLICABLE",
    )
    old_agent = _derive(policy, features=frozenset())
    assert old_agent.overall == "UNSUPPORTED"
