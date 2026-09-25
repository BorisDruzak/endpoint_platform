"""The server, not the Agent, derives browser and device compliance."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from endpoint_contracts.browser_status import BrowserStatusReportV1
from endpoint_contracts.endpoint_policy import EndpointPolicyV1
from endpoint_server.policy.compliance import derive_browser_compliance
from tests.contracts.test_browser_status_v1 import _report
from tests.contracts.test_endpoint_policy_v1 import _policy


NOW = datetime(2026, 9, 25, 12, tzinfo=UTC)


def _required_policy(*, deployment_mode: str = "agent_managed") -> EndpointPolicyV1:
    value = _policy()
    value["browser_sensor"] = {
        "required": True, "deployment_mode": deployment_mode,
    }
    return EndpointPolicyV1.model_validate(value)


def _status(policy: EndpointPolicyV1, *, yandex_absent: bool = True) -> BrowserStatusReportV1:
    value = _report()
    value["policy_id"] = policy.policy_id
    value["policy_version"] = policy.policy_version
    chrome = value["browsers"][0]
    chrome.update({
        "running_state": "RUNNING", "last_running_at": NOW,
        "extension_version": "0.1.0", "extension_last_seen_at": NOW,
        "extension_install_type": "ADMIN",
    })
    if yandex_absent:
        value["browsers"][1].update({
            "browser_state": "ABSENT", "running_state": "CLOSED",
            "policy_owner": "NONE", "installation_policy_state": "NOT_APPLIED",
            "native_host_state": "READY",
        })
    else:
        value["browsers"][1].update({
            "running_state": "RUNNING", "last_running_at": NOW,
            "extension_version": "0.1.0", "extension_last_seen_at": NOW,
            "extension_install_type": "ADMIN",
        })
    return BrowserStatusReportV1.model_validate(value)


def test_not_required_and_old_agent_have_distinct_results() -> None:
    disabled = EndpointPolicyV1.model_validate(_policy(browser_sensor={
        "required": False, "deployment_mode": "agent_managed",
    }))
    result = derive_browser_compliance(disabled, "APPLIED", None, now=NOW)
    assert result.overall == "COMPLIANT"
    assert {item.state for item in result.browsers} == {"NOT_APPLICABLE"}

    result = derive_browser_compliance(_required_policy(), "UNSUPPORTED", None, now=NOW)
    assert result.overall == "UNSUPPORTED"


def test_active_browser_and_absent_browser_are_independent() -> None:
    policy = _required_policy()
    result = derive_browser_compliance(policy, "APPLIED", _status(policy), now=NOW)
    assert result.overall == "COMPLIANT"
    assert [(item.browser_family, item.state) for item in result.browsers] == [
        ("chrome", "ACTIVE"), ("yandex", "NOT_APPLICABLE"),
    ]
    assert [item.effective_policy_state for item in result.browsers] == [
        "APPLIED", "UNKNOWN",
    ]


def test_browser_effective_policy_requires_fresh_admin_install_and_matching_machine_value() -> None:
    policy = _required_policy()
    value = _status(policy).model_dump(mode="python")
    value["browsers"][0]["extension_install_type"] = "UNKNOWN"
    unknown = derive_browser_compliance(
        policy, "APPLIED", BrowserStatusReportV1.model_validate(value), now=NOW,
    )
    assert unknown.browsers[0].effective_policy_state == "UNKNOWN"
    value["browsers"][0]["extension_install_type"] = "OTHER"
    other = derive_browser_compliance(
        policy, "APPLIED", BrowserStatusReportV1.model_validate(value), now=NOW,
    )
    assert other.browsers[0].effective_policy_state == "NOT_APPLIED"
    value["browsers"][0]["extension_install_type"] = "ADMIN"
    value["browsers"][0]["extension_last_seen_at"] = NOW - timedelta(minutes=10)
    stale = derive_browser_compliance(
        policy, "APPLIED", BrowserStatusReportV1.model_validate(value), now=NOW,
    )
    assert stale.browsers[0].effective_policy_state == "UNKNOWN"
    value["browsers"][0]["extension_last_seen_at"] = NOW
    value["browsers"][0]["installation_policy_state"] = "NOT_APPLIED"
    unconfigured = derive_browser_compliance(
        policy, "APPLIED", BrowserStatusReportV1.model_validate(value), now=NOW,
    )
    assert unconfigured.browsers[0].effective_policy_state == "UNKNOWN"
    value["browsers"][0]["installation_policy_state"] = "APPLIED"
    failed_ack = derive_browser_compliance(
        policy, "ERROR", BrowserStatusReportV1.model_validate(value), now=NOW,
    )
    assert failed_ack.browsers[0].effective_policy_state == "UNKNOWN"


def test_closed_browser_preserves_last_heartbeat_without_installation_error() -> None:
    policy = _required_policy()
    report = _status(policy)
    value = report.model_dump(mode="python")
    value["browsers"][0]["running_state"] = "CLOSED"
    value["browsers"][0]["extension_last_seen_at"] = NOW - timedelta(minutes=10)
    report = BrowserStatusReportV1.model_validate(value)
    result = derive_browser_compliance(policy, "APPLIED", report, now=NOW)
    chrome = result.browsers[0]
    assert result.overall == "PARTIAL"
    assert chrome.state == "STALE"
    assert chrome.reason == "BROWSER_CLOSED"
    assert chrome.extension_version == "0.1.0"
    assert chrome.extension_last_seen_at == NOW - timedelta(minutes=10)


def test_closed_never_seen_without_launch_proof_does_not_claim_browser_not_launched() -> None:
    policy = _required_policy()
    value = _status(policy).model_dump(mode="python")
    value["browsers"][0].update({
        "running_state": "CLOSED", "last_running_at": None,
        "extension_version": None, "extension_last_seen_at": None,
        "extension_install_type": "UNKNOWN",
    })
    report = BrowserStatusReportV1.model_validate(value)
    result = derive_browser_compliance(policy, "APPLIED", report, now=NOW)
    assert result.browsers[0].state == "NEVER_SEEN"
    assert result.browsers[0].reason == "EXTENSION_NEVER_SEEN"
    assert result.overall == "PARTIAL"


def test_conflict_and_wrong_ownership_are_noncompliant() -> None:
    policy = _required_policy()
    value = _status(policy).model_dump(mode="python")
    value["browsers"][0].update({
        "policy_owner": "CONFLICT", "installation_policy_state": "CONFLICT",
    })
    conflict = derive_browser_compliance(
        policy, "APPLIED", BrowserStatusReportV1.model_validate(value), now=NOW,
    )
    assert conflict.overall == "NON_COMPLIANT"
    assert conflict.browsers[0].reason == "POLICY_CONFLICT"
    absent_conflict = conflict.browsers[0]
    value["browsers"][0].update({
        "browser_state": "ABSENT", "running_state": "CLOSED",
        "last_running_at": None,
    })
    absent = derive_browser_compliance(
        policy, "APPLIED", BrowserStatusReportV1.model_validate(value), now=NOW,
    )
    assert absent.browsers[0].reason == "POLICY_CONFLICT"
    assert absent_conflict.state == absent.browsers[0].state
    value["browsers"][0].update({
        "browser_state": "DETECTED", "running_state": "RUNNING",
        "last_running_at": NOW,
    })
    failed_ack = derive_browser_compliance(
        policy, "ERROR", BrowserStatusReportV1.model_validate(value), now=NOW,
    )
    assert failed_ack.overall == "NON_COMPLIANT"
    assert failed_ack.browsers[0].reason == "POLICY_CONFLICT"

    value["browsers"][0].update({
        "policy_owner": "EXTERNAL", "installation_policy_state": "APPLIED",
    })
    wrong_owner = derive_browser_compliance(
        policy, "APPLIED", BrowserStatusReportV1.model_validate(value), now=NOW,
    )
    assert wrong_owner.browsers[0].reason == "POLICY_OWNER_MISMATCH"


def test_external_mode_accepts_external_owner_but_not_endpoint_owner() -> None:
    policy = _required_policy(deployment_mode="external_managed")
    value = _status(policy).model_dump(mode="python")
    value["browsers"][0]["policy_owner"] = "EXTERNAL"
    report = BrowserStatusReportV1.model_validate(value)
    assert derive_browser_compliance(policy, "APPLIED", report, now=NOW).overall == "COMPLIANT"
    value["browsers"][0]["policy_owner"] = "ENDPOINT"
    result = derive_browser_compliance(
        policy, "APPLIED", BrowserStatusReportV1.model_validate(value), now=NOW,
    )
    assert result.browsers[0].reason == "POLICY_OWNER_MISMATCH"


def test_registry_and_heartbeat_alone_do_not_prove_managed_installation() -> None:
    policy = _required_policy()
    value = _status(policy).model_dump(mode="python")
    value["browsers"][0]["extension_install_type"] = "UNKNOWN"
    unproven = derive_browser_compliance(
        policy, "APPLIED", BrowserStatusReportV1.model_validate(value), now=NOW,
    )
    assert unproven.overall == "PARTIAL"
    assert unproven.browsers[0].reason == "BROWSER_POLICY_EFFECT_UNKNOWN"
    value["browsers"][0]["extension_install_type"] = "OTHER"
    manual = derive_browser_compliance(
        policy, "APPLIED", BrowserStatusReportV1.model_validate(value), now=NOW,
    )
    assert manual.overall == "NON_COMPLIANT"
    assert manual.browsers[0].reason == "EXTENSION_NOT_MANAGED"


def test_missing_stale_or_wrong_policy_report_cannot_be_compliant() -> None:
    policy = _required_policy()
    missing = derive_browser_compliance(policy, "APPLIED", None, now=NOW)
    assert missing.overall == "PARTIAL"
    assert {item.reason for item in missing.browsers} == {"STATUS_NOT_REPORTED"}

    stale = derive_browser_compliance(
        policy, "APPLIED", _status(policy), now=NOW + timedelta(minutes=10),
    )
    assert stale.overall == "STALE"

    other_policy = EndpointPolicyV1.model_validate(_policy(policy_version=2))
    wrong = derive_browser_compliance(
        other_policy, "APPLIED", _status(policy), now=NOW,
    )
    assert wrong.overall == "STALE"
