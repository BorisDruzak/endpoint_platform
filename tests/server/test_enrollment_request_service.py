from datetime import UTC, datetime, timedelta
from ipaddress import ip_address

from endpoint_server.enrollment.campaigns import issue_campaign
from endpoint_server.enrollment.requests import (
    approve_enrollment_request,
    RequestTransitionError,
    request_capability_matches,
    request_capability_digest,
    build_enrollment_request,
    evaluate_campaign_selection,
    transition_request_status,
    deny_enrollment_request,
    mark_request_claim_issued,
    persist_enrollment_request,
)


NOW = datetime(2026, 9, 19, 12, tzinfo=UTC)
PEPPER = b"enrollment-request-test-pepper-with-enough-entropy"
POLICY = {
    "policy_id": "windows-office-v1",
    "enrollment_mode": "auto",
    "allowed_installer_releases": ["1.0.0"],
}


def _campaign(*, mode: str = "auto", cidr: str = "192.168.100.0/24"):
    return issue_campaign(
        PEPPER,
        expires_at=NOW + timedelta(hours=1),
        max_uses=2,
        allowed_cidrs=(cidr,),
        target_platform="windows",
        policy={**POLICY, "enrollment_mode": mode},
        now=NOW,
    ).record


def test_selection_denies_when_no_campaign_matches_source_and_release() -> None:
    selected = evaluate_campaign_selection(
        [_campaign(cidr="192.168.101.0/24")],
        source_address=ip_address("192.168.100.20"),
        installer_release_id="1.0.0",
        now=NOW,
    )

    assert selected.status == "denied"
    assert selected.campaign is None
    assert selected.reason == "NO_MATCHING_CAMPAIGN"


def test_selection_freezes_exactly_one_manual_or_auto_campaign() -> None:
    auto = evaluate_campaign_selection(
        [_campaign(mode="auto")],
        source_address=ip_address("192.168.100.20"),
        installer_release_id="1.0.0",
        now=NOW,
    )
    manual = evaluate_campaign_selection(
        [_campaign(mode="manual")],
        source_address=ip_address("192.168.100.20"),
        installer_release_id="1.0.0",
        now=NOW,
    )

    assert auto.status == "auto_approved"
    assert auto.campaign is not None
    assert manual.status == "waiting_approval"
    assert manual.campaign is not None


def test_selection_requires_review_for_overlap_without_implicit_tiebreak() -> None:
    selected = evaluate_campaign_selection(
        [_campaign(), _campaign()],
        source_address=ip_address("192.168.100.20"),
        installer_release_id="1.0.0",
        now=NOW,
    )

    assert selected.status == "review_required"
    assert selected.campaign is None
    assert selected.reason == "AMBIGUOUS_CAMPAIGN"


def test_request_transition_allows_only_approval_and_claim_lifecycle() -> None:
    assert transition_request_status("waiting_approval", "approved")
    assert transition_request_status("approved", "claim_issued")
    assert transition_request_status("review_required", "denied")
    assert transition_request_status("claim_issued", "enrolling")
    assert transition_request_status("device_registered", "waiting_wss")
    assert transition_request_status("waiting_wss", "completed")

    try:
        transition_request_status("denied", "claim_issued")
    except RequestTransitionError:
        pass
    else:
        raise AssertionError("terminal denied request must not issue a claim")


def test_request_capability_is_hmac_bound_and_constant_time_comparable() -> None:
    capability = "a" * 43
    digest = request_capability_digest(capability, PEPPER)

    assert digest != capability
    assert request_capability_matches(capability, digest, PEPPER)
    assert not request_capability_matches("b" * 43, digest, PEPPER)


def test_request_builder_freezes_selected_campaign_and_only_persists_digests() -> None:
    campaign = _campaign()
    selection = evaluate_campaign_selection(
        [campaign],
        source_address=ip_address("192.168.100.20"),
        installer_release_id="1.0.0",
        now=NOW,
    )
    request = build_enrollment_request(
        installation_id="win-00112233-4455-6677-8899-aabbccddeeff",
        hardware_fingerprint="sha256:windows-fingerprint-v1",
        request_capability="a" * 43,
        source_address=ip_address("192.168.100.20"),
        installer_version="1.0.0",
        installer_release_id="1.0.0",
        hostname="office-pc-01",
        selection=selection,
        pepper=PEPPER,
        now=NOW,
    )

    assert request.status == "auto_approved"
    assert request.selected_campaign_id == campaign.id
    assert request.installation_id_digest != "win-00112233-4455-6677-8899-aabbccddeeff"
    assert request.fingerprint_digest != "sha256:windows-fingerprint-v1"
    assert request.request_capability_digest != "a" * 43


def test_manual_approval_freezes_the_original_selected_campaign() -> None:
    campaign = _campaign(mode="manual")
    request = build_enrollment_request(
        installation_id="win-00112233-4455-6677-8899-aabbccddeeff",
        hardware_fingerprint="sha256:windows-fingerprint-v1",
        request_capability="a" * 43,
        source_address=ip_address("192.168.100.20"),
        installer_version="1.0.0",
        installer_release_id="1.0.0",
        hostname="office-pc-01",
        selection=evaluate_campaign_selection(
            [campaign],
            source_address=ip_address("192.168.100.20"),
            installer_release_id="1.0.0",
            now=NOW,
        ),
        pepper=PEPPER,
        now=NOW,
    )

    approve_enrollment_request(request, campaign=campaign, now=NOW)

    assert request.status == "approved"
    assert request.selected_campaign_id == campaign.id
    assert request.decision_reason == "MANUALLY_APPROVED"


def test_deny_is_terminal_and_cannot_issue_a_claim() -> None:
    campaign = _campaign(mode="manual")
    request = build_enrollment_request(
        installation_id="win-00112233-4455-6677-8899-aabbccddeeff",
        hardware_fingerprint="sha256:windows-fingerprint-v1",
        request_capability="a" * 43,
        source_address=ip_address("192.168.100.20"),
        installer_version="1.0.0",
        installer_release_id="1.0.0",
        hostname="office-pc-01",
        selection=evaluate_campaign_selection(
            [campaign],
            source_address=ip_address("192.168.100.20"),
            installer_release_id="1.0.0",
            now=NOW,
        ),
        pepper=PEPPER,
        now=NOW,
    )

    deny_enrollment_request(request, reason="ADMIN_DENIED", now=NOW)

    assert request.status == "denied"
    try:
        approve_enrollment_request(request, campaign=campaign, now=NOW)
    except RequestTransitionError:
        pass
    else:
        raise AssertionError("denied request must stay terminal")


def test_claim_issuance_requires_approved_or_auto_approved_request() -> None:
    campaign = _campaign()
    request = build_enrollment_request(
        installation_id="win-00112233-4455-6677-8899-aabbccddeeff",
        hardware_fingerprint="sha256:windows-fingerprint-v1",
        request_capability="a" * 43,
        source_address=ip_address("192.168.100.20"),
        installer_version="1.0.0",
        installer_release_id="1.0.0",
        hostname="office-pc-01",
        selection=evaluate_campaign_selection(
            [campaign],
            source_address=ip_address("192.168.100.20"),
            installer_release_id="1.0.0",
            now=NOW,
        ),
        pepper=PEPPER,
        now=NOW,
    )

    mark_request_claim_issued(request, campaign=campaign, now=NOW)

    assert request.status == "claim_issued"
    assert request.selected_campaign_id == campaign.id


class _PersistingSession:
    def __init__(self) -> None:
        self.added: list[object] = []

    def add(self, value: object) -> None:
        self.added.append(value)


def test_persist_request_appends_a_redacted_audit_event() -> None:
    campaign = _campaign()
    request = build_enrollment_request(
        installation_id="win-00112233-4455-6677-8899-aabbccddeeff",
        hardware_fingerprint="sha256:windows-fingerprint-v1",
        request_capability="a" * 43,
        source_address=ip_address("192.168.100.20"),
        installer_version="1.0.0",
        installer_release_id="1.0.0",
        hostname="office-pc-01",
        selection=evaluate_campaign_selection(
            [campaign],
            source_address=ip_address("192.168.100.20"),
            installer_release_id="1.0.0",
            now=NOW,
        ),
        pepper=PEPPER,
        now=NOW,
    )
    session = _PersistingSession()

    import asyncio

    asyncio.run(persist_enrollment_request(session, request=request, request_id="request-1", now=NOW))

    assert session.added[0] is request
    audit = session.added[1]
    assert audit.action == "enrollment_request.created"
    assert "request_capability" not in audit.details
