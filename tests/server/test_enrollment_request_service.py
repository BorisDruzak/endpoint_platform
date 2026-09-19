from datetime import UTC, datetime, timedelta
from ipaddress import ip_address

from endpoint_server.enrollment.campaigns import issue_campaign
from endpoint_server.enrollment.requests import evaluate_campaign_selection


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
