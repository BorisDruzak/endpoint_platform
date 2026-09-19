"""Selection and transition helpers for universal enrollment requests."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
import hmac
from ipaddress import IPv4Address, IPv6Address
from typing import Literal, Sequence

from endpoint_server.db.models import EnrollmentCampaign

from .campaigns import campaign_request_matches, parse_windows_enrollment_policy


RequestSelectionStatus = Literal["auto_approved", "waiting_approval", "review_required", "denied"]
_REQUEST_CAPABILITY_CONTEXT = b"endpoint-enrollment-request-capability-v1\0"


class RequestTransitionError(ValueError):
    """Raised when a request would move backwards or leave a terminal state."""


_ALLOWED_TRANSITIONS: dict[str, frozenset[str]] = {
    "created": frozenset({"validating", "denied", "failed", "cancelled", "expired"}),
    "validating": frozenset({"auto_approved", "waiting_approval", "review_required", "denied", "failed", "expired"}),
    "auto_approved": frozenset({"claim_issued", "denied", "expired", "failed"}),
    "waiting_approval": frozenset({"claim_issued", "denied", "expired", "cancelled"}),
    "review_required": frozenset({"claim_issued", "denied", "expired", "cancelled"}),
    "claim_issued": frozenset({"enrolling", "denied", "expired", "failed"}),
    "enrolling": frozenset({"device_registered", "failed", "expired"}),
    "device_registered": frozenset({"waiting_wss", "failed", "expired"}),
    "waiting_wss": frozenset({"completed", "failed", "expired"}),
}


def transition_request_status(current: str, next_status: str) -> bool:
    """Validate a monotonic request transition without mutating persistence."""
    if next_status not in _ALLOWED_TRANSITIONS.get(current, frozenset()):
        raise RequestTransitionError(f"invalid enrollment request transition: {current} -> {next_status}")
    return True


def request_capability_digest(capability: str, pepper: bytes) -> str:
    """Persist only a context-separated HMAC of the ephemeral poll capability."""
    if not capability or not pepper:
        raise ValueError("request capability and pepper must not be empty")
    return hmac.new(
        pepper,
        _REQUEST_CAPABILITY_CONTEXT + capability.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()


def request_capability_matches(capability: str, expected_digest: str, pepper: bytes) -> bool:
    """Compare an in-memory capability with persistence without an oracle."""
    try:
        actual_digest = request_capability_digest(capability, pepper)
    except (UnicodeEncodeError, ValueError):
        return False
    return hmac.compare_digest(actual_digest, expected_digest)


@dataclass(frozen=True, slots=True)
class CampaignSelection:
    """The only permitted campaign-selection result for a request transaction."""

    status: RequestSelectionStatus
    campaign: EnrollmentCampaign | None
    reason: str


def evaluate_campaign_selection(
    campaigns: Sequence[EnrollmentCampaign],
    *,
    source_address: IPv4Address | IPv6Address,
    installer_release_id: str,
    now: datetime,
    blocking_identity_conflict: bool = False,
) -> CampaignSelection:
    """Choose one eligible Windows campaign or explicitly refuse to choose."""
    checked_at = now.astimezone(UTC)
    eligible: list[tuple[EnrollmentCampaign, str]] = []
    for campaign in campaigns:
        policy = parse_windows_enrollment_policy(campaign.policy)
        if (
            policy is None
            or installer_release_id not in policy.allowed_installer_releases
            or not campaign_request_matches(
                campaign,
                now=checked_at,
                source_address=source_address,
                platform="windows",
            )
            or campaign.use_count >= campaign.max_uses
        ):
            continue
        eligible.append((campaign, policy.enrollment_mode))

    if not eligible:
        return CampaignSelection("denied", None, "NO_MATCHING_CAMPAIGN")
    if len(eligible) != 1:
        return CampaignSelection("review_required", None, "AMBIGUOUS_CAMPAIGN")

    campaign, mode = eligible[0]
    if blocking_identity_conflict:
        return CampaignSelection("review_required", campaign, "DUPLICATE_IDENTITY")
    if mode == "manual":
        return CampaignSelection("waiting_approval", campaign, "MANUAL_POLICY")
    return CampaignSelection("auto_approved", campaign, "AUTO_POLICY")
