"""Selection and transition helpers for universal enrollment requests."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv6Address
from typing import Literal, Sequence

from endpoint_server.db.models import EnrollmentCampaign

from .campaigns import campaign_request_matches, parse_windows_enrollment_policy


RequestSelectionStatus = Literal["auto_approved", "waiting_approval", "review_required", "denied"]


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
