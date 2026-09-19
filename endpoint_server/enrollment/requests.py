"""Selection and transition helpers for universal enrollment requests."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import hashlib
import hmac
from ipaddress import IPv4Address, IPv6Address
from typing import Literal, Sequence
from uuid import uuid4

from endpoint_server.db.models import EnrollmentCampaign, EnrollmentRequest
from endpoint_server.audit.service import append_audit_event

from .campaigns import campaign_request_matches, parse_windows_enrollment_policy


RequestSelectionStatus = Literal["auto_approved", "waiting_approval", "review_required", "denied"]
_REQUEST_CAPABILITY_CONTEXT = b"endpoint-enrollment-request-capability-v1\0"
_INSTALLATION_ID_CONTEXT = b"endpoint-enrollment-request-installation-v1\0"
_FINGERPRINT_CONTEXT = b"endpoint-enrollment-request-fingerprint-v1\0"
_REQUEST_LIFETIME = timedelta(hours=24)


class RequestTransitionError(ValueError):
    """Raised when a request would move backwards or leave a terminal state."""


_ALLOWED_TRANSITIONS: dict[str, frozenset[str]] = {
    "created": frozenset({"validating", "denied", "failed", "cancelled", "expired"}),
    "validating": frozenset({"auto_approved", "waiting_approval", "review_required", "denied", "failed", "expired"}),
    "auto_approved": frozenset({"claim_issued", "denied", "expired", "failed"}),
    "waiting_approval": frozenset({"approved", "denied", "expired", "cancelled"}),
    "review_required": frozenset({"approved", "denied", "expired", "cancelled"}),
    "approved": frozenset({"claim_issued", "denied", "expired", "failed"}),
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


def _binding_digest(value: str, pepper: bytes, context: bytes) -> str:
    if not value or not pepper:
        raise ValueError("request binding and pepper must not be empty")
    return hmac.new(pepper, context + value.encode("utf-8"), hashlib.sha256).hexdigest()


def build_enrollment_request(
    *,
    installation_id: str,
    hardware_fingerprint: str,
    request_capability: str,
    source_address: IPv4Address | IPv6Address,
    installer_version: str,
    installer_release_id: str,
    hostname: str,
    selection: CampaignSelection,
    pepper: bytes,
    now: datetime,
    manufacturer: str | None = None,
    model: str | None = None,
    serial: str | None = None,
    product_uuid: str | None = None,
    macs: Sequence[str] = (),
) -> EnrollmentRequest:
    """Create an uncommitted request record without retaining any raw binding."""
    created_at = now.astimezone(UTC)
    return EnrollmentRequest(
        id=uuid4(),
        installation_id_digest=_binding_digest(
            installation_id, pepper, _INSTALLATION_ID_CONTEXT
        ),
        fingerprint_digest=_binding_digest(
            hardware_fingerprint, pepper, _FINGERPRINT_CONTEXT
        ),
        request_capability_digest=request_capability_digest(request_capability, pepper),
        platform="windows",
        hostname=hostname,
        manufacturer=manufacturer,
        model=model,
        serial=serial,
        product_uuid=product_uuid,
        macs=list(macs),
        source_address=str(source_address),
        installer_version=installer_version,
        installer_release_id=installer_release_id,
        selected_campaign_id=(selection.campaign.id if selection.campaign else None),
        status=selection.status,
        decision_reason=selection.reason,
        decided_at=(
            created_at
            if selection.status in {"auto_approved", "denied", "review_required"}
            else None
        ),
        decided_by=None,
        device_id=None,
        created_at=created_at,
        updated_at=created_at,
        expires_at=created_at + _REQUEST_LIFETIME,
    )


def _campaign_still_allows_request(
    request: EnrollmentRequest,
    campaign: EnrollmentCampaign,
    *,
    now: datetime,
) -> bool:
    policy = parse_windows_enrollment_policy(campaign.policy)
    try:
        source_address = IPv4Address(request.source_address)
    except ValueError:
        try:
            source_address = IPv6Address(request.source_address)
        except ValueError:
            return False
    return (
        request.selected_campaign_id == campaign.id
        and policy is not None
        and request.installer_release_id in policy.allowed_installer_releases
        and campaign.use_count < campaign.max_uses
        and campaign_request_matches(
            campaign,
            now=now.astimezone(UTC),
            source_address=source_address,
            platform="windows",
        )
    )


def approve_enrollment_request(
    request: EnrollmentRequest,
    *,
    campaign: EnrollmentCampaign,
    now: datetime,
) -> None:
    """Approve only the frozen campaign after rechecking its current validity."""
    transition_request_status(request.status, "approved")
    if not _campaign_still_allows_request(request, campaign, now=now):
        raise RequestTransitionError("selected campaign is no longer eligible")
    request.status = "approved"
    request.decision_reason = "MANUALLY_APPROVED"
    request.decided_at = now.astimezone(UTC)
    request.updated_at = now.astimezone(UTC)


def deny_enrollment_request(
    request: EnrollmentRequest,
    *,
    reason: str,
    now: datetime,
) -> None:
    """Terminally deny a pending/review request without modifying identity state."""
    transition_request_status(request.status, "denied")
    request.status = "denied"
    request.decision_reason = reason
    request.decided_at = now.astimezone(UTC)
    request.updated_at = now.astimezone(UTC)


def mark_request_claim_issued(
    request: EnrollmentRequest,
    *,
    campaign: EnrollmentCampaign,
    now: datetime,
) -> None:
    """Record claim issuance only for the request's still-valid frozen campaign."""
    transition_request_status(request.status, "claim_issued")
    if not _campaign_still_allows_request(request, campaign, now=now):
        raise RequestTransitionError("selected campaign is no longer eligible")
    request.status = "claim_issued"
    request.updated_at = now.astimezone(UTC)


async def persist_enrollment_request(
    session,
    *,
    request: EnrollmentRequest,
    request_id: str,
    now: datetime,
) -> EnrollmentRequest:
    """Append a request and its non-secret audit evidence to one transaction."""
    session.add(request)
    await append_audit_event(
        session,
        actor_kind="installer",
        actor_identifier=None,
        action="enrollment_request.created",
        object_kind="enrollment_request",
        object_identifier=str(request.id),
        request_id=request_id,
        details={
            "installer_release_id": request.installer_release_id,
            "platform": request.platform,
            "selected_campaign_id": (
                str(request.selected_campaign_id) if request.selected_campaign_id else None
            ),
            "source_address": request.source_address,
            "status": request.status,
        },
        occurred_at=now,
    )
    return request


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
