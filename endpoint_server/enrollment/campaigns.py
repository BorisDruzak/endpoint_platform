"""Bounded enrollment campaigns and one-time install claims."""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import secrets
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv6Address
from typing import Literal
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from endpoint_contracts.identity import normalize_hardware_fingerprint
from endpoint_contracts.json_types import validate_bounded_json
from endpoint_server.audit.service import append_audit_event
from endpoint_server.db.models import EnrollmentCampaign, EnrollmentClaim


_TOKEN_BYTES = 32
_IDENTIFIER_BYTES = 16
_CAMPAIGN_MARKER = "ec_"
_CLAIM_MARKER = "ic_"
_CAMPAIGN_CONTEXT = b"endpoint-enrollment-campaign-v1\0"
_CLAIM_CONTEXT = b"endpoint-install-claim-v1\0"
_INSTALL_SESSION_CONTEXT = b"endpoint-install-session-v1\0"
_FINGERPRINT_CONTEXT = b"endpoint-enrollment-fingerprint-v1\0"

EnrollmentDenialCategory = Literal[
    "campaign",
    "claim",
    "cidr",
    "expired",
    "fingerprint",
    "installation_id",
    "platform",
]


class EnrollmentDenied(Exception):
    """Generic fail-closed enrollment denial without credential oracle details."""

    def __init__(
        self,
        message: str = "Enrollment denied",
        *,
        category: EnrollmentDenialCategory = "claim",
    ) -> None:
        super().__init__(message)
        self.category = category


@dataclass(frozen=True, slots=True)
class IssuedCampaign:
    """One-time raw campaign bearer paired with its persistence record."""

    token: str = field(repr=False)
    record: EnrollmentCampaign


@dataclass(frozen=True, slots=True)
class IssuedInstallClaim:
    """One-time raw install claim paired with its persistence record."""

    token: str = field(repr=False)
    record: EnrollmentClaim


def _digest(value: str, pepper: bytes, context: bytes) -> str:
    if not value or not pepper:
        raise ValueError("credential and pepper must not be empty")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValueError("credential must be valid UTF-8") from error
    return hmac.new(pepper, context + encoded, hashlib.sha256).hexdigest()


def campaign_token_digest(token: str, pepper: bytes) -> str:
    """Return the contextual HMAC digest stored for a campaign bearer."""
    return _digest(token, pepper, _CAMPAIGN_CONTEXT)


def claim_token_digest(token: str, pepper: bytes) -> str:
    """Return the contextual HMAC digest stored for an install claim."""
    return _digest(token, pepper, _CLAIM_CONTEXT)


def install_claim_bindings_match(
    claim: EnrollmentClaim,
    pepper: bytes,
    *,
    installation_session: str,
    hardware_fingerprint: str,
) -> bool:
    """Check stored claim bindings without exposing which input mismatched."""
    return (
        install_claim_binding_denial_category(
            claim,
            pepper,
            installation_session=installation_session,
            hardware_fingerprint=hardware_fingerprint,
        )
        is None
    )


def install_claim_binding_denial_category(
    claim: EnrollmentClaim,
    pepper: bytes,
    *,
    installation_session: str,
    hardware_fingerprint: str,
) -> EnrollmentDenialCategory | None:
    """Classify a bound-claim mismatch for internal audit only."""
    try:
        session_digest = _bound_digest(
            installation_session,
            pepper,
            _INSTALL_SESSION_CONTEXT,
        )
    except ValueError:
        return "installation_id"
    if not _digest_matches(session_digest, claim.installation_session_digest):
        return "installation_id"
    try:
        canonical_fingerprint = normalize_hardware_fingerprint(hardware_fingerprint)
        fingerprint_digest = _bound_digest(
            canonical_fingerprint,
            pepper,
            _FINGERPRINT_CONTEXT,
        )
    except ValueError:
        return "fingerprint"
    if not _digest_matches(fingerprint_digest, claim.fingerprint_digest):
        return "fingerprint"
    return None


def _bound_digest(value: str, pepper: bytes, context: bytes) -> str:
    return _digest(value, pepper, context)


def _digest_matches(actual: str, expected: str) -> bool:
    try:
        return hmac.compare_digest(actual, expected)
    except TypeError:
        return False


def _issue_token(marker: str) -> tuple[str, str]:
    identifier = secrets.token_hex(_IDENTIFIER_BYTES)
    secret = (
        base64.urlsafe_b64encode(secrets.token_bytes(_TOKEN_BYTES))
        .rstrip(b"=")
        .decode("ascii")
    )
    return identifier, f"{marker}{identifier}.{secret}"


def _aware_utc(value: datetime, name: str) -> datetime:
    if value.tzinfo is None:
        raise ValueError(f"{name} must be timezone-aware")
    return value.astimezone(UTC)


def _normalized_cidrs(values: Sequence[str]) -> list[str]:
    if isinstance(values, (str, bytes)) or not values:
        raise ValueError("at least one allowed CIDR is required")
    normalized: list[str] = []
    for value in values:
        try:
            network = ipaddress.ip_network(value, strict=True)
        except ValueError as error:
            raise ValueError("allowed CIDRs must be canonical networks") from error
        canonical = str(network)
        if canonical != value:
            raise ValueError("allowed CIDRs must be canonical networks")
        normalized.append(canonical)
    return sorted(set(normalized))


def _validated_text(
    value: str | None,
    *,
    name: str,
    maximum: int,
    required: bool,
) -> str | None:
    if value is None:
        if required:
            raise ValueError(f"{name} is required")
        return None
    if (
        not value
        or value != value.strip()
        or not value.isascii()
        or len(value) > maximum
        or any(ord(character) < 32 for character in value)
    ):
        raise ValueError(f"{name} must be bounded printable ASCII")
    return value


def issue_campaign(
    pepper: bytes,
    *,
    expires_at: datetime,
    max_uses: int,
    allowed_cidrs: Sequence[str],
    target_platform: str,
    policy: Mapping[str, object],
    label: str | None = None,
    site: str | None = None,
    owner_service_client_id: UUID | None = None,
    now: datetime | None = None,
) -> IssuedCampaign:
    """Create a bounded campaign record and return its raw bearer once."""
    issued_at = _aware_utc(now or datetime.now(UTC), "now")
    expiry = _aware_utc(expires_at, "campaign expiry")
    if expiry <= issued_at:
        raise ValueError("campaign expiry must be in the future")
    if not isinstance(max_uses, int) or isinstance(max_uses, bool) or max_uses <= 0:
        raise ValueError("campaign max uses must be positive")
    platform = _validated_text(
        target_platform, name="target platform", maximum=64, required=True
    )
    normalized_policy = dict(policy)
    validate_bounded_json(normalized_policy)
    identifier, token = _issue_token(_CAMPAIGN_MARKER)
    record = EnrollmentCampaign(
        id=uuid4(),
        campaign_identifier=identifier,
        token_digest=campaign_token_digest(token, pepper),
        expires_at=expiry,
        disabled_at=None,
        max_uses=max_uses,
        use_count=0,
        allowed_cidrs=_normalized_cidrs(allowed_cidrs),
        target_platform=platform,
        policy=normalized_policy,
        label=_validated_text(label, name="label", maximum=256, required=False),
        site=_validated_text(site, name="site", maximum=128, required=False),
        revoked_at=None,
        owner_service_client_id=owner_service_client_id,
    )
    return IssuedCampaign(token=token, record=record)


def issue_install_claim(
    campaign: EnrollmentCampaign,
    pepper: bytes,
    *,
    installation_session: str,
    hardware_fingerprint: str,
    expires_at: datetime,
    now: datetime | None = None,
) -> IssuedInstallClaim:
    """Create one expiring claim bound to an installation session and fingerprint."""
    issued_at = _aware_utc(now or datetime.now(UTC), "now")
    expiry = _aware_utc(expires_at, "claim expiry")
    if expiry <= issued_at:
        raise ValueError("claim expiry must be in the future")
    if not (
        campaign.revoked_at is None
        and campaign.disabled_at is None
        and campaign.expires_at is not None
        and campaign.expires_at.tzinfo is not None
        and issued_at < campaign.expires_at
        and campaign.use_count < campaign.max_uses
    ):
        raise EnrollmentDenied("Enrollment denied")
    if campaign.expires_at is None or campaign.expires_at.tzinfo is None:
        raise ValueError("campaign expiry must be timezone-aware")
    if expiry > campaign.expires_at.astimezone(UTC):
        raise ValueError("claim cannot outlive campaign")
    canonical_fingerprint = normalize_hardware_fingerprint(hardware_fingerprint)
    identifier, token = _issue_token(_CLAIM_MARKER)
    record = EnrollmentClaim(
        id=uuid4(),
        campaign_id=campaign.id,
        claim_identifier=identifier,
        claim_digest=claim_token_digest(token, pepper),
        installation_session_digest=_bound_digest(
            installation_session,
            pepper,
            _INSTALL_SESSION_CONTEXT,
        ),
        fingerprint_digest=_bound_digest(
            canonical_fingerprint,
            pepper,
            _FINGERPRINT_CONTEXT,
        ),
        expires_at=expiry,
        device_id=None,
        claimed_at=None,
    )
    return IssuedInstallClaim(token=token, record=record)


def campaign_request_matches(
    campaign: EnrollmentCampaign,
    *,
    now: datetime,
    source_address: IPv4Address | IPv6Address,
    platform: str,
) -> bool:
    """Validate immutable request context without considering remaining quota."""
    return (
        campaign_request_denial_category(
            campaign,
            now=now,
            source_address=source_address,
            platform=platform,
        )
        is None
    )


def campaign_request_denial_category(
    campaign: EnrollmentCampaign,
    *,
    now: datetime,
    source_address: IPv4Address | IPv6Address,
    platform: str,
) -> EnrollmentDenialCategory | None:
    """Classify immutable campaign context failures for internal audit only."""
    expiry = campaign.expires_at
    if campaign.revoked_at is not None or campaign.disabled_at is not None:
        return "campaign"
    if expiry is None or expiry.tzinfo is None:
        return "campaign"
    if now >= expiry:
        return "expired"
    if platform != campaign.target_platform:
        return "platform"
    try:
        networks = tuple(
            ipaddress.ip_network(value, strict=True) for value in campaign.allowed_cidrs
        )
    except ValueError:
        return "campaign"
    if not any(source_address in network for network in networks):
        return "cidr"
    return None


def _campaign_allows(
    campaign: EnrollmentCampaign,
    *,
    now: datetime,
    source_address: IPv4Address | IPv6Address,
    platform: str,
) -> bool:
    return campaign.use_count < campaign.max_uses and (
        campaign_request_denial_category(
            campaign,
            now=now,
            source_address=source_address,
            platform=platform,
        )
        is None
    )


async def reserve_campaign_use(
    session: AsyncSession,
    token: str,
    pepper: bytes,
    *,
    source_address: IPv4Address | IPv6Address,
    platform: str,
    actor_kind: str,
    actor_identifier: str | None,
    request_id: str,
    now: datetime | None = None,
) -> EnrollmentCampaign:
    """Lock and reserve one campaign use inside the caller's transaction."""
    checked_at = _aware_utc(now or datetime.now(UTC), "now")
    try:
        digest = campaign_token_digest(token, pepper)
    except ValueError as error:
        raise EnrollmentDenied("Enrollment denied") from error
    result = await session.execute(
        select(EnrollmentCampaign)
        .where(EnrollmentCampaign.token_digest == digest)
        .with_for_update()
    )
    campaign = result.scalar_one_or_none()
    if campaign is None:
        raise EnrollmentDenied("Enrollment denied", category="campaign")
    if campaign.use_count >= campaign.max_uses:
        raise EnrollmentDenied("Enrollment denied", category="campaign")
    category = campaign_request_denial_category(
        campaign,
        now=checked_at,
        source_address=source_address,
        platform=platform,
    )
    if category is not None:
        raise EnrollmentDenied("Enrollment denied", category=category)
    campaign.use_count += 1
    await append_audit_event(
        session,
        actor_kind=actor_kind,
        actor_identifier=actor_identifier,
        action="enrollment_campaign.use_reserved",
        object_kind="enrollment_campaign",
        object_identifier=str(campaign.id),
        request_id=request_id,
        details={
            "platform": platform,
            "source_address": str(source_address),
        },
        occurred_at=checked_at,
    )
    return campaign


async def revoke_campaign(
    session: AsyncSession,
    campaign_id: UUID,
    *,
    actor_kind: str = "admin",
    actor_identifier: str,
    request_id: str,
    now: datetime | None = None,
) -> EnrollmentCampaign:
    """Lock and revoke a campaign inside the caller's transaction."""
    revoked_at = _aware_utc(now or datetime.now(UTC), "now")
    result = await session.execute(
        select(EnrollmentCampaign)
        .where(EnrollmentCampaign.id == campaign_id)
        .with_for_update()
    )
    campaign = result.scalar_one_or_none()
    if campaign is None:
        raise EnrollmentDenied("Enrollment campaign not found")
    if campaign.revoked_at is None:
        campaign.revoked_at = revoked_at
        await append_audit_event(
            session,
            actor_kind=actor_kind,
            actor_identifier=actor_identifier,
            action="enrollment_campaign.revoked",
            object_kind="enrollment_campaign",
            object_identifier=str(campaign.id),
            request_id=request_id,
            details={},
            occurred_at=revoked_at,
        )
    return campaign


async def consume_install_claim(
    session: AsyncSession,
    token: str,
    pepper: bytes,
    *,
    installation_session: str,
    hardware_fingerprint: str,
    source_address: IPv4Address | IPv6Address,
    platform: str,
    actor_kind: str,
    actor_identifier: str | None,
    request_id: str,
    now: datetime | None = None,
) -> EnrollmentClaim:
    """Lock and consume one correctly bound install claim in the caller transaction."""
    checked_at = _aware_utc(now or datetime.now(UTC), "now")
    try:
        token_digest = claim_token_digest(token, pepper)
    except ValueError as error:
        raise EnrollmentDenied("Enrollment denied") from error
    claim_result = await session.execute(
        select(EnrollmentClaim)
        .where(EnrollmentClaim.claim_digest == token_digest)
        .with_for_update()
    )
    claim = claim_result.scalar_one_or_none()
    if claim is None or claim.claimed_at is not None:
        raise EnrollmentDenied("Enrollment denied", category="claim")
    if claim.expires_at.tzinfo is None:
        raise EnrollmentDenied("Enrollment denied", category="claim")
    if checked_at >= claim.expires_at:
        raise EnrollmentDenied("Enrollment denied", category="expired")
    category = install_claim_binding_denial_category(
        claim,
        pepper,
        installation_session=installation_session,
        hardware_fingerprint=hardware_fingerprint,
    )
    if category is not None:
        raise EnrollmentDenied("Enrollment denied", category=category)
    campaign_result = await session.execute(
        select(EnrollmentCampaign)
        .where(EnrollmentCampaign.id == claim.campaign_id)
        .with_for_update()
    )
    campaign = campaign_result.scalar_one_or_none()
    if campaign is None:
        raise EnrollmentDenied("Enrollment denied", category="campaign")
    if campaign.use_count >= campaign.max_uses:
        raise EnrollmentDenied("Enrollment denied", category="campaign")
    category = campaign_request_denial_category(
        campaign,
        now=checked_at,
        source_address=source_address,
        platform=platform,
    )
    if category is not None:
        raise EnrollmentDenied("Enrollment denied", category=category)
    claim.claimed_at = checked_at
    campaign.use_count += 1
    await append_audit_event(
        session,
        actor_kind=actor_kind,
        actor_identifier=actor_identifier,
        action="enrollment_claim.consumed",
        object_kind="enrollment_claim",
        object_identifier=str(claim.id),
        request_id=request_id,
        details={},
        occurred_at=checked_at,
    )
    return claim
