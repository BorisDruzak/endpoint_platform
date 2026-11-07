"""Source-qualified Linux adapter over canonical enrollment authority."""
from datetime import UTC, datetime
from ipaddress import ip_address
import hmac

from sqlalchemy import select, cast, String

from endpoint_contracts.linux_enrollment import LinuxEnrollmentPolicyV1
from endpoint_contracts.linux_installation_lifecycle import LinuxNativeSource
from endpoint_server.installation_lifecycle.linux_sources import LinuxNativeRelease
from endpoint_server.db.models import EnrollmentCampaign, EnrollmentClaim, EnrollmentRequest, DeviceCredential
from .linux_models import LinuxEnrollmentBinding
from .campaigns import campaign_request_matches, hardware_fingerprint_digest, EnrollmentDenied
from .requests import CampaignSelection, build_enrollment_request, request_bindings_match


def linux_policy(campaign):
    if campaign.target_platform != 'linux':
        return None
    try:
        return LinuxEnrollmentPolicyV1.model_validate(campaign.policy)
    except (ValueError, TypeError):
        return None


def select_linux_campaign(campaigns, *, source_id, source_address, now, blocking_identity_conflict=False):
    eligible = []
    for campaign in campaigns:
        policy = linux_policy(campaign)
        if (policy and source_id in policy.allowed_native_releases and campaign.use_count < campaign.max_uses
            and campaign_request_matches(campaign, now=now, source_address=source_address, platform='linux')):
            eligible.append((campaign, policy))
    if len(eligible) != 1:
        return CampaignSelection('review_required', None, 'NO_MATCHING_CAMPAIGN' if not eligible else 'AMBIGUOUS_CAMPAIGN')
    campaign, policy = eligible[0]
    evidence = dict(policy_id=policy.policy_id, enrollment_mode=policy.enrollment_mode,
        source_network_match=True, release_match=True, identity_conflict=blocking_identity_conflict)
    if blocking_identity_conflict:
        return CampaignSelection('review_required', campaign, 'DUPLICATE_IDENTITY', **evidence)
    if policy.enrollment_mode == 'manual':
        return CampaignSelection('waiting_approval', campaign, 'MANUAL_POLICY', **evidence)
    return CampaignSelection('auto_approved', campaign, 'AUTO_POLICY', **evidence)


def linux_campaign_allows(record, campaign, *, now, consumed=False):
    policy = linux_policy(campaign)
    try:
        from uuid import UUID
        source_id = UUID(record.installer_release_id)
        address = ip_address(record.source_address)
    except (TypeError, ValueError):
        return False
    return bool(record.platform == 'linux' and record.selected_campaign_id == campaign.id and policy
        and source_id in policy.allowed_native_releases and (consumed or campaign.use_count < campaign.max_uses)
        and campaign_request_matches(campaign, now=now, source_address=address, platform='linux'))


async def resolve_enrollment_source(session, source):
    if type(source) is not LinuxNativeSource:
        raise EnrollmentDenied('Exact Linux source required')
    row = await session.scalar(select(LinuxNativeRelease).where(LinuxNativeRelease.retired_at.is_(None),
        *(getattr(LinuxNativeRelease, key) == value for key, value in source.model_dump().items())).with_for_update())
    if row is None:
        raise EnrollmentDenied('Exact registered Linux source required')
    return row


def build_linux_request(body, *, source_id, selection, source_address, pepper, now):
    values = body.model_dump(exclude={'schema_version', 'platform', 'native', 'requested_at'})
    record = build_enrollment_request(**values, installer_version=body.native.version,
        installer_release_id=str(source_id), selection=selection, source_address=source_address, pepper=pepper, now=now)
    record.platform = 'linux'
    binding = LinuxEnrollmentBinding(enrollment_request_id=record.id, native_release_id=source_id,
        claim_fingerprint_digest=hardware_fingerprint_digest(body.hardware_fingerprint, pepper))
    return record, binding


async def validate_linux_request(session, record, *, body=None, pepper=None):
    binding = await session.scalar(select(LinuxEnrollmentBinding).where(
        LinuxEnrollmentBinding.enrollment_request_id == record.id).with_for_update())
    source = None if binding is None else await session.scalar(select(LinuxNativeRelease).where(
        LinuxNativeRelease.id == binding.native_release_id).with_for_update())
    if (record.platform != 'linux' or binding is None or source is None or source.retired_at is not None
        or record.installer_release_id != str(source.id) or record.installer_version != source.version):
        raise EnrollmentDenied('Linux request source is unavailable')
    if body is not None and (body.platform != 'linux' or not request_bindings_match(record,
        installation_id=body.installation_id, hardware_fingerprint=body.hardware_fingerprint, pepper=pepper)
        or not hmac.compare_digest(binding.claim_fingerprint_digest, hardware_fingerprint_digest(body.hardware_fingerprint, pepper))):
        raise EnrollmentDenied('Linux request binding mismatch')
    return binding


async def bind_linux_enrollment(session, record, claim, credential, *, body, pepper, now):
    binding = await validate_linux_request(session, record, body=body, pepper=pepper)
    if (claim.enrollment_request_id != record.id or claim.device_id != record.device_id
        or credential.device_id != record.device_id or claim.claimed_at is None
        or not hmac.compare_digest(binding.claim_fingerprint_digest, claim.fingerprint_digest)
        or binding.claim_id is not None or binding.credential_id is not None):
        raise EnrollmentDenied('Linux enrollment authority mismatch')
    binding.claim_id = claim.id
    binding.credential_id = credential.id


async def has_linux_bootstrap_binding(session, device_id, *, credential_id=None, native_source=None):
    now = datetime.now(UTC)
    stmt = (select(LinuxEnrollmentBinding.id).join(EnrollmentRequest,
        EnrollmentRequest.id == LinuxEnrollmentBinding.enrollment_request_id)
        .join(LinuxNativeRelease, LinuxNativeRelease.id == LinuxEnrollmentBinding.native_release_id)
        .join(EnrollmentClaim, EnrollmentClaim.id == LinuxEnrollmentBinding.claim_id)
        .join(DeviceCredential, DeviceCredential.id == LinuxEnrollmentBinding.credential_id)
        .join(EnrollmentCampaign, EnrollmentCampaign.id == EnrollmentClaim.campaign_id)
        .where(EnrollmentRequest.device_id == device_id, EnrollmentRequest.platform == 'linux',
            EnrollmentRequest.installer_version == LinuxNativeRelease.version,
            EnrollmentRequest.installer_release_id == cast(LinuxNativeRelease.id, String),
            EnrollmentRequest.status.in_(['device_registered','waiting_wss','completed']),
            EnrollmentRequest.selected_campaign_id == EnrollmentClaim.campaign_id,
            EnrollmentClaim.enrollment_request_id == EnrollmentRequest.id,
            EnrollmentClaim.device_id == device_id, EnrollmentClaim.claimed_at.is_not(None),
            EnrollmentClaim.fingerprint_digest == LinuxEnrollmentBinding.claim_fingerprint_digest,
            EnrollmentCampaign.target_platform == 'linux', LinuxNativeRelease.retired_at.is_(None),
            DeviceCredential.device_id == device_id, DeviceCredential.revoked_at.is_(None),
            (DeviceCredential.expires_at.is_(None) | (DeviceCredential.expires_at > now))))
    if credential_id is not None:
        stmt = stmt.where(DeviceCredential.id == credential_id)
    if native_source is not None:
        if not isinstance(native_source, LinuxNativeSource):
            return False
        stmt = stmt.where(*(getattr(LinuxNativeRelease, key) == value
            for key, value in native_source.model_dump(exclude={'exit_code'}).items()))
    return await session.scalar(stmt.limit(1)) is not None
