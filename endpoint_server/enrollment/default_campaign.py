"""Transactional inclusion of trusted Windows publications in one auto campaign."""
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select, text

from endpoint_contracts.enrollment import WindowsEnrollmentPolicyV1
from endpoint_server.audit.service import append_audit_event
from endpoint_server.db.models import EnrollmentCampaign, WindowsSetupRelease
from .campaigns import parse_windows_enrollment_policy


async def lock_campaign_set(session) -> None:
    """Serialize publication with campaign creation/configuration on PostgreSQL."""
    if session.get_bind().dialect.name == 'postgresql':
        await session.execute(text('SELECT pg_advisory_xact_lock(728019456102)'))


async def _plan_windows_release_inclusion(session, release, *, campaign_id, now, lock):
    explicit_now = now
    now = now or datetime.now(UTC)
    if (release.retired_at is not None or release.authenticode_status != 'valid'
            or release.msi_authenticode_status != 'valid'):
        raise ValueError('automatic enrollment requires a trusted active Setup release')
    query = select(EnrollmentCampaign).where(
        EnrollmentCampaign.target_platform == 'windows',
        EnrollmentCampaign.disabled_at.is_(None), EnrollmentCampaign.revoked_at.is_(None),
        EnrollmentCampaign.expires_at > now)
    query = query.order_by(EnrollmentCampaign.id)
    if lock:
        await lock_campaign_set(session)
        query = query.with_for_update()
    rows = (await session.scalars(query)).all()
    candidates = [(row, parse_windows_enrollment_policy(row.policy)) for row in rows]
    candidates = [(row, policy) for row, policy in candidates
                  if policy is not None and policy.enrollment_mode == 'auto']
    if len(candidates) != 1 or (campaign_id is not None and candidates[0][0].id != campaign_id):
        raise ValueError('one active default Windows auto-enrollment campaign is required')
    campaign, policy = candidates[0]
    checked_at = explicit_now or datetime.now(UTC)
    if campaign.expires_at <= checked_at or campaign.use_count >= campaign.max_uses:
        raise ValueError('default auto-enrollment campaign is expired or exhausted')
    if release.version in policy.allowed_installer_releases:
        return campaign, None, now
    updated = WindowsEnrollmentPolicyV1.model_validate({**policy.model_dump(),
        'allowed_installer_releases': [*policy.allowed_installer_releases, release.version]})
    return campaign, updated, now


async def preview_windows_release_inclusion(session, release: WindowsSetupRelease, *,
        campaign_id: UUID | None = None) -> dict:
    campaign, updated, _ = await _plan_windows_release_inclusion(session, release,
        campaign_id=campaign_id, now=None, lock=False)
    return {'campaign_id': str(campaign.id), 'already_included': updated is None}


async def include_windows_release(session, release: WindowsSetupRelease, *,
        campaign_id: UUID | None = None, now: datetime | None = None) -> bool:
    """Append to the unique live auto campaign without changing its authority."""
    campaign, updated, now = await _plan_windows_release_inclusion(session, release,
        campaign_id=campaign_id, now=now, lock=True)
    if updated is None:
        return False
    campaign.policy = updated.model_dump(mode='json')
    await append_audit_event(session, actor_kind='operator', actor_identifier='windows-release-publisher',
        action='enrollment_campaign.release_included', object_kind='enrollment_campaign',
        object_identifier=str(campaign.id), request_id=f'publish-{release.id}',
        details={'setup_release_id': str(release.id), 'installer_release_id': release.version,
                 'source_scope_quota_and_expiry_preserved': True}, occurred_at=now)
    await session.flush()
    return True
