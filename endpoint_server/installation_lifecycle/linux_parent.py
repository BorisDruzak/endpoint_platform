"""Explicit legacy Linux history adapter; never manufactures a prior request."""
from sqlalchemy import select

from endpoint_server.db.models import EnrollmentClaim, EnrollmentCampaign
from endpoint_server.enrollment.linux_requests import validate_linux_request
from endpoint_server.support_access.platforms import LINUX, verified_platform


async def matching_linux_previous_claim(session, record, previous_device_id):
    """Both sides are derived with the canonical Claim-domain public builder.

    The fresh source-qualified request retained that digest at intake, separately
    from its Request-domain digest. Existing156 may have no Request FK at all.
    """
    binding = await validate_linux_request(session, record)
    if await verified_platform(session, previous_device_id) != LINUX:
        return None
    return await session.scalar(select(EnrollmentClaim.id).join(EnrollmentCampaign,
        EnrollmentCampaign.id == EnrollmentClaim.campaign_id).where(
            EnrollmentClaim.device_id == previous_device_id,
            EnrollmentClaim.claimed_at.is_not(None),
            EnrollmentClaim.fingerprint_digest == binding.claim_fingerprint_digest,
            EnrollmentCampaign.target_platform == 'linux',
        ).limit(1).with_for_update(of=EnrollmentClaim))
