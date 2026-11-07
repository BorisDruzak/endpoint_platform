"""Persisted platform and explicit principal selection; never trust a route body."""
from dataclasses import dataclass
from sqlalchemy import select
from pydantic import ValidationError
from endpoint_contracts.context import DeviceContextEnvelopeV1
from endpoint_server.db.models import EnrollmentCampaign, EnrollmentClaim, EnrollmentRequest
from endpoint_server.context.models import ContextCurrent, ContextSnapshot

WINDOWS = 'windows_amd64'
LINUX = 'linux_amd64'


async def verified_platform(session, device_id, *, credential_id=None, native_source=None):
    """Consumed enrollment and canonical inventory must agree on exact platform."""
    claims=(await session.execute(select(EnrollmentCampaign.target_platform, EnrollmentClaim.enrollment_request_id, EnrollmentRequest.platform)
        .join(EnrollmentClaim, EnrollmentClaim.campaign_id==EnrollmentCampaign.id)
        .outerjoin(EnrollmentRequest, (EnrollmentRequest.id==EnrollmentClaim.enrollment_request_id) &
            (EnrollmentRequest.device_id==EnrollmentClaim.device_id))
        .where(EnrollmentClaim.device_id==device_id,EnrollmentClaim.claimed_at.is_not(None)).limit(101))).all()
    if not claims or len(claims)>100:
        return None
    enrolled=set()
    for campaign, request_id, request in claims:
        if request_id is not None and request is None:
            return None
        value={'linux':LINUX,'linux_amd64':LINUX,'windows':WINDOWS,'windows_amd64':WINDOWS}.get(campaign)
        if value is None or (request is not None and {'linux':LINUX,'linux_amd64':LINUX,'windows':WINDOWS,'windows_amd64':WINDOWS}.get(request)!=value):
            return None
        enrolled.add(value)
    snapshots=(await session.execute(select(ContextCurrent.profile,ContextSnapshot.normalized_projection)
        .outerjoin(ContextSnapshot,(ContextCurrent.snapshot_id==ContextSnapshot.id) &
            (ContextCurrent.device_id==ContextSnapshot.device_id) & (ContextCurrent.profile==ContextSnapshot.profile))
        .where(ContextCurrent.device_id==device_id,ContextCurrent.profile.in_(['baseline_v1','inventory_v1'])))).all()
    observed=set()
    for profile,payload in snapshots:
        try:
            envelope=DeviceContextEnvelopeV1.model_validate(payload)
        except (ValidationError,TypeError):
            return None
        if envelope.profile!=profile:
            return None
        system=envelope.sections.system
        if system.platform not in ('linux','windows') or system.architecture!='x86_64':
            return None
        observed.add(LINUX if system.platform=='linux' else WINDOWS)
    if not snapshots and enrolled == {LINUX}:
        from endpoint_server.enrollment.linux_requests import has_linux_bootstrap_binding
        if await has_linux_bootstrap_binding(session, device_id, credential_id=credential_id, native_source=native_source):
            return LINUX
    return next(iter(enrolled)) if len(enrolled)==1 and enrolled==observed else None


def principal_bound(row):
    if getattr(row,'platform',WINDOWS)==LINUX:
        return bool(row.linux_admin_username and row.linux_admin_uid is not None and row.windows_admin_username is None)
    return bool(row.windows_admin_username)


@dataclass(frozen=True)
class InstallationDefaults:
    enabled: bool
    keys: tuple
    username: str
    uid: int | None
    hours: float


def installation_defaults(settings, platform=WINDOWS):
    if platform==LINUX:
        return InstallationDefaults(settings.support_linux_install_auto_enable,
            settings.support_linux_install_operator_public_keys,settings.support_linux_install_admin_username,
            settings.support_linux_install_admin_uid,settings.support_linux_install_access_hours)
    return InstallationDefaults(settings.support_install_auto_enable,settings.support_install_operator_public_keys,
        settings.support_install_windows_admin_username,None,settings.support_install_access_hours)


def set_principal(row,username,uid=None):
    if getattr(row,'platform',WINDOWS)==LINUX:
        row.linux_admin_username=username or None; row.linux_admin_uid=uid
        row.windows_admin_username=None
    else:
        row.windows_admin_username=username or None


def principal_matches(row,defaults):
    if getattr(row,'platform',WINDOWS)==LINUX:
        return row.linux_admin_username==defaults.username and row.linux_admin_uid==defaults.uid and row.windows_admin_username is None
    return row.windows_admin_username==defaults.username
