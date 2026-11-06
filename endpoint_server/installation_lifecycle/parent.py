"""Explicit historical relation; never consumes or copies the previous identity."""
from fastapi import HTTPException
from sqlalchemy import select
from endpoint_server.audit.service import append_audit_event
from endpoint_server.audit.request_ids import audit_request_id
from endpoint_server.auth.admin_sessions import _load_admin_principal,ADMIN_SESSION_COOKIE
from endpoint_server.db.models import Device,EnrollmentClaim,AdminUser,AdminSession
from .models import InstallationParent,InstallationState


async def link_previous_installation(session,record,previous_device_id,principal,request):
    previous=await session.scalar(select(Device).where(Device.id==previous_device_id).with_for_update())
    state=await session.scalar(select(InstallationState).where(InstallationState.device_id==previous_device_id).with_for_update())
    matching=await session.scalar(select(EnrollmentClaim.id).where(EnrollmentClaim.device_id==previous_device_id,
        EnrollmentClaim.fingerprint_digest==record.fingerprint_digest,EnrollmentClaim.claimed_at.is_not(None)).limit(1))
    if (record.status != 'approved' or previous is None or previous.retired_at is not None
        or state is None or state.state!='removed' or matching is None or record.device_id==previous_device_id):
        raise HTTPException(409,'Previous installation does not match a committed removal')
    await session.scalar(select(AdminUser).where(AdminUser.id==principal.user.id).with_for_update().execution_options(populate_existing=True))
    await session.scalar(select(AdminSession).where(AdminSession.id==principal.session.id).with_for_update().execution_options(populate_existing=True))
    fresh=await _load_admin_principal(session,request.cookies.get(ADMIN_SESSION_COOKIE,''),request.app.state.settings.session_secret,
        request=request,commit_revalidation=False)
    if fresh is None or fresh.user.id!=principal.user.id or fresh.session.id!=principal.session.id:
        raise HTTPException(401,'Administrator authority changed')
    session.add(InstallationParent(enrollment_request_id=record.id,previous_device_id=previous_device_id,
        removed_event_id=state.event_id,approved_by=principal.user.id))
    await append_audit_event(session,actor_kind='admin',actor_identifier=str(principal.user.id),action='installation.previous_linked',
        object_kind='enrollment_request',object_identifier=str(record.id),request_id=audit_request_id(request),
        details={'previous_device_id':str(previous_device_id),'removed_event_id':str(state.event_id)})
