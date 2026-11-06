"""One-use native reinstall capability, never an administrator reset shortcut."""
from datetime import timedelta
from sqlalchemy import select
from endpoint_server.installation_lifecycle.models import InstallationState
from .service import utc
from .installation import installation_audit,defaults_digest,key_authority_lock,operator_roles_conflict


async def native_ticket(session,row,credential_id,now):
    state=await session.scalar(select(InstallationState).where(InstallationState.device_id==row.device_id).with_for_update())
    if state is None or state.state!='installed' or state.support_rebind_until is None:
        return None
    if (utc(state.support_rebind_until)<=now or state.support_revision!=row.revision or
        state.support_generation!=row.generation or state.support_credential_id!=credential_id or
        row.source_credential_id!=credential_id or row.reset_registration_allowed):
        state.support_rebind_until=None
        return None
    return state


async def consume_native_ticket(session,row,ticket,settings,now,request_id):
    deadline=ticket.support_rebind_until
    ticket.support_rebind_until=None
    # Prior manual principal/keys remain as configuration, with access disabled.
    row.enabled=False;row.expires_at=None;row.revoked_at=None;row.generation+=1;row.revision+=1
    row.installed=False;row.tunnel_connected=False;row.reported_at=None;row.last_error_code=None
    row.component_version='1.0.0';row.access_verified_at=None;row.access_verified_by=None
    row.installation_access_pending_until=None
    await installation_audit(session,row,'native_rebound',request_id=request_id,
        details={'event_id':str(ticket.event_id),'generation_id':str(ticket.generation_id)})
    if not ticket.support_auto_eligible or settings is None or not settings.support_install_auto_enable:
        return
    await key_authority_lock(session)
    if await operator_roles_conflict(session,settings):
        return
    row.operator_public_keys=list(settings.support_install_operator_public_keys)
    row.windows_admin_username=settings.support_install_windows_admin_username
    row.installation_access_pending_until=utc(deadline)
    await installation_audit(session,row,'pending',request_id=request_id,
        details={'pending_until':row.installation_access_pending_until.isoformat(),'defaults_digest':defaults_digest(settings),
            'native_event_id':str(ticket.event_id)})
