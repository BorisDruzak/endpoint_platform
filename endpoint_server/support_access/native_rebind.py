"""One-use native reinstall capability, never an administrator reset shortcut."""
from datetime import timedelta
from sqlalchemy import select
from endpoint_server.installation_lifecycle.models import InstallationState
from .service import utc
from .platforms import installation_defaults,set_principal
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
    if row.platform=='linux_amd64':
        return await consume_linux_native_ticket(session,row,ticket,now,request_id)
    deadline=ticket.support_rebind_until
    ticket.support_rebind_until=None
    # Prior manual principal/keys remain as configuration, with access disabled.
    row.enabled=False;row.expires_at=None;row.revoked_at=None;row.generation+=1;row.revision+=1
    row.installed=False;row.tunnel_connected=False;row.reported_at=None;row.last_error_code=None
    row.component_version='1.0.0';row.access_verified_at=None;row.access_verified_by=None
    row.installation_access_pending_until=None
    await installation_audit(session,row,'native_rebound',request_id=request_id,
        details={'event_id':str(ticket.event_id),'generation_id':str(ticket.generation_id)})
    if not ticket.support_auto_eligible or settings is None or not installation_defaults(settings,row.platform).enabled:
        return
    await key_authority_lock(session)
    if await operator_roles_conflict(session,settings,row.platform):
        return
    defaults=installation_defaults(settings,row.platform)
    row.operator_public_keys=list(defaults.keys)
    set_principal(row,defaults.username,defaults.uid)
    row.installation_access_pending_until=utc(deadline)
    await installation_audit(session,row,'pending',request_id=request_id,
        details={'pending_until':row.installation_access_pending_until.isoformat(),'defaults_digest':defaults_digest(settings,row.platform),
            'native_event_id':str(ticket.event_id)})


def linux_lease_binding(row):
    """Exact approved configuration; no defaults or new authorization deadline."""
    from .platforms import principal_bound
    if not row.expires_at or not row.operator_public_keys or not principal_bound(row):
        return None
    return {'expires_at':utc(row.expires_at).isoformat(),'source_credential_id':str(row.source_credential_id),
        'linux_admin_username':row.linux_admin_username,'linux_admin_uid':row.linux_admin_uid,
        'operator_public_keys':list(row.operator_public_keys)}


def capture_linux_lease(row,now):
    if not row.enabled or row.revoked_at is not None or row.reset_registration_allowed or not row.expires_at or utc(row.expires_at)<=now:
        return None
    return linux_lease_binding(row)


async def linux_lease_may_resume(session,row,now):
    from endpoint_server.db.models import AuditEvent
    from .service import source_active
    if not row.expires_at or utc(row.expires_at)<=now or not await source_active(session,row,now):
        return False
    if capture_linux_lease(row,now) is not None:
        # Offline removal retained the actual enabled policy. Native ticket
        # revision/generation/credential checks prove no intervening decision.
        return True
    if row.enabled or row.revoked_at is None or row.reset_registration_allowed:
        return False
    # Online unregister disables the component before the native events arrive.
    # Only its authenticated exact pre-removal binding can resume that lease.
    events=(await session.scalars(select(AuditEvent).where(AuditEvent.object_kind=='support_access',
        AuditEvent.object_identifier==str(row.id),AuditEvent.action=='support_access.component_removed')
        .order_by(AuditEvent.created_at.desc(),AuditEvent.id.desc()).limit(1000))).all()
    current=[event for event in events if event.details.get('revision')==row.revision]
    return bool(len(current)==1 and current[0].details.get('generation')==row.generation and
        current[0].details.get('source_credential_id')==str(row.source_credential_id) and
        current[0].details.get('linux_removal_revoked_at')==utc(row.revoked_at).isoformat() and
        current[0].details.get('linux_prior_lease') is not None and
        current[0].details.get('linux_prior_lease')==linux_lease_binding(row))


async def consume_linux_native_ticket(session,row,ticket,now,request_id):
    from .disabled_intent import linux_disabled_authority,inherited_disabled_intent
    disabled_intent=inherited_disabled_intent(row,await linux_disabled_authority(session,row))
    resume=await linux_lease_may_resume(session,row,now)
    ticket.support_rebind_until=None
    # Preserve the original expiry and approved principal/operator keys even
    # when expired or disabled. Rebinding keys is never a lease renewal.
    row.enabled=resume;row.revoked_at=None;row.generation+=1;row.revision+=1
    row.installed=False;row.tunnel_connected=False;row.reported_at=None;row.last_error_code=None
    row.component_version='1.0.0';row.access_verified_at=None;row.access_verified_by=None
    row.installation_access_pending_until=None
    await installation_audit(session,row,'native_rebound',request_id=request_id,
        details={'event_id':str(ticket.event_id),'generation_id':str(ticket.generation_id),
            'linux_lease_resumed':resume,'original_expires_at':utc(row.expires_at).isoformat() if row.expires_at else None,
            'linux_disabled_intent':disabled_intent})
