"""Native facts commit only inside the caller's locked DeviceBearer transaction."""
from datetime import UTC, datetime, timedelta
from uuid import uuid4
from sqlalchemy import select
from endpoint_contracts.installation_lifecycle import InstallationEventAckV1
from endpoint_server.audit.service import append_audit_event
from endpoint_server.db.models import AuditEvent, Device, WindowsSetupRelease
from endpoint_server.support_access.models import SupportAccess
from endpoint_server.support_access.service import utc
from .models import InstallationEvent, InstallationState


class InstallationConflict(ValueError):
    pass


async def removed(session, device_id):
    return await session.scalar(select(InstallationState.state).where(InstallationState.device_id == device_id)) == 'removed'


async def support_snapshot(session, projection, credential_id):
    projection.support_revision = None
    projection.support_generation = None
    projection.support_credential_id = None
    projection.support_auto_eligible = False
    projection.support_rebind_until = None
    row = await session.scalar(select(SupportAccess).where(SupportAccess.device_id == projection.device_id).with_for_update())
    if row is None or row.source_credential_id != credential_id or row.reset_registration_allowed:
        return
    events = (await session.scalars(select(AuditEvent).where(AuditEvent.object_kind == 'support_access',
        AuditEvent.object_identifier == str(row.id), AuditEvent.action.in_([
            'support_access.component_removed', 'support_access.policy_changed', 'support_access.revoked',
            'support_access.registration_reset_authorized', 'support_access.installation_access_granted']))
        .order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc()).limit(1000))).all()
    component_removed = any(e.action == 'support_access.component_removed' and e.details.get('revision') == row.revision for e in events)
    # An offline uninstaller may remove owned keys without delivering unregister.
    # Only an explicit current manual disable proves this is disabled access,
    # rather than an ambiguous historical refusal/revocation. Never infer False
    # from a missing field, a numeric zero, or a prior policy revision.
    explicitly_disabled = not row.enabled and row.revoked_at is None and any(
        e.action == 'support_access.policy_changed' and e.details.get('revision') == row.revision
        and e.details.get('enabled') is False for e in events)
    if row.platform == 'linux_amd64':
        from endpoint_server.support_access.disabled_intent import linux_disabled_authority
        explicitly_disabled = await linux_disabled_authority(session, row) is not None
    if not component_removed and not (row.revoked_at is None and row.enabled) and not explicitly_disabled:
        return
    projection.support_revision = row.revision
    projection.support_generation = row.generation
    projection.support_credential_id = credential_id
    grants = [e for e in events if e.action == 'support_access.installation_access_granted']
    if grants and not explicitly_disabled:
        grant = grants[0]
        projection.support_auto_eligible = not any(e.action in (
            'support_access.policy_changed', 'support_access.revoked', 'support_access.registration_reset_authorized')
            and e.created_at >= grant.created_at for e in events)


async def resolve_windows_source(session,proof):
    from endpoint_contracts.installation_lifecycle import InstallationNativeProof
    if not isinstance(proof,InstallationNativeProof):
        raise InstallationConflict('Windows native proof required')
    release = await session.scalar(select(WindowsSetupRelease).where(
        WindowsSetupRelease.agent_version == proof.version,
        WindowsSetupRelease.msi_sha256 == proof.msi_sha256,
        WindowsSetupRelease.msi_source_commit == proof.source_revision,
        WindowsSetupRelease.product_code == proof.product_code,
        WindowsSetupRelease.authenticode_status == 'valid',
        WindowsSetupRelease.msi_authenticode_status == 'valid',
        WindowsSetupRelease.retired_at.is_(None)).limit(1))
    if release is None:
        raise InstallationConflict('Native source is not an exact registered Windows release')
    return release


async def accept_event(session, principal, body, *, request_id, now=None, source_resolver=None):
    now = now or datetime.now(UTC)
    if body.device_id != principal.device.id:
        raise InstallationConflict('Event identity does not match authenticated device')
    # Caller locks/revalidates Device then credential first. All events serialize
    # even when no projection row exists yet; retries cannot create a second head.
    existing = await session.get(InstallationEvent, body.event_id)
    payload = body.model_dump(mode='json')
    if existing:
        if existing.device_id != body.device_id or existing.payload != payload:
            raise InstallationConflict('Event identity already has different content')
        return InstallationEventAckV1.model_validate(existing.acknowledgement)
    projection = await session.scalar(select(InstallationState).where(InstallationState.device_id == body.device_id).with_for_update())
    if projection:
        if (body.generation_id != projection.generation_id or body.sequence != projection.sequence + 1
            or body.previous_event_id != projection.event_id):
            raise InstallationConflict('Event does not extend the current causal stream')
    elif body.sequence != 1:
        raise InstallationConflict('First event must begin a causal stream')
    proof = body.native
    await (source_resolver or resolve_windows_source)(session,proof)
    ack = InstallationEventAckV1(schema_version='endpoint_installation_event_ack_v1',device_id=body.device_id,
        event_id=body.event_id,generation_id=body.generation_id,sequence=body.sequence,state=body.action,received_at=now)
    event = InstallationEvent(id=body.event_id,device_id=body.device_id,source_credential_id=principal.credential.id,
        generation_id=body.generation_id,sequence=body.sequence,previous_event_id=body.previous_event_id,action=body.action,
        occurred_at=body.occurred_at,received_at=now,payload=payload,acknowledgement=ack.model_dump(mode='json'))
    session.add(event)
    await session.flush()
    previous_state = projection.state if projection else None
    if projection is None:
        projection = InstallationState(device_id=body.device_id,generation_id=body.generation_id,sequence=body.sequence,
            event_id=body.event_id,state=body.action,received_at=now,support_auto_eligible=False)
        session.add(projection)
    else:
        projection.sequence=body.sequence; projection.event_id=body.event_id
        projection.state=body.action; projection.received_at=now
    if body.action == 'removed':
        await support_snapshot(session, projection, principal.credential.id)
    elif previous_state == 'removed' and projection.support_credential_id == principal.credential.id:
        row = await session.scalar(select(SupportAccess).where(SupportAccess.device_id == body.device_id).with_for_update())
        if row and row.revision == projection.support_revision and row.generation == projection.support_generation and not row.reset_registration_allowed:
            projection.support_rebind_until = now + timedelta(minutes=15)
    elif body.action == 'installed':
        projection.support_rebind_until = None
    # Ordinary installed polling or upgrades never renew an outstanding ticket.
    await append_audit_event(session, actor_kind='device',actor_identifier=str(body.device_id),
        action='installation.'+body.action,object_kind='installation_event',object_identifier=str(body.event_id),
        request_id=request_id,details={'device_id':str(body.device_id),'generation_id':str(body.generation_id),
            'sequence':body.sequence,'version':proof.version,'cleanup':body.cleanup.model_dump()},occurred_at=now)
    await session.flush()
    return ack


async def projection_data(session, device_id, *, include_parent=False):
    row = await session.scalar(select(InstallationState).where(InstallationState.device_id == device_id))
    from .models import InstallationParent
    from endpoint_server.db.models import EnrollmentRequest
    parent=None
    if include_parent:
        parent=await session.scalar(select(InstallationParent.previous_device_id).join(EnrollmentRequest,
            EnrollmentRequest.id==InstallationParent.enrollment_request_id).where(EnrollmentRequest.device_id==device_id).limit(1))
    data={'state':'unknown','event_id':None,'received_at':None} if row is None else {
        'state':row.state,'event_id':str(row.event_id),'received_at':row.received_at}
    data['previous_device_id']=str(parent) if parent else None
    return data


def connection_conflicts_with_removal(state, last_seen_at, received_at):
    """A pre-removal heartbeat still in the presence TTL is not new evidence."""
    return bool(state == 'removed' and last_seen_at is not None and received_at is not None
        and utc(last_seen_at) > utc(received_at))
