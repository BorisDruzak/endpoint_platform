"""One-shot installation authorization under the registration and key-role locks."""
from datetime import timedelta
import hashlib
import json
from uuid import uuid4

from sqlalchemy import or_, select

from endpoint_server.audit.service import append_audit_event
from endpoint_server.db.models import AuditEvent
from .models import SupportAccess
from .service import domain_principal_available, key_authority_lock, source_active, utc


def defaults_digest(settings):
    payload = [sorted(settings.support_install_operator_public_keys),
        settings.support_install_windows_admin_username, float(settings.support_install_access_hours),
        settings.support_gateway_host, settings.support_gateway_port, settings.support_gateway_host_public_key]
    return hashlib.sha256(json.dumps(payload, separators=(',', ':'), ensure_ascii=True).encode('ascii')).hexdigest()


async def installation_audit(session, row, action, *, request_id=None, reason=None, details=None,
                             actor_kind='device', actor_identifier=None):
    values = {'device_id': str(row.device_id), 'revision': row.revision}
    if reason is not None:
        values['reason'] = reason
    values.update(details or {})
    await append_audit_event(session, actor_kind=actor_kind, actor_identifier=str(actor_identifier or row.device_id),
        action='support_access.installation_access_'+action, object_kind='support_access',
        object_identifier=str(row.id), request_id=request_id or str(uuid4()), details=values)


async def cancel_installation_access(session, row, reason, *, request_id=None, increment_revision=True, expired=False,
                                     actor_kind='system', actor_identifier='support_install_defaults'):
    if row.installation_access_pending_until is None:
        return
    row.installation_access_pending_until = None
    if increment_revision:
        row.revision += 1
    await installation_audit(session, row, 'expired' if expired else 'cancelled', request_id=request_id, reason=reason,
        actor_kind=actor_kind, actor_identifier=actor_identifier)


async def operator_roles_conflict(session, settings):
    keys = settings.support_install_operator_public_keys
    return bool(await session.scalar(select(SupportAccess.id).where(or_(
        SupportAccess.tunnel_public_key.in_(keys), SupportAccess.host_public_key.in_(keys))).limit(1)))


async def pending_authority_current(session, row, settings, now, *, request_id=None):
    """Disarm expired or changed intent even when no healthy runtime is available."""
    deadline = row.installation_access_pending_until
    if deadline is None:
        return False
    if utc(deadline) <= now:
        await cancel_installation_access(session, row, 'installer_intent_expired', request_id=request_id, expired=True)
        return False
    reason = None
    if not settings.support_install_auto_enable:
        reason = 'installation_defaults_disabled'
    elif (row.enabled or row.revoked_at is not None or row.reset_registration_allowed or row.expires_at is not None or
          row.operator_public_keys != list(settings.support_install_operator_public_keys) or
          row.windows_admin_username != settings.support_install_windows_admin_username):
        reason = 'installation_defaults_changed'
    elif not await source_active(session, row, now):
        reason = 'installation_source_inactive'
    else:
        events = (await session.scalars(select(AuditEvent).where(
            AuditEvent.action == 'support_access.installation_access_pending',
            AuditEvent.object_kind == 'support_access', AuditEvent.object_identifier == str(row.id)).order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc()).limit(1000))).all()
        events = [event for event in events if event.details.get('revision') == row.revision]
        if len(events) != 1 or events[0].details.get('revision') != row.revision or events[0].details.get('pending_until') != utc(deadline).isoformat() or events[0].details.get('defaults_digest') != defaults_digest(settings):
            reason = 'installation_defaults_unbound_or_changed'
    if reason:
        await cancel_installation_access(session, row, reason, request_id=request_id)
        return False
    return True


async def queue_installation_access(session, row, settings, now, *, request_id=None):
    if row.installation_access_pending_until is not None:
        await pending_authority_current(session, row, settings, now, request_id=request_id)
        return
    if not settings.support_install_auto_enable or not (row.revision == 1 and row.generation == 1 and
        not row.enabled and not row.operator_public_keys and not row.windows_admin_username and
        row.expires_at is None and row.revoked_at is None and not row.reset_registration_allowed):
        return
    await key_authority_lock(session)
    if await operator_roles_conflict(session, settings):
        # A failed automatic decision is final for this installation; retries
        # cannot later silently turn it into authority after the conflict clears.
        row.revision += 1
        await installation_audit(session, row, 'default_conflict', request_id=request_id, reason='operator_key_role_conflict')
        return
    row.operator_public_keys = list(settings.support_install_operator_public_keys)
    row.windows_admin_username = settings.support_install_windows_admin_username
    row.installation_access_pending_until = now + timedelta(minutes=15)
    await installation_audit(session, row, 'pending', request_id=request_id,
        details={'pending_until': row.installation_access_pending_until.isoformat(), 'defaults_digest': defaults_digest(settings)})


async def consume_installation_access(session, row, settings, now, *, request_id=None):
    if not await pending_authority_current(session, row, settings, now, request_id=request_id):
        return
    if not domain_principal_available(row, now) or row.last_error_code is not None:
        return
    await key_authority_lock(session)
    if await operator_roles_conflict(session, settings):
        await cancel_installation_access(session, row, 'operator_key_role_conflict', request_id=request_id)
        return
    # Revalidate independent source authority after any wait on the role lock.
    if not await source_active(session, row, now):
        await cancel_installation_access(session, row, 'installation_source_inactive', request_id=request_id)
        return
    row.enabled = True
    row.expires_at = now + timedelta(hours=settings.support_install_access_hours)
    row.installation_access_pending_until = None
    row.revision += 1
    row.access_verified_at = None
    row.access_verified_by = None
    await installation_audit(session, row, 'granted', request_id=request_id,
        details={'expires_at': row.expires_at.isoformat(), 'defaults_digest': defaults_digest(settings)})
