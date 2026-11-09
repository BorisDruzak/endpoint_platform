"""Linux disabled-key continuity, rooted in an explicit administrator decision."""
from uuid import UUID

from sqlalchemy import select

from endpoint_server.db.models import AuditEvent
from endpoint_server.installation_lifecycle.models import InstallationEvent
from .service import utc


async def linux_disabled_authority(session, row):
    """Return the current proven audit head; historical unbound rebinds fail closed.

    Each native transition must consume the immediately preceding authority at
    its exact revision/generation/credential and reference real causal native
    events. No old False event or native_rebound(False) alone conveys intent.
    """
    if row.platform != 'linux_amd64' or row.enabled or row.revoked_at is not None or row.reset_registration_allowed:
        return None
    events = (await session.scalars(select(AuditEvent).where(
        AuditEvent.object_kind == 'support_access', AuditEvent.object_identifier == str(row.id),
        AuditEvent.action.in_(['support_access.policy_changed', 'support_access.revoked',
            'support_access.registration_reset_authorized', 'support_access.component_removed',
            'support_access.installation_access_granted', 'support_access.installation_access_native_rebound']))
        .order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc()).limit(1000))).all()
    revision, generation = row.revision, row.generation
    newer_sequence, native_generation = None, None
    for index, event in enumerate(events):
        details = event.details
        if type(details.get('revision')) is not int or details['revision'] != revision:
            return None
        if event.action == 'support_access.policy_changed':
            return events[0] if event.actor_kind == 'admin' and details.get('enabled') is False else None
        if (event.action != 'support_access.installation_access_native_rebound' or
            event.actor_kind != 'device' or event.actor_identifier != str(row.device_id) or
            details.get('device_id') != str(row.device_id) or details.get('linux_lease_resumed') is not False or
            details.get('original_expires_at') != (utc(row.expires_at).isoformat() if row.expires_at else None)):
            return None
        intent = details.get('linux_disabled_intent')
        if not isinstance(intent, dict) or intent.get('enabled') is not False:
            return None
        if (type(intent.get('generation')) is not int or intent['generation'] != generation or
            type(intent.get('source_revision')) is not int or intent['source_revision'] != revision - 1 or
            type(intent.get('source_generation')) is not int or intent['source_generation'] != generation - 1 or
            intent.get('source_credential_id') != str(row.source_credential_id) or
            index + 1 == len(events) or intent.get('previous_audit_event_id') != str(events[index + 1].id)):
            return None
        try:
            event_id = UUID(details['event_id'])
        except (KeyError, ValueError, TypeError, AttributeError):
            return None
        installed = await session.get(InstallationEvent, event_id)
        if (installed is None or installed.action != 'installed' or installed.device_id != row.device_id or
            installed.source_credential_id != row.source_credential_id or
            installed.payload.get('schema_version') != 'endpoint_linux_installation_event_v1' or
            str(installed.generation_id) != details.get('generation_id') or
            (native_generation is not None and installed.generation_id != native_generation) or
            (newer_sequence is not None and installed.sequence >= newer_sequence)):
            return None
        removed = await session.get(InstallationEvent, installed.previous_event_id) if installed.previous_event_id else None
        if (removed is None or removed.action != 'removed' or removed.device_id != row.device_id or
            removed.source_credential_id != row.source_credential_id or
            removed.generation_id != installed.generation_id or removed.sequence != installed.sequence - 1):
            return None
        revision, generation = intent['source_revision'], intent['source_generation']
        newer_sequence, native_generation = removed.sequence, installed.generation_id
    return None


def inherited_disabled_intent(row, authority):
    if authority is None:
        return None
    return {'enabled': False, 'previous_audit_event_id': str(authority.id),
        'source_revision': row.revision, 'source_generation': row.generation,
        'generation': row.generation + 1, 'source_credential_id': str(row.source_credential_id)}
