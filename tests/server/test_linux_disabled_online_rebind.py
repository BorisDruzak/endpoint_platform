"""Authenticated online removal must compose with later offline key rotation."""
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import httpx
import pytest
from sqlalchemy import select

from endpoint_server.audit.service import append_audit_event
from endpoint_server.db.models import AuditEvent
from endpoint_server.installation_lifecycle.models import InstallationState
from endpoint_server.main import create_app
from endpoint_server.support_access.disabled_intent import linux_disabled_authority
from endpoint_server.support_access.installation import consume_installation_access
from endpoint_server.support_access.models import SupportAccess
from endpoint_server.support_access.native_rebind import native_ticket
from endpoint_server.support_access.service import register, support_token, get_broker_leases, SupportConflict, utc
from tests.server.test_linux_disabled_rebind import disabled_installation
from tests.server.test_linux_native_rebind_expiry import configured, reinstall, healthy, grant_count
from tests.server.test_linux_support_lifecycle import sessions, registration


async def online_unregister(sessions, settings, token):
    app = create_app(settings, sessions)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=('127.0.0.1', 12345)),
        base_url=settings.public_base_url) as client:
        response = await client.post('/agent/v1/support-access/linux/unregister',
            headers={'Authorization': 'Bearer ' + token})
        assert response.status_code == 204, response.text


@pytest.mark.parametrize('online_cycles', [(True, False, False), (False, True, False)])
async def test_authenticated_online_disable_rebind_composes_with_repeated_offline_cycles(sessions, tmp_path, online_cycles):
    settings = configured(tmp_path)
    async with sessions() as session:
        principal, row, previous, decision = await disabled_installation(session, settings, datetime.now(UTC))
        support_id, source_id = row.id, row.source_credential_id
        await session.commit()
    for cycle, online in enumerate(online_cycles):
        if online:
            async with sessions() as session:
                row = await session.get(SupportAccess, support_id)
                token = support_token(row, settings.device_token_pepper)
            await online_unregister(sessions, settings, token)
        async with sessions() as session:
            row = await session.get(SupportAccess, support_id)
            revision, generation = row.revision, row.generation
            now = datetime.now(UTC)
            previous = await reinstall(session, principal, now, now, previous)
            state = await session.scalar(select(InstallationState))
            assert (state.support_revision, state.support_generation) == (revision, generation)
            assert state.support_credential_id == source_id and state.support_auto_eligible is False
            assert await native_ticket(session, row, source_id, now) is state
            await register(session, principal.device.id, source_id, registration(4 + 2 * cycle),
                platform='linux_amd64', settings=settings, now=now)
            assert row.id == support_id and row.source_credential_id == source_id
            assert (row.revision, row.generation) == (revision + 1, generation + 1)
            assert row.revoked_at is None and state.support_rebind_until is None
            healthy(row, now)
            await consume_installation_access(session, row, settings, now)
            assert not row.enabled and row.expires_at is None and row.installation_access_pending_until is None
            assert await get_broker_leases(session, now, settings=settings) == []
            assert await grant_count(session) == 1
            await session.commit()
    async with sessions() as session:
        row = await session.get(SupportAccess, support_id)
        assert await linux_disabled_authority(session, row) is not None
        events = (await session.scalars(select(AuditEvent).where(AuditEvent.object_identifier == str(support_id),
            AuditEvent.action.in_(['support_access.policy_changed', 'support_access.component_removed',
                'support_access.installation_access_native_rebound'])).order_by(AuditEvent.created_at, AuditEvent.id))).all()
        assert events[0].id == decision.id and len(events) == 5
        for prior, event in zip(events, events[1:]):
            assert event.details['linux_disabled_intent']['previous_audit_event_id'] == str(prior.id)
        late = datetime.now(UTC) + timedelta(hours=9)
        healthy(row, late)
        await consume_installation_access(session, row, settings, late)
        assert not row.enabled and row.expires_at is None and await get_broker_leases(session, late, settings=settings) == []
        assert await grant_count(session) == 1


@pytest.mark.parametrize('change', ['source', 'revision', 'generation', 'revoke', 'reset', 'true', 'false'])
async def test_online_disabled_native_ticket_cannot_override_later_authority(sessions, tmp_path, change):
    settings = configured(tmp_path)
    async with sessions() as session:
        principal, row, previous, _ = await disabled_installation(session, settings, datetime.now(UTC))
        token = support_token(row, settings.device_token_pepper)
        await session.commit()
    await online_unregister(sessions, settings, token)
    async with sessions() as session:
        row = await session.scalar(select(SupportAccess))
        now = datetime.now(UTC)
        await reinstall(session, principal, now, now, previous)
        assert await native_ticket(session, row, principal.credential.id, now) is not None
        if change == 'source':
            row.source_credential_id = uuid4()
        elif change == 'generation':
            row.generation += 1
        else:
            row.revision += 1
            if change in ('revoke', 'reset'):
                row.revoked_at = now
                row.generation += 1
                row.reset_registration_allowed = change == 'reset'
            elif change in ('true', 'false'):
                row.enabled = change == 'true'
                row.expires_at = now + timedelta(hours=1) if row.enabled else None
                if row.enabled:
                    row.revoked_at = None
                await append_audit_event(session, actor_kind='admin', actor_identifier='fixture',
                    action='support_access.policy_changed', object_kind='support_access', object_identifier=str(row.id),
                    request_id='after-online-policy', details={'revision': row.revision, 'enabled': row.enabled})
        assert await native_ticket(session, row, principal.credential.id, now) is None
        if change != 'reset':
            with pytest.raises(SupportConflict):
                await register(session, principal.device.id, principal.credential.id, registration(4),
                    platform='linux_amd64', settings=settings, now=now)
        assert row.installation_access_pending_until is None and await grant_count(session) == 1


@pytest.mark.parametrize('forgery', ['missing', 'nonbool', 'actor', 'source', 'revision', 'generation',
    'previous', 'revoked_time', 'lease', 'proof'])
async def test_online_disabled_provenance_requires_exact_authenticated_transition(sessions, tmp_path, forgery):
    settings = configured(tmp_path)
    async with sessions() as session:
        principal, row, previous, decision = await disabled_installation(session, settings, datetime.now(UTC))
        revision, generation = row.revision, row.generation
        row.revision += 1
        row.generation += 1
        row.revoked_at = datetime.now(UTC)
        intent = {'enabled': False, 'previous_audit_event_id': str(decision.id), 'source_revision': revision,
            'source_generation': generation, 'generation': row.generation, 'source_credential_id': str(row.source_credential_id)}
        details = {'device_id': str(row.device_id), 'revision': row.revision, 'generation': row.generation,
            'source_credential_id': str(row.source_credential_id), 'linux_removal_revoked_at': utc(row.revoked_at).isoformat(),
            'linux_prior_lease': None, 'linux_disabled_intent': intent}
        actor = 'device'
        if forgery == 'missing':
            del details['linux_disabled_intent']
        elif forgery == 'nonbool':
            intent['enabled'] = 0
        elif forgery == 'actor':
            actor = 'admin'
        elif forgery == 'source':
            details['source_credential_id'] = str(uuid4())
        elif forgery == 'revision':
            intent['source_revision'] = revision - 1
        elif forgery == 'generation':
            details['generation'] = generation
        elif forgery == 'previous':
            intent['previous_audit_event_id'] = str(uuid4())
        elif forgery == 'revoked_time':
            details['linux_removal_revoked_at'] = utc(row.revoked_at - timedelta(seconds=1)).isoformat()
        elif forgery == 'lease':
            details['linux_prior_lease'] = {'expires_at': (datetime.now(UTC) + timedelta(hours=1)).isoformat()}
        else:
            intent['source_generation'] = generation - 1
        await append_audit_event(session, actor_kind=actor, actor_identifier=str(row.device_id),
            action='support_access.component_removed', object_kind='support_access', object_identifier=str(row.id),
            request_id='forged-online-disable', details=details)
        assert await linux_disabled_authority(session, row) is None
        await session.commit()
        session.expunge_all()
        row = await session.scalar(select(SupportAccess))
        now = datetime.now(UTC)
        installed = await reinstall(session, principal, now, now, previous)
        await register(session, principal.device.id, principal.credential.id, registration(4),
            platform='linux_amd64', settings=settings, now=now)
        assert not row.enabled and row.expires_at is None and row.installation_access_pending_until is None
        await reinstall(session, principal, now, now, installed)
        assert await native_ticket(session, row, principal.credential.id, now) is None
        assert await get_broker_leases(session, now, settings=settings) == [] and await grant_count(session) == 1
