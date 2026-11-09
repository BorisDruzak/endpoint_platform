"""A disabled native key rebind retains consent provenance, never access."""
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import select

from endpoint_contracts.linux_installation_lifecycle import LinuxInstallationEventV1
from endpoint_server.audit.service import append_audit_event
from endpoint_server.db.models import AuditEvent
from endpoint_server.installation_lifecycle.models import InstallationState
from endpoint_server.installation_lifecycle.service import accept_event
from endpoint_server.installation_lifecycle.linux_sources import resolve_linux_source
from endpoint_server.support_access.installation import consume_installation_access
from endpoint_server.support_access.native_rebind import native_ticket
from endpoint_server.support_access.service import register, get_broker_leases, SupportConflict
from tests.contracts.test_linux_support_lifecycle import event_data
from tests.server.test_linux_native_rebind_expiry import configured, healthy, seed, reinstall, grant_count
from tests.server.test_linux_support_lifecycle import sessions, registration


async def disabled_installation(session, settings, now):
    principal, row = await seed(session, settings, now - timedelta(hours=1))
    installed = LinuxInstallationEventV1.model_validate(event_data(device_id=str(principal.device.id)))
    await accept_event(session, principal, installed, request_id='initial-installed', now=now,
        source_resolver=resolve_linux_source)
    row.enabled = False
    row.expires_at = None
    row.revision += 1
    decision = await append_audit_event(session, actor_kind='admin', actor_identifier='fixture',
        action='support_access.policy_changed', object_kind='support_access', object_identifier=str(row.id),
        request_id='manual-disable', details={'device_id': str(row.device_id), 'revision': row.revision, 'enabled': False})
    await session.flush()
    return principal, row, installed, decision


async def test_repeated_offline_linux_rebind_retains_manual_disable_without_new_grants(sessions, tmp_path):
    now = datetime.now(UTC)
    settings = configured(tmp_path)
    async with sessions() as session:
        principal, row, previous, decision = await disabled_installation(session, settings, now)
        support_id, credential_id = row.id, row.source_credential_id
        for cycle in range(3):
            step = now + timedelta(minutes=cycle)
            revision, generation = row.revision, row.generation
            # Offline removal: unregister is unavailable. Deliver the genuine
            # ordered native removed/installed facts before bootstrap changes keys.
            previous = await reinstall(session, principal, step, step, previous)
            state = await session.scalar(select(InstallationState))
            assert state.sequence == 3 + 2 * cycle
            assert (state.support_revision, state.support_generation) == (revision, generation)
            assert state.support_credential_id == credential_id
            assert not state.support_auto_eligible
            assert await native_ticket(session, row, credential_id, step) is state
            replacement = registration(4 + 2 * cycle)
            assert await register(session, principal.device.id, credential_id, replacement,
                platform='linux_amd64', settings=settings, now=step) is row
            assert row.id == support_id and row.source_credential_id == credential_id
            assert (row.revision, row.generation) == (revision + 1, generation + 1)
            assert state.support_rebind_until is None
            for offset in (timedelta(seconds=1), timedelta(hours=9)):
                healthy(row, step + offset)
                await consume_installation_access(session, row, settings, step + offset)
                assert not row.enabled and row.expires_at is None and row.installation_access_pending_until is None
                assert await get_broker_leases(session, step + offset, settings=settings) == []
                assert await register(session, principal.device.id, credential_id, replacement,
                    platform='linux_amd64', settings=settings, now=step + offset) is row
            with pytest.raises(SupportConflict):
                await register(session, principal.device.id, credential_id, registration(20 + 2 * cycle),
                    platform='linux_amd64', settings=settings, now=step)
        audits = (await session.scalars(select(AuditEvent).where(
            AuditEvent.action == 'support_access.installation_access_native_rebound')
            .order_by(AuditEvent.created_at, AuditEvent.id))).all()
        assert len(audits) == 3
        prior = decision
        for audit in audits:
            assert audit.actor_kind == 'device' and audit.actor_identifier == str(principal.device.id)
            assert audit.object_kind == 'support_access' and audit.object_identifier == str(support_id)
            assert audit.details['linux_lease_resumed'] is False
            assert audit.details['original_expires_at'] is None
            assert audit.details['linux_disabled_intent']['previous_audit_event_id'] == str(prior.id)
            prior = audit
        assert await grant_count(session) == 1


@pytest.mark.parametrize('forgery', ['missing', 'zero', 'string', 'actor', 'object', 'credential',
    'revision', 'generation', 'previous', 'native_event', 'native_generation', 'native_removed', 'initial_installed'])
async def test_disabled_native_audit_requires_exact_intent_and_native_provenance(sessions, tmp_path, forgery):
    now = datetime.now(UTC)
    settings = configured(tmp_path)
    async with sessions() as session:
        principal, row, initial, decision = await disabled_installation(session, settings, now)
        installed = await reinstall(session, principal, now, now, initial)
        old_revision, old_generation = row.revision, row.generation
        row.revision += 1
        row.generation += 1
        # An audit named native_rebound(false) alone is not consent. Construct
        # plausible but unbound/corrupt provenance around real native events.
        intent = {'previous_audit_event_id': str(decision.id), 'enabled': False,
            'source_revision': old_revision, 'source_generation': old_generation,
            'generation': row.generation, 'source_credential_id': str(principal.credential.id)}
        details = {'device_id': str(row.device_id), 'revision': row.revision, 'event_id': str(installed.event_id),
            'generation_id': str(installed.generation_id), 'linux_lease_resumed': False,
            'original_expires_at': None, 'linux_disabled_intent': intent}
        actor, object_id = 'device', str(row.id)
        if forgery == 'missing':
            del details['linux_disabled_intent']
        elif forgery in ('zero', 'string'):
            intent['enabled'] = 0 if forgery == 'zero' else 'false'
        elif forgery == 'actor':
            actor = 'admin'
        elif forgery == 'object':
            object_id = str(uuid4())
        elif forgery == 'credential':
            intent['source_credential_id'] = str(uuid4())
        elif forgery == 'revision':
            intent['source_revision'] = old_revision - 1
        elif forgery == 'generation':
            intent['generation'] = old_generation
        elif forgery == 'previous':
            intent['previous_audit_event_id'] = str(uuid4())
        elif forgery == 'native_event':
            details['event_id'] = str(uuid4())
        elif forgery == 'native_generation':
            details['generation_id'] = str(uuid4())
        elif forgery == 'native_removed':
            details['event_id'] = str(installed.previous_event_id)
        else:
            details['event_id'] = str(initial.event_id)
        await append_audit_event(session, actor_kind=actor, actor_identifier=str(row.device_id),
            action='support_access.installation_access_native_rebound', object_kind='support_access',
            object_identifier=object_id, request_id='forged-lineage', details=details)
        await session.flush()
        await reinstall(session, principal, now, now, installed)
        assert await native_ticket(session, row, principal.credential.id, now) is None
        with pytest.raises(SupportConflict):
            await register(session, principal.device.id, principal.credential.id, registration(6),
                platform='linux_amd64', settings=settings, now=now)
        assert not row.enabled and row.expires_at is None
        assert row.installation_access_pending_until is None and await grant_count(session) == 1


@pytest.mark.parametrize('mutation', ['revision', 'generation', 'source', 'revoke', 'reset'])
@pytest.mark.parametrize('when', ['before_removal', 'after_removal', 'after_install'])
async def test_inherited_disabled_intent_never_overrides_changed_authority(sessions, tmp_path, mutation, when):
    now = datetime.now(UTC)
    settings = configured(tmp_path)
    async with sessions() as session:
        principal, row, previous, _ = await disabled_installation(session, settings, now)
        previous = await reinstall(session, principal, now, now, previous)
        await register(session, principal.device.id, principal.credential.id, registration(4),
            platform='linux_amd64', settings=settings, now=now)

        async def change():
            if mutation == 'generation':
                row.generation += 1
            elif mutation == 'source':
                row.source_credential_id = uuid4()
            else:
                row.revision += 1
                if mutation in ('revoke', 'reset'):
                    row.revoked_at = now
                    row.generation += 1
                    row.reset_registration_allowed = mutation == 'reset'
            await session.flush()

        if when == 'before_removal':
            await change()
        removed = previous.model_copy(update={'event_id': uuid4(), 'previous_event_id': previous.event_id,
            'sequence': 4, 'action': 'removed'})
        await accept_event(session, principal, removed, request_id='second-removed', now=now,
            source_resolver=resolve_linux_source)
        if when == 'after_removal':
            await change()
        installed = removed.model_copy(update={'event_id': uuid4(), 'previous_event_id': removed.event_id,
            'sequence': 5, 'action': 'installed'})
        await accept_event(session, principal, installed, request_id='second-installed', now=now,
            source_resolver=resolve_linux_source)
        if when == 'after_install':
            await change()
        assert await native_ticket(session, row, principal.credential.id, now) is None
        if mutation != 'reset':
            with pytest.raises(SupportConflict):
                await register(session, principal.device.id, principal.credential.id, registration(6),
                    platform='linux_amd64', settings=settings, now=now)
        assert not row.enabled and row.installation_access_pending_until is None
        assert await get_broker_leases(session, now, settings=settings) == []
        assert await grant_count(session) == 1


@pytest.mark.parametrize('enabled', [True, False])
@pytest.mark.parametrize('when', ['after_removal', 'after_install'])
async def test_new_manual_true_or_false_invalidates_already_captured_native_authority(sessions, tmp_path, enabled, when):
    now = datetime.now(UTC)
    settings = configured(tmp_path)
    async with sessions() as session:
        principal, row, previous, _ = await disabled_installation(session, settings, now)
        previous = await reinstall(session, principal, now, now, previous)
        await register(session, principal.device.id, principal.credential.id, registration(4),
            platform='linux_amd64', settings=settings, now=now)
        removed = previous.model_copy(update={'event_id': uuid4(), 'previous_event_id': previous.event_id,
            'sequence': 4, 'action': 'removed'})
        await accept_event(session, principal, removed, request_id='second-removed', now=now,
            source_resolver=resolve_linux_source)
        installed = removed.model_copy(update={'event_id': uuid4(), 'previous_event_id': removed.event_id,
            'sequence': 5, 'action': 'installed'})
        if when == 'after_install':
            await accept_event(session, principal, installed, request_id='second-installed', now=now,
                source_resolver=resolve_linux_source)
        row.revision += 1
        row.enabled = enabled
        row.expires_at = now + timedelta(hours=1) if enabled else None
        await append_audit_event(session, actor_kind='admin', actor_identifier='fixture',
            action='support_access.policy_changed', object_kind='support_access', object_identifier=str(row.id),
            request_id='new-manual-policy', details={'revision': row.revision, 'enabled': enabled})
        if when == 'after_removal':
            await accept_event(session, principal, installed, request_id='second-installed', now=now,
                source_resolver=resolve_linux_source)
        assert await native_ticket(session, row, principal.credential.id, now) is None
        with pytest.raises(SupportConflict):
            await register(session, principal.device.id, principal.credential.id, registration(6),
                platform='linux_amd64', settings=settings, now=now)
        assert row.enabled is enabled
        assert row.installation_access_pending_until is None and await grant_count(session) == 1


@pytest.mark.parametrize('proof', ['missing', 'zero', 'string', 'true', 'device', 'wrong_object', 'old'])
async def test_linux_disabled_origin_requires_current_admin_boolean_false(sessions, tmp_path, proof):
    now = datetime.now(UTC)
    settings = configured(tmp_path)
    async with sessions() as session:
        principal, row = await seed(session, settings, now)
        row.enabled = False
        row.expires_at = None
        row.revision += 1
        details = {'revision': row.revision - 1 if proof == 'old' else row.revision}
        if proof != 'missing':
            details['enabled'] = {'zero': 0, 'string': 'false', 'true': True}.get(proof, False)
        await append_audit_event(session, actor_kind='device' if proof == 'device' else 'admin',
            actor_identifier='fixture', action='support_access.policy_changed', object_kind='support_access',
            object_identifier=str(uuid4() if proof == 'wrong_object' else row.id), request_id='invalid-disable', details=details)
        await reinstall(session, principal, now, now)
        assert await native_ticket(session, row, principal.credential.id, now) is None
        with pytest.raises(SupportConflict):
            await register(session, principal.device.id, principal.credential.id, registration(4),
                platform='linux_amd64', settings=settings, now=now)
