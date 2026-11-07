"""Linux native key rebind resumes existing authority; it cannot renew it."""
from dataclasses import replace
from datetime import UTC,datetime,timedelta
from uuid import uuid4

import pytest
from sqlalchemy import select

from endpoint_contracts.linux_installation_lifecycle import LinuxInstallationEventV1
from endpoint_contracts.linux_support_access import LinuxSupportStatusReport
from endpoint_server.db.models import AuditEvent
from endpoint_server.installation_lifecycle.linux_sources import LinuxNativeRelease,resolve_linux_source
from endpoint_server.installation_lifecycle.service import accept_event
from endpoint_server.support_access.installation import consume_installation_access
from endpoint_server.support_access.models import SupportAccess
from endpoint_server.support_access.service import register,record_runtime_status,get_broker_leases,SupportConflict
from tests.server.test_linux_support_lifecycle import sessions,identity,registration
from tests.server.test_update_agent_api import _settings
from tests.contracts.test_linux_support_lifecycle import native_data,event_data
from tests.contracts.test_support_access import key


def configured(tmp_path):
    return replace(_settings(tmp_path),support_gateway_host_public_key=key(51),
        support_linux_install_auto_enable=True,support_linux_install_operator_public_keys=(key(50),),
        support_linux_install_admin_username='root',support_linux_install_admin_uid=0)


def healthy(row,now):
    record_runtime_status(row,LinuxSupportStatusReport(installed=True,tunnel_connected=False,component_version='1.0.0'),now)


async def seed(session,settings,grant_at):
    principal=await identity(session)
    row=await register(session,principal.device.id,principal.credential.id,registration(),platform='linux_amd64',settings=settings,now=grant_at)
    healthy(row,grant_at)
    await consume_installation_access(session,row,settings,grant_at)
    assert row.enabled and row.expires_at==grant_at+timedelta(hours=8)
    session.add(LinuxNativeRelease(**{k:v for k,v in native_data().items() if k!='exit_code'},
        signer_fingerprint='A'*40,frozen_manifest_sha256='c'*64,reviewed_by='fixture-review'))
    await session.flush()
    return principal,row


async def reinstall(session,principal,remove_at,install_at,previous=None):
    removed=LinuxInstallationEventV1.model_validate(event_data(device_id=str(principal.device.id),action='removed'))
    if previous:
        removed=removed.model_copy(update={'generation_id':previous.generation_id,'sequence':previous.sequence+1,'previous_event_id':previous.event_id})
    await accept_event(session,principal,removed,request_id='remove',now=remove_at,source_resolver=resolve_linux_source)
    installed=removed.model_copy(update={'event_id':uuid4(),'previous_event_id':removed.event_id,'sequence':removed.sequence+1,'action':'installed'})
    await accept_event(session,principal,installed,request_id='install',now=install_at,source_resolver=resolve_linux_source)
    return installed


async def grant_count(session):
    pending=(await session.scalars(select(AuditEvent).where(AuditEvent.action=='support_access.installation_access_pending'))).all()
    assert len(pending)==1  # Only the original fresh-registration intent exists.
    return len((await session.scalars(select(AuditEvent).where(AuditEvent.action=='support_access.installation_access_granted'))).all())


@pytest.mark.parametrize('phase',['before_removal','between_events','before_healthy'])
async def test_linux_native_reinstall_cannot_bypass_original_expiry(sessions,tmp_path,phase):
    now=datetime.now(UTC)
    settings=configured(tmp_path)
    grant_at=now-timedelta(hours=9) if phase=='before_removal' else now-timedelta(hours=8)+timedelta(minutes=1)
    remove_at=now
    install_at=now+timedelta(minutes=2) if phase=='between_events' else now+timedelta(seconds=1)
    report_at=now+timedelta(minutes=3) if phase!='before_removal' else now+timedelta(seconds=3)
    async with sessions() as session:
        principal,row=await seed(session,settings,grant_at)
        original_expiry=row.expires_at
        original_keys=list(row.operator_public_keys)
        await reinstall(session,principal,remove_at,install_at)
        row=await register(session,principal.device.id,principal.credential.id,registration(4),platform='linux_amd64',settings=settings,now=install_at)
        assert row.installation_access_pending_until is None
        healthy(row,report_at)
        await consume_installation_access(session,row,settings,report_at)
        assert await get_broker_leases(session,report_at, settings=settings)==[]
        if phase!='before_healthy':
            assert not row.enabled
        assert row.expires_at==original_expiry
        assert row.operator_public_keys==original_keys and row.linux_admin_username=='root' and row.linux_admin_uid==0
        assert await grant_count(session)==1


async def test_live_linux_lease_keeps_original_deadline_identity_and_keys_across_repeated_rebind(sessions,tmp_path):
    from endpoint_server.audit.service import append_audit_event
    now=datetime.now(UTC)
    settings=configured(tmp_path)
    changed=replace(settings,support_linux_install_auto_enable=False,support_linux_install_operator_public_keys=(key(52),),
        support_linux_install_admin_username='different-admin',support_linux_install_admin_uid=1000,
        support_linux_install_access_hours=1)
    async with sessions() as session:
        principal,row=await seed(session,settings,now-timedelta(hours=1))
        original_expiry=row.expires_at
        row.operator_public_keys=[key(53)];row.linux_admin_username='approved-admin';row.linux_admin_uid=1001;row.revision+=1
        await append_audit_event(session,actor_kind='admin',actor_identifier='fixture',action='support_access.policy_changed',
            object_kind='support_access',object_identifier=str(row.id),request_id='approve-existing-lease',
            details={'revision':row.revision,'enabled':True})
        previous=None
        for index in range(2):
            step=now+timedelta(minutes=index)
            previous=await reinstall(session,principal,step,step,previous)
            row=await register(session,principal.device.id,principal.credential.id,registration(4+2*index),platform='linux_amd64',settings=changed,now=step)
            assert row.enabled and row.expires_at==original_expiry
            assert not row.installed and await get_broker_leases(session,step, settings=changed)==[]
            assert row.installation_access_pending_until is None
            healthy(row,step)
            for offset in range(3):
                await consume_installation_access(session,row,changed,step+timedelta(seconds=offset))
                assert row.expires_at==original_expiry
            assert len(await get_broker_leases(session,step, settings=changed))==1
            assert row.operator_public_keys==[key(53)] and row.linux_admin_username=='approved-admin' and row.linux_admin_uid==1001
        assert await grant_count(session)==1


@pytest.mark.parametrize('when',['before_removal','after_removal'])
@pytest.mark.parametrize('decision',['disable','revoke','reset'])
async def test_explicit_linux_decision_wins_over_native_rebind(sessions,tmp_path,when,decision):
    from endpoint_server.audit.service import append_audit_event
    now=datetime.now(UTC)
    settings=configured(tmp_path)
    async with sessions() as session:
        principal,row=await seed(session,settings,now-timedelta(hours=1))
        removed=LinuxInstallationEventV1.model_validate(event_data(device_id=str(principal.device.id),action='removed'))
        if when=='after_removal':
            await accept_event(session,principal,removed,request_id='remove',now=now,source_resolver=resolve_linux_source)
        row.enabled=False;row.revision+=1
        action='policy_changed'
        if decision=='disable':
            row.expires_at=None
        else:
            row.revoked_at=now;row.generation+=1
            action='revoked' if decision=='revoke' else 'registration_reset_authorized'
            if decision=='reset':
                row.reset_registration_allowed=True;row.expires_at=None
        await append_audit_event(session,actor_kind='admin',actor_identifier='fixture',action='support_access.'+action,
            object_kind='support_access',object_identifier=str(row.id),request_id='manual-decision',
            details={'revision':row.revision,'enabled':False})
        if when=='before_removal':
            await accept_event(session,principal,removed,request_id='remove',now=now,source_resolver=resolve_linux_source)
        installed=removed.model_copy(update={'event_id':uuid4(),'previous_event_id':removed.event_id,'sequence':2,'action':'installed'})
        await accept_event(session,principal,installed,request_id='install',now=now,source_resolver=resolve_linux_source)
        if decision=='reset' or (decision=='disable' and when=='before_removal'):
            row=await register(session,principal.device.id,principal.credential.id,registration(4),platform='linux_amd64',settings=settings,now=now)
        else:
            with pytest.raises(SupportConflict):
                await register(session,principal.device.id,principal.credential.id,registration(4),platform='linux_amd64',settings=settings,now=now)
        healthy(row,now)
        await consume_installation_access(session,row,settings,now)
        assert not row.enabled and row.installation_access_pending_until is None
        assert await get_broker_leases(session,now, settings=settings)==[] and await grant_count(session)==1
        if decision=='reset':
            assert row.operator_public_keys==[] and row.linux_admin_username is None and row.linux_admin_uid is None
        else:
            assert row.operator_public_keys==[key(50)] and row.linux_admin_username=='root' and row.linux_admin_uid==0


async def test_missing_linux_lease_cannot_be_created_by_native_rebind(sessions,tmp_path):
    from endpoint_server.audit.service import append_audit_event
    settings=configured(tmp_path)
    now=datetime.now(UTC)
    async with sessions() as session:
        principal,row=await seed(session,settings,now-timedelta(hours=1))
        row.expires_at=None;row.enabled=False;row.revision+=1
        await append_audit_event(session,actor_kind='admin',actor_identifier='fixture',action='support_access.policy_changed',
            object_kind='support_access',object_identifier=str(row.id),request_id='disable',details={'revision':row.revision,'enabled':False})
        await reinstall(session,principal,now,now)
        row=await register(session,principal.device.id,principal.credential.id,registration(4),platform='linux_amd64',settings=settings,now=now)
        healthy(row,now)
        await consume_installation_access(session,row,settings,now)
        assert not row.enabled and row.expires_at is None and row.installation_access_pending_until is None
        assert await grant_count(session)==1


@pytest.mark.parametrize('prior',['live','expired','disabled'])
async def test_online_linux_unregister_captures_prior_lease_without_renewing_it(sessions,tmp_path,prior):
    import httpx
    from endpoint_server.main import create_app
    from endpoint_server.support_access.service import support_token,utc
    settings=configured(tmp_path)
    now=datetime.now(UTC)
    async with sessions() as session:
        principal,row=await seed(session,settings,now-timedelta(hours=9 if prior=='expired' else 1))
        if prior=='disabled':
            row.enabled=False;row.expires_at=None;row.revision+=1
        original_expiry=row.expires_at
        token=support_token(row,settings.device_token_pepper)
        await session.commit()
    app=create_app(settings,sessions)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app,client=('127.0.0.1',12345)),base_url=settings.public_base_url) as client:
        result=await client.post('/agent/v1/support-access/linux/unregister',headers={'Authorization':'Bearer '+token})
        assert result.status_code==204,result.text
    async with sessions() as session:
        row=await session.scalar(select(SupportAccess))
        audit=await session.scalar(select(AuditEvent).where(AuditEvent.action=='support_access.component_removed'))
        assert audit.details['revision']==row.revision and audit.details['generation']==row.generation
        assert audit.details['source_credential_id']==str(row.source_credential_id)
        assert audit.details['linux_removal_revoked_at']==utc(row.revoked_at).isoformat()
        assert (audit.details['linux_prior_lease'] is not None)==(prior=='live')
        await reinstall(session,principal,now,now)
        row=await register(session,principal.device.id,principal.credential.id,registration(4),platform='linux_amd64',settings=settings,now=now)
        assert row.enabled==(prior=='live')
        assert (utc(row.expires_at) if row.expires_at else None)==original_expiry
        assert row.installation_access_pending_until is None
        healthy(row,now)
        await consume_installation_access(session,row,settings,now)
        assert (utc(row.expires_at) if row.expires_at else None)==original_expiry and await grant_count(session)==1
        assert bool(await get_broker_leases(session,now, settings=settings))==(prior=='live')


async def test_historical_linux_unregister_without_bound_prior_lease_stays_disabled(sessions,tmp_path):
    from endpoint_server.audit.service import append_audit_event
    settings=configured(tmp_path)
    now=datetime.now(UTC)
    async with sessions() as session:
        principal,row=await seed(session,settings,now-timedelta(hours=1))
        original_expiry=row.expires_at
        # Historical authenticated unregister had no pre-removal authorization
        # snapshot. Retained future expiry alone cannot establish old consent.
        row.enabled=False;row.revoked_at=now;row.revision+=1;row.generation+=1
        await append_audit_event(session,actor_kind='device',actor_identifier=str(row.device_id),
            action='support_access.component_removed',object_kind='support_access',object_identifier=str(row.id),
            request_id='historical-unregister',details={'revision':row.revision,'device_id':str(row.device_id)})
        await reinstall(session,principal,now,now)
        row=await register(session,principal.device.id,principal.credential.id,registration(4),platform='linux_amd64',settings=settings,now=now)
        healthy(row,now)
        await consume_installation_access(session,row,settings,now)
        assert not row.enabled and row.expires_at==original_expiry and row.installation_access_pending_until is None
        assert row.operator_public_keys==[key(50)] and row.linux_admin_username=='root' and row.linux_admin_uid==0
        assert await get_broker_leases(session,now, settings=settings)==[] and await grant_count(session)==1
