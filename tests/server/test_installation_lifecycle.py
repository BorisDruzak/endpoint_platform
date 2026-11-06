from datetime import UTC,datetime,timedelta
from types import SimpleNamespace
from uuid import uuid4
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine,async_sessionmaker
from endpoint_contracts.installation_lifecycle import InstallationEventV1
from endpoint_server.db.base import Base
from endpoint_server.db.models import Device,DeviceCredential,WindowsSetupRelease,AuditEvent
from endpoint_server.installation_lifecycle.models import InstallationState,InstallationEvent
from endpoint_server.installation_lifecycle.service import accept_event,InstallationConflict
from tests.contracts.test_installation_lifecycle import event_data

@pytest.fixture
async def sessions():
    engine=create_async_engine('sqlite+aiosqlite:///:memory:')
    async with engine.begin() as c:
        await c.run_sync(lambda conn: Base.metadata.create_all(conn,tables=[Base.metadata.tables[name] for name in ('devices','device_credentials','windows_setup_releases','audit_events','installation_events','installation_states','support_access')]))
    yield async_sessionmaker(engine,expire_on_commit=False)
    await engine.dispose()

async def seed(s):
    d=Device(device_identifier=uuid4().hex);s.add(d);await s.flush()
    c=DeviceCredential(device_id=d.id,credential_identifier='initial',token_digest=uuid4().hex);s.add(c)
    n=event_data()['native']
    if not await s.scalar(select(WindowsSetupRelease).where(WindowsSetupRelease.version==n['version'])):
        s.add(WindowsSetupRelease(version=n['version'],agent_version=n['version'],artifact_identifier=uuid4().hex,filename='test.exe',
        setup_sha256='c'*64,msi_sha256=n['msi_sha256'],source_commit=n['source_revision'],msi_source_commit=n['source_revision'],
        product_code=n['product_code'],authenticode_status='valid',msi_authenticode_status='valid'))
    await s.flush()
    return SimpleNamespace(device=d,credential=c)

def next_event(first,action):
    return InstallationEventV1.model_validate({**first.model_dump(mode='json'),'event_id':str(uuid4()),'sequence':first.sequence+1,
        'previous_event_id':str(first.event_id),'action':action})

async def test_causal_history_replay_and_exact_release(sessions):
    async with sessions() as s:
        p=await seed(s)
        first=InstallationEventV1.model_validate(event_data(device_id=str(p.device.id)))
        ack=await accept_event(s,p,first,request_id='test')
        assert await accept_event(s,p,first,request_id='retry')==ack
        removed=next_event(first,'removed');await accept_event(s,p,removed,request_id='test')
        installed=next_event(removed,'installed');await accept_event(s,p,installed,request_id='test')
        assert (await accept_event(s,p,removed,request_id='old')).state=='removed'
        assert (await s.scalar(select(InstallationState))).state=='installed'
        assert len((await s.scalars(select(InstallationEvent))).all())==3
        for change in ({'action':'removed'},{'sequence':5,'event_id':uuid4()},{'generation_id':uuid4(),'event_id':uuid4()}):
            with pytest.raises(InstallationConflict):
                await accept_event(s,p,installed.model_copy(update=change),request_id='bad')
        invalid=next_event(installed,'removed')
        invalid=invalid.model_copy(update={'native':invalid.native.model_copy(update={'msi_sha256':'d'*64})})
        with pytest.raises(InstallationConflict):
            await accept_event(s,p,invalid,request_id='bad')
        assert (await s.scalar(select(InstallationState))).sequence==3

async def test_hidden_trusted_candidate_accepts_exact_native_proof(sessions):
    async with sessions() as s:
        p = await seed(s)
        release = await s.scalar(select(WindowsSetupRelease))
        release.download_published = False
        await s.commit()
    async with sessions() as s:
        release = await s.scalar(select(WindowsSetupRelease))
        assert release.download_published is False
        body = InstallationEventV1.model_validate(event_data(device_id=str(p.device.id)))
        assert (await accept_event(s, p, body, request_id='hidden-candidate')).state == 'installed'
        bad = next_event(body, 'removed')
        bad = bad.model_copy(update={'native': bad.native.model_copy(update={'product_code': '{00000000-0000-0000-0000-000000000000}'})})
        with pytest.raises(InstallationConflict):
            await accept_event(s, p, bad, request_id='bad-hidden-candidate')

async def test_removed_blocks_dispatch_without_changing_queued_history(sessions):
    from endpoint_server.gateway.command_service import next_pending_command
    async with sessions() as s:
        p=await seed(s)
        event=InstallationEventV1.model_validate(event_data(device_id=str(p.device.id),action='removed'))
        await accept_event(s,p,event,request_id='test')
        assert await next_pending_command(s,p.device.id) is None

async def test_native_rebind_is_single_use_and_keeps_manual_policy_disabled(sessions):
    from endpoint_contracts.support_access import SupportRegistration
    from endpoint_server.support_access.service import register,SupportConflict
    from tests.contracts.test_support_access import key
    from endpoint_server.audit.service import append_audit_event
    async with sessions() as s:
        p=await seed(s)
        original=SupportRegistration(tunnel_public_key=key(),host_public_key=key(2),component_version='1.0.1')
        support=await register(s,p.device.id,p.credential.id,original)
        support.operator_public_keys=[key(3)];support.windows_admin_username='admin';support.revoked_at=datetime.now(UTC)
        support.generation+=1;support.revision+=1
        await append_audit_event(s,actor_kind='device',actor_identifier=str(p.device.id),action='support_access.component_removed',
            object_kind='support_access',object_identifier=str(support.id),request_id='test',details={'revision':support.revision})
        rem=InstallationEventV1.model_validate(event_data(device_id=str(p.device.id),action='removed'))
        await accept_event(s,p,rem,request_id='test');await accept_event(s,p,next_event(rem,'installed'),request_id='test')
        replacement=SupportRegistration(tunnel_public_key=key(4),host_public_key=key(5),component_version='1.0.1')
        rebound=await register(s,p.device.id,p.credential.id,replacement)
        assert not rebound.enabled and rebound.revoked_at is None
        assert rebound.windows_admin_username=='admin' and rebound.operator_public_keys==[key(3)]
        assert (await s.scalar(select(InstallationState))).support_rebind_until is None
        with pytest.raises(SupportConflict):
            await register(s,p.device.id,p.credential.id,original)

@pytest.mark.parametrize('mutation',['manual','expired','source','revoke'])
async def test_native_ticket_never_overrides_changed_authority(sessions,mutation):
    from endpoint_contracts.support_access import SupportRegistration
    from endpoint_server.support_access.service import register,SupportConflict
    from tests.contracts.test_support_access import key
    async with sessions() as s:
        p=await seed(s)
        original=SupportRegistration(tunnel_public_key=key(),host_public_key=key(2),component_version='1.0.1')
        row=await register(s,p.device.id,p.credential.id,original);row.enabled=True
        removal=InstallationEventV1.model_validate(event_data(device_id=str(p.device.id),action='removed'))
        await accept_event(s,p,removal,request_id='test');await accept_event(s,p,next_event(removal,'installed'),request_id='test')
        state=await s.scalar(select(InstallationState))
        if mutation=='manual': row.revision+=1;row.enabled=False
        elif mutation=='expired': state.support_rebind_until=datetime.now(UTC)-timedelta(seconds=1)
        elif mutation=='source': state.support_credential_id=uuid4()
        else: row.revoked_at=datetime.now(UTC);row.revision+=1;row.generation+=1
        await s.flush()
        with pytest.raises(SupportConflict):
            await register(s,p.device.id,p.credential.id,SupportRegistration(tunnel_public_key=key(4),host_public_key=key(5),component_version='1.0.1'))
        assert row.tunnel_public_key==key()


@pytest.mark.parametrize('manual_after_grant',[False,True])
async def test_fresh_native_reinstall_auto_access_requires_prior_automatic_authority(sessions,tmp_path,manual_after_grant):
    from endpoint_contracts.support_access import SupportRegistration,SupportStatusReport
    from endpoint_server.support_access.service import register,record_runtime_status
    from endpoint_server.support_access.installation import consume_installation_access
    from endpoint_server.audit.service import append_audit_event
    from tests.contracts.test_support_access import key
    from tests.server.test_support_install_access import configured
    settings=configured(tmp_path);now=datetime.now(UTC)
    async with sessions() as s:
        p=await seed(s)
        original=SupportRegistration(tunnel_public_key=key(),host_public_key=key(2),component_version='1.0.1')
        row=await register(s,p.device.id,p.credential.id,original,settings=settings,now=now)
        record_runtime_status(row,SupportStatusReport(installed=True,tunnel_connected=False,component_version='1.0.1'),now)
        await consume_installation_access(s,row,settings,now)
        assert row.enabled
        if manual_after_grant:
            row.revision+=1
            await append_audit_event(s,actor_kind='admin',actor_identifier='test',action='support_access.policy_changed',
                object_kind='support_access',object_identifier=str(row.id),request_id='test',details={'revision':row.revision,'enabled':True},occurred_at=now+timedelta(seconds=1))
        removal=InstallationEventV1.model_validate(event_data(device_id=str(p.device.id),action='removed'))
        await accept_event(s,p,removal,request_id='test',now=now+timedelta(seconds=2))
        install=next_event(removal,'installed');await accept_event(s,p,install,request_id='test',now=now+timedelta(seconds=3))
        deadline=(await s.scalar(select(InstallationState))).support_rebind_until
        replacement=SupportRegistration(tunnel_public_key=key(4),host_public_key=key(5),component_version='1.0.1')
        rebound=await register(s,p.device.id,p.credential.id,replacement,settings=settings,now=now+timedelta(minutes=1))
        assert not rebound.enabled
        if manual_after_grant:
            assert rebound.installation_access_pending_until is None
        else:
            assert rebound.installation_access_pending_until==deadline.replace(tzinfo=UTC)
            record_runtime_status(row,SupportStatusReport(installed=True,tunnel_connected=False,component_version='1.0.1'),now+timedelta(minutes=1))
            await consume_installation_access(s,row,settings,now+timedelta(minutes=1))
            assert row.enabled
            expiry=row.expires_at
            await register(s,p.device.id,p.credential.id,replacement,settings=settings,now=now+timedelta(minutes=2))
            assert row.expires_at==expiry


async def test_event_history_is_immutable(sessions):
    async with sessions() as s:
        p=await seed(s);body=InstallationEventV1.model_validate(event_data(device_id=str(p.device.id)))
        await accept_event(s,p,body,request_id='test');await s.commit()
        event=await s.get(InstallationEvent,body.event_id);event.action='removed'
        with pytest.raises(ValueError,match='append-only'): await s.flush()

async def test_native_ticket_expiry_is_rechecked_after_key_lock_wait(sessions,monkeypatch):
    from endpoint_contracts.support_access import SupportRegistration
    from endpoint_server.support_access import service
    from tests.contracts.test_support_access import key
    now=datetime.now(UTC);clock=[now]
    class Clock:
        @staticmethod
        def now(tz): return clock[0]
    class PostgreSQLLocks:
        bind=SimpleNamespace(dialect=SimpleNamespace(name='postgresql'))
        def __init__(self,session): self.session=session
        def __getattr__(self,name): return getattr(self.session,name)
    async def waited(session): clock[0]=now+timedelta(minutes=16)
    async with sessions() as s:
        p=await seed(s)
        original=SupportRegistration(tunnel_public_key=key(),host_public_key=key(2),component_version='1.0.1')
        row=await service.register(s,p.device.id,p.credential.id,original,now=now);row.enabled=True
        removal=InstallationEventV1.model_validate(event_data(device_id=str(p.device.id),action='removed'))
        await accept_event(s,p,removal,request_id='test',now=now)
        await accept_event(s,p,next_event(removal,'installed'),request_id='test',now=now)
        monkeypatch.setattr(service,'datetime',Clock);monkeypatch.setattr(service,'key_authority_lock',waited)
        with pytest.raises(service.SupportConflict):
            await service.register(PostgreSQLLocks(s),p.device.id,p.credential.id,
                SupportRegistration(tunnel_public_key=key(4),host_public_key=key(5),component_version='1.0.1'),now=now)
        assert row.tunnel_public_key==key()


def test_connection_conflict_requires_observation_after_removal():
    from endpoint_server.installation_lifecycle.service import connection_conflicts_with_removal
    removed_at=datetime.now(UTC)
    assert not connection_conflicts_with_removal('removed',removed_at-timedelta(seconds=1),removed_at)
    assert not connection_conflicts_with_removal('removed',removed_at,removed_at)
    assert connection_conflicts_with_removal('removed',removed_at+timedelta(seconds=1),removed_at)
    assert not connection_conflicts_with_removal('installed',removed_at+timedelta(seconds=1),removed_at)
    assert not connection_conflicts_with_removal('removed',None,removed_at)


@pytest.mark.parametrize('proof', ['explicit', 'explicit-before-grant', 'explicit-equal-grant', 'missing', 'old', 'zero', 'string', 'enabled'])
async def test_offline_disabled_support_rebind_requires_current_explicit_false(sessions,tmp_path,proof):
    from endpoint_contracts.support_access import SupportRegistration,SupportStatusReport
    from endpoint_server.support_access.service import register,SupportConflict,record_runtime_status
    from endpoint_server.support_access.installation import consume_installation_access
    from endpoint_server.audit.service import append_audit_event
    from tests.contracts.test_support_access import key
    from tests.server.test_support_install_access import configured
    settings=configured(tmp_path);now=datetime.now(UTC)
    async with sessions() as s:
        p=await seed(s)
        row=await register(s,p.device.id,p.credential.id,
            SupportRegistration(tunnel_public_key=key(),host_public_key=key(2),component_version='1.0.1'),
            settings=settings,now=now)
        record_runtime_status(row,SupportStatusReport(installed=True,tunnel_connected=False,component_version='1.0.1'),now)
        await consume_installation_access(s,row,settings,now)
        assert row.enabled
        grant=await s.scalar(select(AuditEvent).where(AuditEvent.action=='support_access.installation_access_granted'))
        disable_time=now+timedelta(seconds=1)
        if proof=='explicit-before-grant': disable_time=grant.created_at.replace(tzinfo=UTC)-timedelta(seconds=1)
        elif proof=='explicit-equal-grant': disable_time=grant.created_at.replace(tzinfo=UTC)
        row.enabled=False;row.revision+=1;row.expires_at=None
        row.windows_admin_username='manual-admin';row.operator_public_keys=[key(3)]
        details={'revision':row.revision-1 if proof=='old' else row.revision}
        if proof!='missing': details['enabled']={'zero':0,'string':'false','enabled':True}.get(proof,False)
        await append_audit_event(s,actor_kind='admin',actor_identifier='test',action='support_access.policy_changed',
            object_kind='support_access',object_identifier=str(row.id),request_id='disable',details=details,
            occurred_at=disable_time)
        # Unregister never arrived: local uninstall discarded owned keys offline.
        removal=InstallationEventV1.model_validate(event_data(device_id=str(p.device.id),action='removed'))
        removed_ack=await accept_event(s,p,removal,request_id='removed',now=now+timedelta(seconds=2))
        installed=next_event(removal,'installed')
        installed_ack=await accept_event(s,p,installed,request_id='installed',now=now+timedelta(seconds=3))
        state=await s.scalar(select(InstallationState))
        replacement=SupportRegistration(tunnel_public_key=key(4),host_public_key=key(5),component_version='1.0.1')
        if not proof.startswith('explicit'):
            assert state.support_rebind_until is None
            with pytest.raises(SupportConflict):
                await register(s,p.device.id,p.credential.id,replacement,settings=settings,now=now+timedelta(seconds=4))
            assert row.tunnel_public_key==key()
            return
        assert state.support_rebind_until is not None and not state.support_auto_eligible
        await register(s,p.device.id,p.credential.id,replacement,settings=settings,now=now+timedelta(seconds=4))
        revision,generation=row.revision,row.generation
        for retry in (timedelta(minutes=1),timedelta(hours=9)):
            assert await accept_event(s,p,removal,request_id='retry',now=now+retry)==removed_ack
            assert await accept_event(s,p,installed,request_id='retry',now=now+retry)==installed_ack
            assert await register(s,p.device.id,p.credential.id,replacement,settings=settings,now=now+retry) is row
            record_runtime_status(row,SupportStatusReport(installed=True,tunnel_connected=False,component_version='1.0.1'),now+retry)
            await consume_installation_access(s,row,settings,now+retry)
            assert not row.enabled and row.expires_at is None and row.installation_access_pending_until is None
            assert row.windows_admin_username=='manual-admin' and row.operator_public_keys==[key(3)]
            assert row.revision==revision and row.generation==generation
            assert state.support_rebind_until is None and state.state=='installed'
        with pytest.raises(SupportConflict):
            await register(s,p.device.id,p.credential.id,
                SupportRegistration(tunnel_public_key=key(6),host_public_key=key(7),component_version='1.0.1'))


@pytest.mark.parametrize('mutation', ['revoke-before','reset-before','revoke-after','reset-after','policy-after','credential-after'])
async def test_offline_disabled_rebind_never_overrides_changed_authority(sessions,mutation):
    from endpoint_contracts.support_access import SupportRegistration
    from endpoint_server.support_access.service import register,SupportConflict
    from endpoint_server.support_access.native_rebind import native_ticket
    from endpoint_server.audit.service import append_audit_event
    from tests.contracts.test_support_access import key
    now=datetime.now(UTC)
    async with sessions() as s:
        p=await seed(s)
        row=await register(s,p.device.id,p.credential.id,
            SupportRegistration(tunnel_public_key=key(),host_public_key=key(2),component_version='1.0.1'))
        row.revision+=1
        await append_audit_event(s,actor_kind='admin',actor_identifier='test',action='support_access.policy_changed',
            object_kind='support_access',object_identifier=str(row.id),request_id='disable',
            details={'revision':row.revision,'enabled':False})
        def change():
            row.revision+=1
            if mutation.startswith('revoke'): row.revoked_at=now;row.generation+=1
            elif mutation.startswith('reset'): row.reset_registration_allowed=True;row.generation+=1
            elif mutation.startswith('credential'): row.source_credential_id=uuid4()
        if mutation.endswith('before'): change()
        removal=InstallationEventV1.model_validate(event_data(device_id=str(p.device.id),action='removed'))
        await accept_event(s,p,removal,request_id='removed',now=now)
        if mutation.endswith('after'): change()
        await accept_event(s,p,next_event(removal,'installed'),request_id='installed',now=now)
        assert await native_ticket(s,row,p.credential.id,now) is None
        assert (await s.scalar(select(InstallationState))).support_rebind_until is None
        # Explicit reset retains its separate administrator-authorized path.
        if not mutation.startswith('reset'):
            with pytest.raises(SupportConflict):
                await register(s,p.device.id,p.credential.id,
                    SupportRegistration(tunnel_public_key=key(4),host_public_key=key(5),component_version='1.0.1'))
        assert row.tunnel_public_key==key()
