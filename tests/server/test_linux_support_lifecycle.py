from datetime import UTC, datetime, timedelta
from dataclasses import replace
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from endpoint_server.db.base import Base
from endpoint_server.db.models import Device, DeviceCredential
from endpoint_server.context.models import ContextSnapshot, ContextCurrent
from tests.contracts.test_support_access import key
from tests.contracts.test_linux_support_lifecycle import native_data, event_data
from tests.server.test_update_agent_api import _settings


@pytest.fixture
async def sessions():
    from endpoint_server.installation_lifecycle.linux_sources import LinuxNativeRelease
    engine=create_async_engine('sqlite+aiosqlite:///:memory:')
    async with engine.begin() as connection:
        await connection.run_sync(lambda conn: Base.metadata.create_all(conn,tables=[Base.metadata.tables[name] for name in
            ('devices','device_credentials','support_access','installation_events','installation_states',
             'audit_events','context_snapshots','context_current','linux_native_releases')]))
        # SQLite cannot compile the production campaign ARRAY. These minimal
        # read-side tables exercise the actual platform joins without PG claims.
        await connection.execute(text('CREATE TABLE enrollment_campaigns (id CHAR(32), target_platform TEXT)'))
        await connection.execute(text('CREATE TABLE enrollment_claims (id CHAR(32), campaign_id CHAR(32), device_id CHAR(32), claimed_at TEXT, enrollment_request_id CHAR(32))'))
        await connection.execute(text('CREATE TABLE enrollment_requests (id CHAR(32), device_id CHAR(32), platform TEXT)'))
    yield async_sessionmaker(engine,expire_on_commit=False)
    await engine.dispose()


async def identity(session, platform='linux', architecture='x86_64'):
    device=Device(device_identifier=uuid4().hex); session.add(device); await session.flush()
    credential=DeviceCredential(device_id=device.id,credential_identifier='initial',token_digest=uuid4().hex)
    session.add(credential)
    campaign=uuid4()
    await session.execute(text('INSERT INTO enrollment_campaigns VALUES (:id,:platform)'),{'id':campaign.hex,'platform':platform})
    await session.execute(text('INSERT INTO enrollment_claims VALUES (:id,:campaign,:device,:at,NULL)'),
        {'id':uuid4().hex,'campaign':campaign.hex,'device':device.id.hex,'at':datetime.now(UTC).isoformat()})
    payload={'schema_version':'device_context_v1','profile':'baseline_v1','collected_at':datetime.now(UTC).isoformat(),
        'sections':{'system':{'platform':platform,'distribution':'test','architecture':architecture},
            'hardware':{'manufacturer':'test','model':'test','cpu_model':'test','memory_bytes':1},
            'storage':[{'stable_key':'disk-test','model':'test','size_bytes':1}], 'interfaces':[], 'software':[]},'warnings':[]}
    snapshot=ContextSnapshot(collection_id=uuid4(),device_id=device.id,profile='baseline_v1',collected_at=datetime.now(UTC),normalized_projection=payload)
    session.add(snapshot); await session.flush()
    session.add(ContextCurrent(device_id=device.id,profile='baseline_v1',snapshot_id=snapshot.id,updated_at=datetime.now(UTC)))
    await session.flush()
    return SimpleNamespace(device=device,credential=credential)


def registration(a=1):
    from endpoint_contracts.linux_support_access import LinuxSupportRegistration
    return LinuxSupportRegistration(tunnel_public_key=key(a),host_public_key=key(a+1),component_version='1.0.0')


async def test_persisted_linux_platform_required_and_legacy_windows_cannot_mutate_it(sessions):
    from endpoint_server.support_access.service import register, SupportConflict
    from endpoint_server.support_access.platforms import verified_platform
    from endpoint_contracts.support_access import SupportRegistration
    async with sessions() as session:
        principal=await identity(session)
        assert await verified_platform(session,principal.device.id)=='linux_amd64'
        row=await register(session,principal.device.id,principal.credential.id,registration(),platform='linux_amd64')
        assert row.platform=='linux_amd64' and row.windows_admin_username is None
        with pytest.raises(SupportConflict):
            await register(session,principal.device.id,principal.credential.id,
                SupportRegistration(tunnel_public_key=key(),host_public_key=key(2),component_version='1.0.1'))
        snapshot=await session.scalar(select(ContextSnapshot))
        snapshot.normalized_projection={**snapshot.normalized_projection,'sections':{**snapshot.normalized_projection['sections'],
            'system':{'platform':'windows','distribution':'test','architecture':'x86_64'}}}
        await session.flush()
        assert await verified_platform(session,principal.device.id) is None
        with pytest.raises(SupportConflict):
            await register(session,principal.device.id,principal.credential.id,registration(),platform='linux_amd64')


@pytest.mark.parametrize('platform,architecture',[('windows','x86_64'),('linux','aarch64')])
async def test_non_linux_amd64_registration_refused(sessions,platform,architecture):
    from endpoint_server.support_access.service import register, SupportConflict
    async with sessions() as session:
        principal=await identity(session,platform,architecture)
        with pytest.raises(SupportConflict):
            await register(session,principal.device.id,principal.credential.id,registration(),platform='linux_amd64')


async def test_linux_defaults_are_separate_fresh_and_once_only(sessions,tmp_path):
    from endpoint_contracts.linux_support_access import LinuxSupportStatusReport
    from endpoint_server.support_access.service import register,record_runtime_status,get_broker_leases
    from endpoint_server.support_access.installation import consume_installation_access
    settings=replace(_settings(tmp_path),support_install_auto_enable=True,support_install_operator_public_keys=(key(50),),
        support_install_windows_admin_username='admin',support_gateway_host_public_key=key(51))
    async with sessions() as session:
        principal=await identity(session)
        row=await register(session,principal.device.id,principal.credential.id,registration(),platform='linux_amd64',settings=settings)
        assert row.installation_access_pending_until is None and row.windows_admin_username is None
        # New registration under Linux defaults; Windows defaults never apply.
        other=await identity(session)
        settings=replace(settings,support_linux_install_auto_enable=True,support_linux_install_operator_public_keys=(key(52),),
            support_linux_install_admin_username='osn-admin',support_linux_install_admin_uid=1000)
        row=await register(session,other.device.id,other.credential.id,registration(4),platform='linux_amd64',settings=settings)
        now=datetime.now(UTC)
        await consume_installation_access(session,row,settings,now)
        assert not row.enabled
        record_runtime_status(row,LinuxSupportStatusReport(installed=True,tunnel_connected=False,component_version='1.0.0'),now)
        await consume_installation_access(session,row,settings,now)
        assert row.enabled and row.linux_admin_username=='osn-admin' and row.linux_admin_uid==1000
        expiry=row.expires_at
        await consume_installation_access(session,row,settings,now+timedelta(hours=1))
        assert row.expires_at==expiry
        assert len(await get_broker_leases(session,now))==1
        assert await get_broker_leases(session,now+timedelta(seconds=91))==[]


async def test_linux_exact_source_and_replay_share_causal_projection(sessions):
    from endpoint_contracts.linux_installation_lifecycle import LinuxInstallationEventV1
    from endpoint_server.installation_lifecycle.linux_sources import LinuxNativeRelease,resolve_linux_source
    from endpoint_server.installation_lifecycle.service import accept_event,InstallationConflict
    async with sessions() as session:
        principal=await identity(session)
        body=LinuxInstallationEventV1.model_validate(event_data(device_id=str(principal.device.id)))
        with pytest.raises(InstallationConflict):
            await accept_event(session,principal,body,request_id='unregistered',source_resolver=resolve_linux_source)
        session.add(LinuxNativeRelease(**{k:v for k,v in native_data().items() if k!='exit_code'},
            signer_fingerprint='A'*40,frozen_manifest_sha256='c'*64,reviewed_by='test-review'))
        await session.flush()
        ack=await accept_event(session,principal,body,request_id='registered',source_resolver=resolve_linux_source)
        assert await accept_event(session,principal,body,request_id='replay',source_resolver=resolve_linux_source)==ack
        changed=body.model_copy(update={'action':'removed'})
        with pytest.raises(InstallationConflict):
            await accept_event(session,principal,changed,request_id='collision',source_resolver=resolve_linux_source)
        stale=body.model_copy(update={'event_id':uuid4(),'sequence':2,'previous_event_id':body.event_id,
            'native':body.native.model_copy(update={'core_rpm_sha256':'d'*64})})
        with pytest.raises(InstallationConflict):
            await accept_event(session,principal,stale,request_id='stale-source',source_resolver=resolve_linux_source)


async def test_unknown_platform_and_broken_request_binding_fail_closed(sessions):
    from endpoint_server.support_access.platforms import verified_platform
    async with sessions() as session:
        principal=await identity(session)
        await session.execute(text('UPDATE enrollment_claims SET enrollment_request_id=:id'),{'id':uuid4().hex})
        assert await verified_platform(session,principal.device.id) is None
        await session.execute(text('DELETE FROM enrollment_claims'))
        assert await verified_platform(session,principal.device.id) is None


async def test_source_publisher_requires_native_signature_payload_proof_and_exact_bytes(sessions,tmp_path):
    import hashlib
    from endpoint_server.installation_lifecycle.linux_sources import LinuxNativeReview,VerifiedRPM,publish_native_release
    path=tmp_path/'core.rpm'; path.write_bytes(b'disposable fixture signed archive stand-in')
    review=LinuxNativeReview(**{**{k:v for k,v in native_data().items() if k!='exit_code'},'core_rpm_sha256':hashlib.sha256(path.read_bytes()).hexdigest()},
        signer_fingerprint='A'*40,frozen_manifest_sha256='c'*64,reviewed_by='fixture-review')
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        LinuxNativeReview(**review.model_dump(),exit_code=0)
    good=VerifiedRPM(review.core_nevra,review.signer_fingerprint,review.source_revision,review.frozen_manifest_sha256)
    async with sessions() as session:
        with pytest.raises(TypeError):
            await publish_native_release(session,review,path)
        for bad in (None,True,replace(good,signer_fingerprint='B'*40),replace(good,source_revision='b'*40),
                    replace(good,frozen_manifest_sha256='d'*64),replace(good,nevra='other.x86_64')):
            with pytest.raises(ValueError):
                await publish_native_release(session,review,path,verify_rpm=lambda p,s:bad)
        row=await publish_native_release(session,review,path,verify_rpm=lambda p,s:good)
        assert await publish_native_release(session,review,path,verify_rpm=lambda p,s:good) is row
        from endpoint_server.db.models import AuditEvent
        audits=(await session.scalars(select(AuditEvent).where(AuditEvent.action=='linux_native_release.registered'))).all()
        assert len(audits)==1 and audits[0].details['source_revision']==review.source_revision
        path.write_bytes(b'changed signed archive')
        with pytest.raises(ValueError):
            await publish_native_release(session,review,path,verify_rpm=lambda p,s:good)


@pytest.mark.parametrize('change',[{'source_revision':'b'*40},{'core_rpm_sha256':'d'*64}])
async def test_registered_linux_source_cannot_be_rewritten(sessions,change):
    from endpoint_server.installation_lifecycle.linux_sources import LinuxNativeRelease
    async with sessions() as session:
        row=LinuxNativeRelease(**{k:v for k,v in native_data().items() if k!='exit_code'},
            signer_fingerprint='A'*40,frozen_manifest_sha256='c'*64,reviewed_by='fixture-review')
        session.add(row);await session.commit()
        for key_name,value in change.items():
            setattr(row,key_name,value)
        with pytest.raises(ValueError):
            await session.flush()


async def test_retired_linux_source_cannot_admit_new_event_or_be_reactivated(sessions):
    from endpoint_contracts.linux_installation_lifecycle import LinuxInstallationNativeProof
    from endpoint_server.installation_lifecycle.linux_sources import LinuxNativeRelease,resolve_linux_source
    from endpoint_server.installation_lifecycle.service import InstallationConflict
    async with sessions() as session:
        row=LinuxNativeRelease(**{k:v for k,v in native_data().items() if k!='exit_code'},
            signer_fingerprint='A'*40,frozen_manifest_sha256='c'*64,reviewed_by='fixture-review')
        session.add(row);await session.commit()
        row.retired_at=datetime.now(UTC)
        await session.commit()
        with pytest.raises(InstallationConflict):
            await resolve_linux_source(session,LinuxInstallationNativeProof(**native_data()))
        row.retired_at=None
        with pytest.raises(ValueError):
            await session.flush()


async def test_linux_native_rebind_preserves_manual_disable_and_has_single_use(sessions):
    from endpoint_contracts.linux_installation_lifecycle import LinuxInstallationEventV1
    from endpoint_server.audit.service import append_audit_event
    from endpoint_server.installation_lifecycle.linux_sources import LinuxNativeRelease,resolve_linux_source
    from endpoint_server.installation_lifecycle.service import accept_event
    from endpoint_server.support_access.service import register,SupportConflict
    async with sessions() as session:
        principal=await identity(session)
        row=await register(session,principal.device.id,principal.credential.id,registration(),platform='linux_amd64')
        row.linux_admin_username='root';row.linux_admin_uid=0;row.operator_public_keys=[key(50)]
        await append_audit_event(session,actor_kind='admin',actor_identifier='fixture',action='support_access.policy_changed',
            object_kind='support_access',object_identifier=str(row.id),request_id='manual-disable',details={'revision':row.revision,'enabled':False})
        session.add(LinuxNativeRelease(**{k:v for k,v in native_data().items() if k!='exit_code'},
            signer_fingerprint='A'*40,frozen_manifest_sha256='c'*64,reviewed_by='fixture-review'))
        await session.flush()
        removed=LinuxInstallationEventV1.model_validate(event_data(device_id=str(principal.device.id),action='removed'))
        await accept_event(session,principal,removed,request_id='remove',source_resolver=resolve_linux_source)
        installed=removed.model_copy(update={'event_id':uuid4(),'previous_event_id':removed.event_id,'sequence':2,'action':'installed'})
        await accept_event(session,principal,installed,request_id='install',source_resolver=resolve_linux_source)
        rebound=await register(session,principal.device.id,principal.credential.id,registration(4),platform='linux_amd64')
        assert rebound.id==row.id and not rebound.enabled and rebound.linux_admin_uid==0
        assert rebound.linux_admin_username=='root' and rebound.installation_access_pending_until is None
        with pytest.raises(SupportConflict):
            await register(session,principal.device.id,principal.credential.id,registration(6),platform='linux_amd64')


async def test_linux_authenticated_routes_and_windows_token_separation(sessions,tmp_path):
    import httpx
    from endpoint_server.db.models import DeviceBindingThrottle
    from endpoint_server.enrollment.credentials import device_token_digest
    from endpoint_server.main import create_app
    settings=replace(_settings(tmp_path),support_gateway_host_public_key=key(51),
        support_linux_install_auto_enable=True,support_linux_install_operator_public_keys=(key(50),),
        support_linux_install_admin_username='root',support_linux_install_admin_uid=0)
    async with sessions() as session:
        await (await session.connection()).run_sync(lambda conn: DeviceBindingThrottle.__table__.create(conn))
        principal=await identity(session)
        principal.credential.token_digest=device_token_digest('x'*43,settings.device_token_pepper)
        await session.commit()
    app=create_app(settings,sessions)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app,client=('127.0.0.1',12345)),base_url=settings.public_base_url) as client:
        response=await client.post('/agent/v1/support-access/linux/register',headers={'Authorization':'Bearer '+'x'*43},json=registration().model_dump())
        assert response.status_code==200,response.text
        assert not response.json()['policy']['enabled']
        headers={'Authorization':'Bearer '+response.json()['support_token']}
        status={'installed':True,'tunnel_connected':False,'component_version':'1.0.0'}
        response=await client.post('/agent/v1/support-access/linux/status',headers=headers,json=status)
        assert response.status_code==200,response.text
        assert response.json()['enabled'] and response.json()['linux_admin_uid']==0
        assert 'windows_admin_username' not in response.json()
        assert (await client.get('/agent/v1/support-access/policy',headers=headers)).status_code==401
        expiry=response.json()['expires_at']
        response=await client.post('/agent/v1/support-access/linux/status',headers=headers,json=status)
        from endpoint_server.support_access.service import utc
        assert utc(datetime.fromisoformat(response.json()['expires_at']))==utc(datetime.fromisoformat(expiry))
        from endpoint_server.installation_lifecycle.linux_sources import LinuxNativeRelease
        async with sessions() as session:
            session.add(LinuxNativeRelease(**{k:v for k,v in native_data().items() if k!='exit_code'},
                signer_fingerprint='A'*40,frozen_manifest_sha256='c'*64,reviewed_by='fixture-review'))
            await session.commit()
        native_event=event_data(device_id=str(principal.device.id))
        event_headers={'Authorization':'Bearer '+'x'*43}
        result=await client.post('/agent/v1/installation/linux/events',headers=event_headers,json=native_event)
        assert result.status_code==200,result.text
        assert result.json()['schema_version']=='endpoint_installation_event_ack_v1'
        replay=await client.post('/agent/v1/installation/linux/events',headers=event_headers,json=native_event)
        assert replay.json()==result.json()
        assert (await client.post('/agent/v1/installation-events',headers=event_headers,json=native_event)).status_code==422
        response=await client.post('/agent/v1/support-access/linux/unregister',headers=headers)
        assert response.status_code==204
        assert (await client.get('/agent/v1/support-access/linux/policy',headers=headers)).status_code==401


def test_linux_routes_are_in_canonical_artifact_and_dtos_exported():
    import yaml
    import endpoint_contracts
    from tools.contracts.generate_contract_artifacts import render_artifacts
    from pathlib import Path
    artifacts=render_artifacts(Path('.'))
    document=yaml.safe_load(artifacts[Path('contracts/openapi/endpoint-platform-v1.yaml')])
    assert '/agent/v1/installation/linux/events' in document['paths']
    assert '/agent/v1/support-access/linux/register' in document['paths']
    assert endpoint_contracts.LinuxSupportPolicy
    for path,operations in document['paths'].items():
        if path.startswith('/api/admin/support-access/linux/'):
            for operation in operations.values():
                assert operation['security']==[{'LinuxSupportAdminCookie':[]}]
