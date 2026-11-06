"""Real isolated PostgreSQL allocation/clone races and revocation."""
import asyncio
from datetime import UTC,datetime,timedelta
from uuid import uuid4
import pytest
from alembic import command
from sqlalchemy import select
from endpoint_server.db.session import AsyncSessionProvider
from endpoint_server.db.models import Device,DeviceCredential
from endpoint_contracts.support_access import SupportRegistration
from endpoint_server.support_access.service import register,SupportConflict,get_broker_leases
from tests.contracts.test_support_access import key
from tests.server.test_update_postgresql import update_migration_database_urls,_alembic_config

pytestmark=pytest.mark.usefixtures('preserve_migration_loggers')


def test_registration_race_binds_key_to_exactly_one_device(update_migration_database_urls):
    url,_=update_migration_database_urls
    command.upgrade(_alembic_config(url),'head')
    async def scenario():
        provider=AsyncSessionProvider(url)
        try:
            pairs=[]
            async with provider() as s:
                for _ in range(2):
                    d=Device(device_identifier=uuid4().hex);s.add(d);await s.flush()
                    c=DeviceCredential(device_id=d.id,credential_identifier='initial',token_digest=uuid4().hex);s.add(c);await s.flush();pairs.append((d.id,c.id))
                await s.commit()
            body=SupportRegistration(tunnel_public_key=key(),host_public_key=key(2),component_version='1.0.0')
            async def enroll(pair):
                async with provider() as s:
                    try:
                        row=await register(s,*pair,body)
                        await s.commit()
                        return row
                    except SupportConflict:
                        await s.rollback()
                        return None
            results=await asyncio.gather(*(enroll(pair) for pair in pairs))
            winners=[r for r in results if r]
            assert len(winners)==1
            async def distinct(index):
                async with provider() as s:
                    d=Device(device_identifier=uuid4().hex);s.add(d);await s.flush()
                    c=DeviceCredential(device_id=d.id,credential_identifier='initial',token_digest=uuid4().hex);s.add(c);await s.flush()
                    row=await register(s,d.id,c.id,SupportRegistration(tunnel_public_key=key(index),host_public_key=key(index+1),component_version='1.0.0'))
                    await s.commit()
                    return row.remote_port
            ports=await asyncio.gather(distinct(21),distinct(23))
            assert sorted(ports)==[32001,32002]
            async with provider() as s:
                r=await register(s,winners[0].device_id,winners[0].source_credential_id,body)
                assert r.id==winners[0].id
                now=datetime.now(UTC);r.enabled=True;r.expires_at=now+timedelta(hours=1);r.operator_public_keys=[key(3)];r.windows_admin_username='admin'
                await s.commit()
                leases=await get_broker_leases(s,now)
                assert len(leases)==1
                assert leases[0].remote_port==32000
                c=await s.get(DeviceCredential,r.source_credential_id);c.revoked_at=now
                await s.commit()
                assert await get_broker_leases(s,now)==[]
        finally:
            await provider.close()
    asyncio.run(scenario())


def test_real_cookie_csrf_scope_independent_policy_and_retirement(update_migration_database_urls,tmp_path):
    from dataclasses import replace
    import httpx
    from endpoint_server.main import create_app
    from endpoint_server.auth.admin_sessions import ADMIN_SESSION_COOKIE,issue_admin_session
    from endpoint_server.enrollment.credentials import device_token_digest
    from endpoint_server.db.models import AdminUser
    from tests.server.test_update_agent_api import _settings
    url,_=update_migration_database_urls
    command.upgrade(_alembic_config(url),'head')
    async def scenario():
        settings=replace(_settings(tmp_path),database_url=url,support_gateway_host_public_key=key(9))
        provider=AsyncSessionProvider(url)
        try:
            async with provider() as s:
                d=Device(device_identifier=uuid4().hex);s.add(d);await s.flush()
                token='x'*43
                c=DeviceCredential(device_id=d.id,credential_identifier='initial',token_digest=device_token_digest(token,settings.device_token_pepper));s.add(c)
                admin=AdminUser(username=uuid4().hex,password_digest='test-only',scopes=['updates:write']);s.add(admin);await s.flush()
                issued=issue_admin_session(admin.id,settings.session_secret);s.add(issued.record);await s.commit()
                device_id=d.id
                other=Device(device_identifier=uuid4().hex);s.add(other);await s.flush()
                other_token='y'*43
                s.add(DeviceCredential(device_id=other.id,credential_identifier='initial',token_digest=device_token_digest(other_token,settings.device_token_pepper)))
                await s.commit()
            app=create_app(settings,provider)
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app,client=('127.0.0.1',12345)),base_url=settings.public_base_url) as client:
                registration={'tunnel_public_key':key(10),'host_public_key':key(11),'component_version':'1.0.0'}
                result=await client.post('/agent/v1/support-access/register',json=registration,headers={'Authorization':'Bearer '+token})
                assert result.status_code==200,result.text
                invalid=await client.post('/agent/v1/support-access/register',json={**registration,'sensitive_extra_marker':'sensitive_value_marker'},headers={'Authorization':'Bearer '+token})
                assert invalid.status_code==422
                assert 'sensitive_extra_marker' not in invalid.text and 'sensitive_value_marker' not in invalid.text
                support=result.json()['support_token'];assert not result.json()['policy']['enabled']
                again=await client.post('/agent/v1/support-access/register',json=registration,headers={'Authorization':'Bearer '+token})
                assert again.json()['support_token']==support
                conflict=await client.post('/agent/v1/support-access/register',json={**registration,'host_public_key':key(13)},headers={'Authorization':'Bearer '+token})
                assert conflict.status_code==409 and 'x-support-reset-device' not in conflict.headers
                headers={'Authorization':'Bearer '+support}
                malformed=b'Bearer eps1.'+result.json()['credential_id'].replace('-','').encode()+b'.'+b'\xe9'*64
                assert (await client.get('/agent/v1/support-access/policy',headers=[(b'authorization',malformed)])).status_code==401
                assert (await client.get('/agent/v1/support-access/policy',headers=headers)).status_code==200
                assert (await client.get('/agent/v1/support-access/policy',headers={'Authorization':'Bearer '+token})).status_code==401
                endpoint=f'/api/admin/support-access/devices/{device_id}/policy'
                body={'enabled':True,'expires_at':(datetime.now(UTC)+timedelta(minutes=10)).isoformat(),'operator_public_keys':[key(12)],'windows_admin_username':'admin','reason':'Isolated test acceptance'}
                assert (await client.put(endpoint,json=body)).status_code==401
                client.cookies.set(ADMIN_SESSION_COOKIE,issued.token)
                assert (await client.put(endpoint,json=body)).status_code==403
                changed=await client.put(endpoint,json=body,headers={'X-CSRF-Token':issued.csrf_token})
                assert changed.status_code==200,changed.text
                assert changed.json()['enabled']
                async with provider() as s:
                    actor=await s.get(AdminUser,admin.id);actor.scopes=[];await s.commit()
                assert (await client.put(endpoint,json=body,headers={'X-CSRF-Token':issued.csrf_token})).status_code==403
                async with provider() as s:
                    actor=await s.get(AdminUser,admin.id);actor.scopes=['updates:write'];await s.commit()
                assert (await client.post('/agent/v1/support-access/status',headers=headers,json={'installed':True,'tunnel_connected':True})).status_code==200
                status=(await client.get(f'/api/admin/support-access/devices/{device_id}')).json()
                assert status['installed'] and status['access_verified_at'] is None
                removed=await client.post('/agent/v1/support-access/unregister',headers=headers)
                assert removed.status_code==204,removed.text
                assert (await client.get('/agent/v1/support-access/policy',headers=headers)).status_code==401
                rejected=await client.post('/agent/v1/support-access/register',json=registration,headers={'Authorization':'Bearer '+token})
                assert rejected.status_code==409
                restored=await client.put(endpoint,json=body,headers={'X-CSRF-Token':issued.csrf_token})
                assert restored.status_code==200,restored.text
                rebound=await client.post('/agent/v1/support-access/register',json=registration,headers={'Authorization':'Bearer '+token})
                assert rebound.status_code==200,rebound.text
                assert rebound.json()['support_token']!=support
                headers={'Authorization':'Bearer '+rebound.json()['support_token']}
                reset=f'/api/admin/support-access/devices/{device_id}/reset-registration'
                forbidden=await client.post(reset,json={'reason':'Reinstall isolated test'})
                assert forbidden.status_code==403 and 'x-support-reset-device' not in forbidden.headers
                assert (await client.post(reset,json={'reason':'Reinstall isolated test'},headers={'X-CSRF-Token':issued.csrf_token})).status_code==204
                grant=await client.post('/agent/v1/support-access/register',json=registration,headers={'Authorization':'Bearer '+token})
                assert grant.status_code==409 and grant.headers.get('x-support-reset-device')==str(device_id)
                other_conflict=await client.post('/agent/v1/support-access/register',json=registration,headers={'Authorization':'Bearer '+other_token})
                assert other_conflict.status_code==409 and 'x-support-reset-device' not in other_conflict.headers
                unauthorized=await client.post('/agent/v1/support-access/register',json=registration,headers=headers)
                assert unauthorized.status_code==401 and 'x-support-reset-device' not in unauthorized.headers
                async with provider() as s:
                    device=await s.get(Device,device_id);device.retired_at=datetime.now(UTC);await s.commit()
                retired=await client.post('/agent/v1/support-access/register',json=registration,headers={'Authorization':'Bearer '+token})
                assert retired.status_code==401 and 'x-support-reset-device' not in retired.headers
                async with provider() as s:
                    device=await s.get(Device,device_id);device.retired_at=None
                    credential=await s.get(DeviceCredential,c.id);credential.revoked_at=datetime.now(UTC);await s.commit()
                revoked=await client.post('/agent/v1/support-access/register',json=registration,headers={'Authorization':'Bearer '+token})
                assert revoked.status_code==401 and 'x-support-reset-device' not in revoked.headers
                async with provider() as s:
                    credential=await s.get(DeviceCredential,c.id);credential.revoked_at=None;await s.commit()
                assert (await client.get('/agent/v1/support-access/policy',headers=headers)).status_code==401
                assert (await client.put(endpoint,json=body,headers={'X-CSRF-Token':issued.csrf_token})).status_code==409
                registration={'tunnel_public_key':key(31),'host_public_key':key(32),'component_version':'1.0.1'}
                reinstalled=await client.post('/agent/v1/support-access/register',json=registration,headers={'Authorization':'Bearer '+token})
                assert reinstalled.status_code==200,reinstalled.text
                assert reinstalled.json()['credential_id']==result.json()['credential_id']
                assert not reinstalled.json()['policy']['enabled']
                assert reinstalled.json()['support_token']!=rebound.json()['support_token']
                headers={'Authorization':'Bearer '+reinstalled.json()['support_token']}
                assert (await client.post(reset,json={'reason':'Verify grant request budget'},headers={'X-CSRF-Token':issued.csrf_token})).status_code==204
                grant_count=0
                for _ in range(13):
                    bounded=await client.post('/agent/v1/support-access/register',json=registration,headers={'Authorization':'Bearer '+token})
                    if bounded.status_code==429:
                        assert 'x-support-reset-device' not in bounded.headers
                        break
                    assert bounded.status_code==409 and bounded.headers.get('x-support-reset-device')==str(device_id)
                    grant_count+=1
                else:
                    pytest.fail('Reset grants did not consume the durable registration budget')
                assert 0<grant_count<12
                async with provider() as s:
                    from sqlalchemy import func
                    from endpoint_server.db.models import AuditEvent,DeviceBindingThrottle
                    budget=await s.scalar(select(DeviceBindingThrottle).where(DeviceBindingThrottle.bucket=='support-register:'+str(device_id)))
                    assert budget.attempts==12
                    grants=await s.scalar(select(func.count()).select_from(AuditEvent).where(AuditEvent.object_identifier==result.json()['credential_id'],AuditEvent.action=='support_access.registration_key_rotation_granted'))
                    assert grants==grant_count+1
                async with provider() as s:
                    device=await s.get(Device,device_id);device.retired_at=datetime.now(UTC);await s.commit()
                assert (await client.get('/agent/v1/support-access/policy',headers=headers)).status_code==401
        finally:
            await provider.close()
    asyncio.run(scenario())
