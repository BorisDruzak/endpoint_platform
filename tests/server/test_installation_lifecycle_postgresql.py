"""Real PostgreSQL transaction, authentication and causal-order acceptance."""
import asyncio
from dataclasses import replace
from datetime import UTC,datetime,timedelta
from uuid import uuid4
import httpx
import pytest
from alembic import command
from sqlalchemy import select,func,text
from endpoint_server.db.session import AsyncSessionProvider
from endpoint_server.db.models import Device,DeviceCredential,AuditEvent
from endpoint_server.installation_lifecycle.models import InstallationEvent,InstallationState
from endpoint_server.enrollment.credentials import device_token_digest
from endpoint_server.main import create_app
from tests.server.test_update_postgresql import update_migration_database_urls,_alembic_config
from tests.server.test_update_agent_api import _settings
from tests.server.test_installation_lifecycle import seed,next_event
from tests.contracts.test_installation_lifecycle import event_data
from endpoint_contracts.installation_lifecycle import InstallationEventV1
pytestmark=pytest.mark.usefixtures('preserve_migration_loggers')


def test_migration_preserves_legacy_unknown_and_downgrade(update_migration_database_urls):
    url,_=update_migration_database_urls
    command.upgrade(_alembic_config(url),'0047_support_install_access')
    async def legacy():
        p=AsyncSessionProvider(url)
        try:
            async with p() as s:
                d=Device(device_identifier=uuid4().hex);s.add(d);await s.commit();return d.id
        finally: await p.close()
    identifier=asyncio.run(legacy())
    command.upgrade(_alembic_config(url),'head')
    async def check():
        p=AsyncSessionProvider(url)
        try:
            async with p() as s:
                assert await s.get(Device,identifier)
                assert await s.scalar(select(func.count()).select_from(InstallationState))==0
                assert await s.scalar(select(func.count()).select_from(InstallationEvent))==0
        finally: await p.close()
    asyncio.run(check())
    command.downgrade(_alembic_config(url),'0047_support_install_access')
    command.upgrade(_alembic_config(url),'head')
    asyncio.run(check())


def test_authenticated_events_retry_order_source_auth_and_history(update_migration_database_urls,tmp_path):
    url,_=update_migration_database_urls
    command.upgrade(_alembic_config(url),'head')
    async def scenario():
        settings=replace(_settings(tmp_path),database_url=url)
        provider=AsyncSessionProvider(url)
        try:
            async with provider() as s:
                p=await seed(s);token=uuid4().hex+uuid4().hex
                p.credential.token_digest=device_token_digest(token,settings.device_token_pepper)
                d,c=p.device.id,p.credential.id;await s.commit()
            app=create_app(settings,provider)
            event=event_data(device_id=str(d));headers={'Authorization':'Bearer '+token}
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app,client=('127.0.0.1',1)),base_url=settings.public_base_url) as client:
                path='/agent/v1/installation-events'
                assert (await client.post(path,json=event)).status_code==401
                bad={**event,'device_id':str(uuid4())}
                assert (await client.post(path,json=bad,headers=headers)).status_code==409
                bad={**event,'native':{**event['native'],'msi_sha256':'f'*64}}
                assert (await client.post(path,json=bad,headers=headers)).status_code==409
                first=await client.post(path,json=event,headers=headers);assert first.status_code==200,first.text
                retry=await client.post(path,json=event,headers=headers);assert retry.json()==first.json()
                removal=next_event(InstallationEventV1.model_validate(event),'removed')
                options=[removal.model_dump(mode='json'),removal.model_copy(update={'event_id':uuid4()}).model_dump(mode='json')]
                results=await asyncio.gather(*(client.post(path,json=value,headers=headers) for value in options))
                assert sorted(r.status_code for r in results)==[200,409]
                winner=options[next(i for i,r in enumerate(results) if r.status_code==200)]
                restored=next_event(InstallationEventV1.model_validate(winner),'installed')
                response=await client.post(path,json=restored.model_dump(mode='json'),headers=headers);assert response.status_code==200,response.text
                assert (await client.post(path,json=winner,headers=headers)).status_code==200
                assert (await client.get(f'/api/admin/console/devices/{d}/installation-events')).status_code==401
                async with provider() as s:
                    current=await s.scalar(select(InstallationState).where(InstallationState.device_id==d))
                    assert current.state=='installed' and current.sequence==3
                    assert await s.scalar(select(func.count()).select_from(InstallationEvent).where(InstallationEvent.device_id==d))==3
                    credential=await s.get(DeviceCredential,c);credential.revoked_at=datetime.now(UTC);await s.commit()
                assert (await client.post(path,json=winner,headers=headers)).status_code==401
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app,client=('203.0.113.1',1)),base_url=settings.public_base_url) as client:
                assert (await client.post('/agent/v1/installation-events',json=event,headers=headers)).status_code==401
        finally: await provider.close()
    asyncio.run(scenario())


def test_revocation_committed_during_authentication_prevents_event(update_migration_database_urls,tmp_path,monkeypatch):
    import endpoint_server.installation_lifecycle.routes as routes
    url,_=update_migration_database_urls
    async def scenario():
        settings=replace(_settings(tmp_path),database_url=url);provider=AsyncSessionProvider(url)
        entered=asyncio.Event();resume=asyncio.Event();original=routes._authenticate_device
        async def pause(session,request):
            principal=await original(session,request);entered.set();await resume.wait();return principal
        monkeypatch.setattr(routes,'_authenticate_device',pause)
        try:
            async with provider() as s:
                p=await seed(s);token=uuid4().hex+uuid4().hex
                p.credential.token_digest=device_token_digest(token,settings.device_token_pepper)
                d,c=p.device.id,p.credential.id;await s.commit()
            app=create_app(settings,provider)
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app,client=('127.0.0.1',1)),base_url=settings.public_base_url) as client:
                pending=asyncio.create_task(client.post('/agent/v1/installation-events',json=event_data(device_id=str(d)),headers={'Authorization':'Bearer '+token}))
                await asyncio.wait_for(entered.wait(),5)
                async with provider() as s:
                    credential=await s.get(DeviceCredential,c);credential.revoked_at=datetime.now(UTC);await s.commit()
                resume.set();assert (await asyncio.wait_for(pending,10)).status_code==401
                async with provider() as s:
                    assert await s.scalar(select(InstallationState).where(InstallationState.device_id==d)) is None
                    assert await s.scalar(select(func.count()).select_from(InstallationEvent).where(InstallationEvent.device_id==d))==0
        finally: resume.set();await provider.close()
    asyncio.run(scenario())

def test_explicit_full_wipe_link_is_audited_history_only(update_migration_database_urls,tmp_path):
    from ipaddress import IPv4Address
    from endpoint_server.db.models import EnrollmentClaim,EnrollmentRequest,AdminUser
    from endpoint_server.enrollment.campaigns import issue_install_claim
    from endpoint_server.enrollment.requests import CampaignSelection,build_enrollment_request
    from endpoint_server.auth.admin_sessions import ADMIN_SESSION_COOKIE,issue_admin_session
    from endpoint_server.installation_lifecycle.models import InstallationParent
    from endpoint_server.installation_lifecycle.service import accept_event
    from tests.server.test_enrollment_request_admin_api import _campaign,PEPPER
    url,_=update_migration_database_urls
    command.upgrade(_alembic_config(url),'head')
    async def scenario():
        settings=replace(_settings(tmp_path),database_url=url);provider=AsyncSessionProvider(url)
        try:
            async with provider() as s:
                p=await seed(s);previous=p.device.id;cred=p.credential.id
                campaign=_campaign();campaign.max_uses=10;s.add(campaign);await s.flush()
                now=datetime.now(UTC);fingerprint='sha256:windows-fingerprint-v1'
                def request_for(hardware):
                    return build_enrollment_request(
                        installation_id=str(uuid4()),hardware_fingerprint=hardware,request_capability=uuid4().hex,
                        source_address=IPv4Address('192.168.100.10'),installer_version='1.0.0',installer_release_id='1.0.0',
                        hostname='office-pc-01',selection=CampaignSelection('waiting_approval',campaign,'MANUAL_POLICY'),
                        pepper=PEPPER,now=now)
                record=request_for(fingerprint)
                prior=request_for(fingerprint);prior.status='completed';prior.device_id=previous
                different=request_for('sha256:different-hardware');different.status='completed';different.device_id=previous
                s.add_all((record,prior,different));await s.flush();rid=record.id;prior_id=prior.id;different_id=different.id
                claim=issue_install_claim(campaign,PEPPER,installation_session=str(uuid4()),hardware_fingerprint=fingerprint,
                    expires_at=now+timedelta(hours=1),now=now).record
                assert prior.fingerprint_digest==record.fingerprint_digest
                assert claim.fingerprint_digest!=record.fingerprint_digest
                claim.device_id=previous;claim.claimed_at=now;claim.enrollment_request_id=prior_id;s.add(claim)
                admin=AdminUser(username=uuid4().hex,password_digest='test-only',scopes=[]);s.add(admin);await s.flush()
                issued=issue_admin_session(admin.id,settings.session_secret);s.add(issued.record)
                native=InstallationEventV1.model_validate(event_data(device_id=str(previous)))
                await accept_event(s,p,native,request_id='test');await s.commit();claim_id=claim.id
            app=create_app(settings,provider)
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app,client=('127.0.0.1',1)),base_url=settings.public_base_url) as client:
                path=f'/api/admin/enrollment/requests/{rid}/approve';body={'previous_device_id':str(previous)}
                client.cookies.set(ADMIN_SESSION_COOKIE,issued.token)
                assert (await client.post(path,json=body)).status_code==403
                headers={'X-CSRF-Token':issued.csrf_token}
                assert (await client.post(path,json=body,headers=headers)).status_code==409
                async with provider() as s:
                    p=type('Principal',(),{'device':await s.get(Device,previous),'credential':await s.get(DeviceCredential,cred)})()
                    await accept_event(s,p,next_event(native,'removed'),request_id='test');await s.commit()
                # Missing request, different hardware, unconsumed claim and inconsistent
                # request/device linkage must all fail closed without creating history.
                for failure in ('missing_request','different_hardware','unconsumed','wrong_device','retired'):
                    async with provider() as s:
                        claim=await s.get(EnrollmentClaim,claim_id);prior=await s.get(EnrollmentRequest,prior_id)
                        old=await s.get(Device,previous)
                        claim.enrollment_request_id=(None if failure=='missing_request' else different_id if failure=='different_hardware' else prior_id)
                        claim.claimed_at=None if failure=='unconsumed' else now
                        prior.device_id=None if failure=='wrong_device' else previous
                        old.retired_at=now if failure=='retired' else None
                        await s.commit()
                    assert (await client.post(path,json=body,headers=headers)).status_code==409,failure
                    async with provider() as s:
                        assert await s.scalar(select(InstallationParent).where(InstallationParent.enrollment_request_id==rid)) is None
                        assert (await s.get(EnrollmentRequest,rid)).status=='waiting_approval'
                async with provider() as s:
                    claim=await s.get(EnrollmentClaim,claim_id);claim.enrollment_request_id=prior_id;claim.claimed_at=now
                    prior=await s.get(EnrollmentRequest,prior_id);prior.device_id=previous
                    (await s.get(Device,previous)).retired_at=None;await s.commit()
                result=await client.post(path,json=body,headers=headers);assert result.status_code==204,result.text
                history=await client.get(f'/api/admin/console/devices/{previous}/installation-events');assert history.status_code==200
                assert history.json()['installation']['state']=='removed' and len(history.json()['data'])==2
                async with provider() as s:
                    relation=await s.scalar(select(InstallationParent).where(InstallationParent.enrollment_request_id==rid))
                    assert relation.previous_device_id==previous
                    request=await s.get(EnrollmentRequest,rid);assert request.status=='approved' and request.device_id is None
                    old=await s.get(Device,previous);assert old.retired_at is None
                    credential=await s.get(DeviceCredential,cred);assert credential.revoked_at is None
                    audits=(await s.scalars(select(AuditEvent).where(AuditEvent.object_identifier==str(rid)))).all()
                    assert any(row.action=='installation.previous_linked' for row in audits)
        finally: await provider.close()
    asyncio.run(scenario())
