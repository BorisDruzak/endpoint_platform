"""Disposable-DB browser binding, self-only scope and same-person AD adoption."""
import asyncio
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from ipaddress import ip_network
from types import SimpleNamespace
from unittest.mock import AsyncMock
from urllib.parse import parse_qs,urlsplit
from uuid import uuid4,UUID

import httpx
import pytest
from sqlalchemy import select,func
from tests.server.test_identity_sso_postgres import sso_database
from tests.server.test_identity_sso import provider_fixture
from endpoint_server.config import Settings
from endpoint_server.main import create_app
from endpoint_server.db.session import create_session_provider
from endpoint_server.db.models.identity import ConfirmedIdentity,ScopedRoleGrant
from endpoint_server.db.models.administration import AdminUser
from endpoint_server.db.models.worktime_sessions import WorktimeLoginFlow,HelpdeskWorktimeSession
from endpoint_server.worktime.models import WorkState
from endpoint_server.identity.worktime_client import WorktimeIdentity,WorktimeAuthorityError
from endpoint_server.auth.worktime_protocol import WORKTIME_COOKIE,FLOW_COOKIE
from endpoint_server.auth.csrf import csrf_token_for_session


pytestmark=pytest.mark.usefixtures('preserve_migration_loggers')

def application(database,tmp_path):
    oidc=provider_fixture()
    oidc.settings=replace(oidc.settings,helpdesk_base_url='https://helpdesk-staging.sosnadmin.local')
    settings=Settings(database_url=database,public_base_url='https://endpoint-staging.sosnadmin.local',device_token_pepper=b'device',service_token_pepper=b'service',session_secret=b'secret'*8,
        allowed_agent_cidrs=(ip_network('127.0.0.0/8'),),allowed_admin_cidrs=(ip_network('127.0.0.0/8'),),artifact_root=tmp_path,oidc=oidc.settings,worktime_enabled=True,worktime_helpdesk_enabled=True)
    provider=create_session_provider(database);app=create_app(settings,session_provider=provider);app.state.oidc_provider=oidc
    person=WorktimeIdentity(uuid4(),uuid4(),datetime.now(UTC)+timedelta(hours=1),'h'*43)
    client=SimpleNamespace(exchange=AsyncMock(return_value=person),introspect=AsyncMock(return_value=person))
    app.state.worktime_identity_client=client
    return app,provider,settings,person,oidc


async def handoff(client,settings):
    start=await client.get('/auth/worktime/helpdesk/login');assert start.status_code==303
    target=urlsplit(start.headers['location']);assert target.hostname=='helpdesk-staging.sosnadmin.local'
    query=parse_qs(target.query);assert query['code_challenge_method']==['S256']
    return {'code':'c'*43,'state':query['state'][0]}


@pytest.mark.asyncio
async def test_handoff_is_browser_bound_single_use_self_only_and_own_csrf(sso_database,tmp_path):
    app,provider,settings,person,_=application(sso_database,tmp_path)
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app),base_url=settings.public_base_url,follow_redirects=False) as client:
            body=await handoff(client,settings)
            assert (await client.post('/auth/worktime/helpdesk/callback',data=body,headers={'origin':'https://evil.test'})).status_code==400
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app),base_url=settings.public_base_url) as other:
                assert (await other.post('/auth/worktime/helpdesk/callback',data=body,headers={'origin':settings.oidc.helpdesk_base_url})).status_code==400
            results=await asyncio.gather(*[client.post('/auth/worktime/helpdesk/callback',data=body,headers={'origin':settings.oidc.helpdesk_base_url}) for _ in range(2)])
            assert sorted(item.status_code for item in results)==[303,401]
            app.state.worktime_identity_client.exchange.assert_awaited_once()
            raw=client.cookies.get(WORKTIME_COOKIE);assert raw and len(raw)==43
            session=await client.get('/api/employee/worktime/session');assert session.status_code==200
            payload=session.json();assert payload['person_id']==str(person.person_id) and payload['grants']==[] and payload['privileged_assurance'] is False
            assert (await client.get('/api/employee/session')).status_code==401
            assert (await client.get('/api/employee/worktime/categories')).status_code==200
            assert (await client.get('/api/employee/worktime/day',params={'day':'2026-11-05','person_id':str(uuid4())})).status_code==403
            async with provider() as db:
                assert await db.scalar(select(func.count()).select_from(WorkState))==0
                identity=await db.scalar(select(ConfirmedIdentity).where(ConfirmedIdentity.person_id==person.person_id))
                assert identity.authority_kind=='helpdesk' and identity.ad_object_guid is None
                admin=AdminUser(username='isolated-grant-owner',password_digest='unused',scopes=[]);db.add(admin);await db.flush()
                db.add(ScopedRoleGrant(identity_id=identity.id,role='worktime_admin',granted_by=admin.id));await db.commit()
            # Even an existing privileged grant on the same identity is not inherited.
            again=await client.get('/api/employee/worktime/session');assert again.json()['grants']==[]
            people=await client.get('/api/employee/worktime/people');assert [row['person_id'] for row in people.json()['people']]==[str(person.person_id)]
            assert (await client.delete('/api/employee/worktime/session')).status_code==403
            assert (await client.delete('/api/employee/worktime/session',headers={'x-csrf-token':csrf_token_for_session('a'*43,settings.session_secret)})).status_code==403
            app.state.worktime_identity_client.introspect.side_effect=WorktimeAuthorityError(503)
            assert (await client.get('/api/employee/worktime/session')).status_code==503
            app.state.worktime_identity_client.introspect.side_effect=WorktimeAuthorityError(401)
            assert (await client.get('/api/employee/worktime/session')).status_code==401
            app.state.worktime_identity_client.introspect.side_effect=None
            assert (await client.delete('/api/employee/worktime/session',headers={'x-csrf-token':payload['csrf_token']})).status_code==204
            assert client.cookies.get(WORKTIME_COOKIE) is None
    finally:await provider.close()


@pytest.mark.asyncio
async def test_explicit_ad_login_adopts_local_person_without_moving_history(sso_database,tmp_path):
    app,provider,settings,person,oidc=application(sso_database,tmp_path)
    app.state.helpdesk_identity_client=SimpleNamespace(resolve=AsyncMock(return_value=SimpleNamespace(person_id=person.person_id,department_id=person.department_id)))
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app),base_url=settings.public_base_url,follow_redirects=False) as client:
            body=await handoff(client,settings)
            assert (await client.post('/auth/worktime/helpdesk/callback',data=body,headers={'origin':settings.oidc.helpdesk_base_url})).status_code==303
            async with provider() as db:
                identity=await db.scalar(select(ConfirmedIdentity).where(ConfirmedIdentity.person_id==person.person_id));original=identity.id
                db.add(WorkState(person_id=person.person_id,status='ENDED'));await db.commit()
            start=await client.get('/auth/employee/login?worktime=1');query=parse_qs(urlsplit(start.headers['location']).query)
            oidc.fixture_claims['nonce']=query['nonce'][0]
            from endpoint_server.auth.oidc import unseal
            from endpoint_server.db.models.identity import OIDCFlow
            async with provider() as db:
                flow=await db.scalar(select(OIDCFlow));oidc.expected_verifier=unseal(settings.oidc,flow.encrypted_material)['verifier']
            result=await client.get('/auth/employee/callback',params={'code':'fixture-ad-code','state':query['state'][0]})
            assert result.status_code==303 and client.cookies.get(WORKTIME_COOKIE) is None
            assert client.cookies.get('endpoint_employee_session')
            async with provider() as db:
                identity=await db.scalar(select(ConfirmedIdentity).where(ConfirmedIdentity.person_id==person.person_id))
                assert identity.id==original and identity.authority_kind=='oidc' and identity.ad_object_guid==UUID(oidc.fixture_claims['ad_object_guid'])
                assert (await db.scalar(select(WorkState).where(WorkState.person_id==person.person_id))).status=='ENDED'
            assert (await client.get('/api/employee/worktime/session')).status_code==200
    finally:await provider.close()
