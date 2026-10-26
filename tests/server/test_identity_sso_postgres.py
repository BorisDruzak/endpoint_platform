"""Disposable PostgreSQL callback/session integration and concurrent state consumption."""
import asyncio
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from ipaddress import ip_network
import os
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit
from unittest.mock import AsyncMock
from uuid import uuid4

import asyncpg
from alembic import command
from alembic.config import Config
from fastapi import HTTPException
import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.engine import make_url

from endpoint_server.auth.admin_sessions import session_digest
from endpoint_server.auth.admin_sessions import issue_admin_session
from endpoint_server.auth.oidc_config import OIDCSettings
from endpoint_server.auth.passwords import hash_password
from endpoint_server.auth.oidc import consume_flow
from endpoint_server.config import Settings
from endpoint_server.db.models.identity import EmployeeSession, OIDCFlow, UpstreamSession
from endpoint_server.db.models import AdminUser, AdminSession, AuditEvent
from endpoint_server.db.session import create_session_provider
from endpoint_server.main import create_app
from tests.server.test_identity_sso import provider_fixture

pytestmark = pytest.mark.usefixtures('preserve_migration_loggers')


async def execute(url,sql):
    connection=await asyncpg.connect(url)
    try:
        await connection.execute(sql)
    finally:
        await connection.close()


@pytest.fixture
def sso_database(monkeypatch):
    raw=os.environ.get('ENDPOINT_TEST_POSTGRES_URL')
    if not raw:
        pytest.skip('requires disposable loopback ENDPOINT_TEST_POSTGRES_URL')
    parsed=make_url(raw)
    if parsed.host not in {'127.0.0.1','localhost','::1'}:
        pytest.fail('SSO tests require loopback PostgreSQL')
    admin=parsed.set(drivername='postgresql').render_as_string(hide_password=False)
    name='endpoint_sso_'+uuid4().hex
    asyncio.run(execute(admin,f'CREATE DATABASE "{name}"'))
    url=parsed.set(drivername='postgresql+asyncpg',database=name).render_as_string(hide_password=False)
    monkeypatch.setenv('DATABASE_URL',url)
    try:
        config=Config(Path(__file__).resolve().parents[2]/'alembic.ini')
        command.upgrade(config,'head')
        yield url
    finally:
        asyncio.run(execute(admin,"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '"+name+"' AND pid <> pg_backend_pid()"))
        asyncio.run(execute(admin,f'DROP DATABASE "{name}"'))


@pytest.mark.asyncio
async def test_state_consumption_is_serialized_across_database_sessions(sso_database):
    provider=create_session_provider(sso_database)
    now=datetime.now(UTC)
    try:
        async with provider() as session:
            session.add(OIDCFlow(state_digest=session_digest('state',b'secret'),browser_digest='browser',realm='employee',encrypted_material='opaque',expires_at=now+timedelta(minutes=5),consumed_at=None))
            await session.commit()
        async def attempt():
            async with provider() as session:
                try:
                    await consume_flow(session,'state','browser','employee',b'secret')
                    return 'consumed'
                except HTTPException as error:
                    return error.status_code
        assert sorted(await asyncio.gather(attempt(),attempt()),key=str)==[401,'consumed']
    finally:
        await provider.close()


@pytest.mark.asyncio
async def test_migrated_admin_local_bypass_requires_new_bounded_audited_breakglass(sso_database,tmp_path):
    settings=Settings(database_url=sso_database,public_base_url='https://endpoint.example',device_token_pepper=b'device',service_token_pepper=b'service',session_secret=b'secret'*8,
        allowed_agent_cidrs=(ip_network('127.0.0.0/8'),),allowed_admin_cidrs=(ip_network('127.0.0.0/8'),),artifact_root=tmp_path)
    provider=create_session_provider(sso_database)
    user=AdminUser(id=uuid4(),username='explicit-emergency-admin',password_digest=hash_password('test-password'),scopes=[],sso_migrated_at=datetime.now(UTC))
    old=issue_admin_session(user.id,settings.session_secret)
    async with provider() as session:
        session.add(user)
        await session.flush()
        session.add(old.record)
        await session.commit()
    app=create_app(settings,session_provider=provider)
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app),base_url=settings.public_base_url) as client:
            client.cookies.set('endpoint_admin_session',old.token)
            assert (await client.get('/api/admin/console/session')).status_code==401
            body={'username':user.username,'password':'test-password'}
            assert (await client.post('/api/admin/session',json=body)).status_code==401
            until=datetime.now(UTC)+timedelta(minutes=20)
            app.state.settings=replace(settings,oidc=OIDCSettings(breakglass_usernames=(user.username,),breakglass_until=until))
            # Enabling emergency login does not resurrect an older local cookie.
            assert (await client.get('/api/admin/console/session')).status_code==401
            issued=await client.post('/api/admin/session',json=body)
            assert issued.status_code==201
            assert (await client.get('/api/admin/console/session')).status_code==200
            async with provider() as session:
                emergency=await session.scalar(select(AdminSession).where(AdminSession.auth_method=='breakglass'))
                assert emergency.expires_at<=until
                event=await session.scalar(select(AuditEvent).where(AuditEvent.action=='admin_breakglass_session.created'))
                assert event.actor_identifier==str(user.id)
            app.state.settings=replace(settings,oidc=OIDCSettings(breakglass_usernames=(user.username,),breakglass_until=datetime.now(UTC)-timedelta(seconds=1)))
            assert (await client.get('/api/admin/console/session')).status_code==401
            assert (await client.post('/api/admin/session',json=body)).status_code==401
            # Expired emergency sessions can still be locally revoked with CSRF.
            assert (await client.delete('/api/admin/session',headers={'x-csrf-token':issued.json()['csrf_token']})).status_code==204
    finally:
        await provider.close()


@pytest.mark.asyncio
async def test_real_authlib_bff_persists_opaque_employee_cookie_and_encrypted_tokens(sso_database,tmp_path):
    oidc=provider_fixture()
    settings=Settings(database_url=sso_database,public_base_url='https://endpoint.example',device_token_pepper=b'device',service_token_pepper=b'service',session_secret=b'secret'*8,
        allowed_agent_cidrs=(ip_network('127.0.0.0/8'),),allowed_admin_cidrs=(ip_network('127.0.0.0/8'),),artifact_root=tmp_path,oidc=oidc.settings)
    provider=create_session_provider(sso_database)
    app=create_app(settings,session_provider=provider)
    app.state.oidc_provider=oidc
    person_id=uuid4()
    app.state.helpdesk_identity_client=SimpleNamespace(resolve=AsyncMock(return_value=SimpleNamespace(person_id=person_id,department_id=None)))
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app),base_url=settings.public_base_url,follow_redirects=False) as client:
            assert (await client.get('/auth/employee/callback?code=code')).status_code==401
            start=await client.get('/auth/employee/login')
            assert start.status_code==303
            query=parse_qs(urlsplit(start.headers['location']).query)
            oidc.fixture_claims['nonce']=query['nonce'][0]
            callback='/auth/employee/callback?code=code&state='+query['state'][0]
            async with provider() as session:
                row=await session.scalar(select(OIDCFlow))
                from endpoint_server.auth.oidc import unseal
                material=unseal(oidc.settings,row.encrypted_material)
                assert query['code_challenge_method']==['S256']
                oidc.expected_verifier=material['verifier']
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app),base_url=settings.public_base_url) as other:
                assert (await other.get(callback)).status_code==401
            completed=await client.get(callback)
            assert completed.status_code==303
            raw=client.cookies.get('endpoint_employee_session')
            assert raw and len(raw)==43
            safe=await client.get('/api/employee/session')
            assert safe.status_code==200
            assert safe.json()['person_id']==str(person_id)
            assert 'access_token' not in safe.text
            async with provider() as session:
                upstream=await session.scalar(select(UpstreamSession))
                upstream.expires_at=datetime.now(UTC)-timedelta(minutes=5)
                upstream.checked_at=datetime.now(UTC)-timedelta(minutes=10)
                await session.commit()
            # A valid persisted refresh session survives an access-token gap;
            # concurrent portal reads spend the rotating refresh token only once.
            replies=await asyncio.gather(client.get('/api/employee/session'),client.get('/api/employee/session'))
            assert [reply.status_code for reply in replies]==[200,200]
            assert oidc.refresh_requests==1
            assert (await client.get(callback)).status_code==401
            async with provider() as session:
                upstream=await session.scalar(select(UpstreamSession))
                record=await session.scalar(select(EmployeeSession))
                assert record.session_digest==session_digest(raw,settings.session_secret)
                assert 'access-token' not in upstream.encrypted_tokens
                assert raw not in record.session_digest
                assert upstream.sid=='upstream-session'
            assert (await client.delete('/api/employee/session')).status_code==403
            app.state.oidc_provider=SimpleNamespace(introspect=AsyncMock(side_effect=RuntimeError('provider down')))
            assert (await client.delete('/api/employee/session',headers={'x-csrf-token':safe.json()['csrf_token']})).status_code==204
            assert (await client.get('/api/employee/session')).status_code==401
    finally:
        await provider.close()
