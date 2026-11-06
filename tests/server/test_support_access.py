from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from endpoint_server.db.models import Device, DeviceCredential
from tests.contracts.test_support_access import key


@pytest.fixture
async def sessions():
    from endpoint_server.support_access.models import SupportAccess
    engine = create_async_engine('sqlite+aiosqlite:///:memory:')
    async with engine.begin() as conn:
        await conn.run_sync(lambda sync: Device.metadata.create_all(sync,tables=[Device.__table__,DeviceCredential.__table__,SupportAccess.__table__]))
    yield async_sessionmaker(engine,expire_on_commit=False)
    await engine.dispose()


async def identity(session):
    d=Device(device_identifier=uuid4().hex)
    session.add(d)
    await session.flush()
    c=DeviceCredential(device_id=d.id,credential_identifier='initial',token_digest=uuid4().hex)
    session.add(c)
    await session.flush()
    return d,c


@pytest.mark.asyncio
async def test_registration_retry_disabled_policy_and_conflicts(sessions):
    from endpoint_contracts.support_access import SupportRegistration
    from endpoint_server.support_access.service import register, support_token, SupportConflict, get_broker_leases
    async with sessions() as s:
        d,c=await identity(s)
        body=SupportRegistration(tunnel_public_key=key(),host_public_key=key(2),component_version='1.0.0')
        a=await register(s,d.id,c.id,body)
        token=support_token(a,b'pepper')
        assert a.enabled is False
        assert await get_broker_leases(s,datetime.now(UTC)) == []
        b=await register(s,d.id,c.id,body)
        assert support_token(b,b'pepper')==token
        with pytest.raises(SupportConflict):
            await register(s,d.id,c.id,body.model_copy(update={'host_public_key':key(3)}))
        other,oc=await identity(s)
        with pytest.raises(SupportConflict):
            await register(s,other.id,oc.id,body)


@pytest.mark.asyncio
async def test_broker_excludes_expired_revoked_retired_and_caps_lease(sessions):
    from endpoint_contracts.support_access import SupportRegistration
    from endpoint_server.support_access.service import register,get_broker_leases
    now=datetime.now(UTC)
    async with sessions() as s:
        d,c=await identity(s)
        r=await register(s,d.id,c.id,SupportRegistration(tunnel_public_key=key(),host_public_key=key(2),component_version='1.0.0'))
        r.enabled=True;r.expires_at=now+timedelta(hours=1);r.operator_public_keys=[key(3)];r.windows_admin_username='admin'
        await s.flush()
        leases=await get_broker_leases(s,now)
        assert len(leases)==1
        assert leases[0].expires_at<=now+timedelta(seconds=90)
        c.revoked_at=now
        await s.flush()
        assert await get_broker_leases(s,now)==[]
        c.revoked_at=None;d.retired_at=now
        await s.flush()
        assert await get_broker_leases(s,now)==[]
        d.retired_at=None;r.expires_at=now
        await s.flush()
        assert await get_broker_leases(s,now)==[]


@pytest.mark.asyncio
async def test_independent_token_does_not_accept_device_token_or_survive_revoke(sessions):
    from endpoint_contracts.support_access import SupportRegistration
    from endpoint_server.support_access.service import register,authenticate,support_token
    async with sessions() as s:
        d,c=await identity(s)
        r=await register(s,d.id,c.id,SupportRegistration(tunnel_public_key=key(),host_public_key=key(2),component_version='1.0.0'))
        token=support_token(r,b'pepper')
        assert await authenticate(s,token,b'pepper') is r
        assert await authenticate(s,c.token_digest,b'pepper') is None
        assert await authenticate(s,token,b'wrong') is None
        assert await authenticate(s,'eps1.'+r.id.hex+'.'+'я'*64,b'pepper') is None
        r.generation+=1
        await s.flush()
        assert await authenticate(s,token,b'pepper') is None
        r.generation-=1;c.revoked_at=datetime.now(UTC)
        await s.flush()
        assert await authenticate(s,token,b'pepper') is None


@pytest.mark.asyncio
async def test_exporter_produces_atomic_bounded_snapshot(sessions,tmp_path):
    import json
    from contextlib import asynccontextmanager
    from endpoint_server.support_access.exporter import export_once
    @asynccontextmanager
    async def provider():
        async with sessions() as session:
            yield session
    now=datetime.now(UTC)
    destination=tmp_path/'leases.json'
    await export_once(provider,destination,now=now)
    payload=json.loads(destination.read_text())
    assert payload['leases']==[]
    assert datetime.fromisoformat(payload['valid_until'])-datetime.fromisoformat(payload['generated_at'])==timedelta(seconds=60)
    assert list(tmp_path.iterdir())==[destination]


@pytest.mark.asyncio
async def test_registration_cannot_reuse_an_approved_operator_key(sessions):
    from endpoint_contracts.support_access import SupportRegistration
    from endpoint_server.support_access.service import register,SupportConflict
    async with sessions() as s:
        d,c=await identity(s)
        row=await register(s,d.id,c.id,SupportRegistration(tunnel_public_key=key(),host_public_key=key(2),component_version='1.0.0'))
        row.operator_public_keys=[key(3)]
        await s.flush()
        other,credential=await identity(s)
        with pytest.raises(SupportConflict):
            await register(s,other.id,credential.id,SupportRegistration(tunnel_public_key=key(3),host_public_key=key(4),component_version='1.0.0'))


@pytest.mark.asyncio
async def test_validation_never_reflects_extra_field_names():
    from starlette.requests import Request
    from fastapi.exceptions import RequestValidationError
    from endpoint_server.auth.validation import redacting_validation_exception_handler
    request=Request({'type':'http','path':'/agent/v1/support-access/register','headers':[]})
    error=RequestValidationError([{'type':'extra_forbidden','loc':('body','sensitive_extra_marker'),'msg':'Extra inputs are not permitted','input':'secret'}])
    response=await redacting_validation_exception_handler(request,error)
    assert b'sensitive_extra_marker' not in response.body


@pytest.mark.asyncio
async def test_explicit_reset_allows_one_key_replacement_with_same_device_history(sessions):
    from endpoint_contracts.support_access import SupportRegistration
    from endpoint_server.support_access.service import register,SupportConflict,support_token
    async with sessions() as s:
        d,c=await identity(s)
        old=SupportRegistration(tunnel_public_key=key(),host_public_key=key(2),component_version='1.0.0')
        row=await register(s,d.id,c.id,old)
        identity_id,port,token=row.id,row.remote_port,support_token(row,b'pepper')
        replacement=SupportRegistration(tunnel_public_key=key(3),host_public_key=key(4),component_version='1.0.1')
        with pytest.raises(SupportConflict):
            await register(s,d.id,c.id,replacement)
        row.reset_registration_allowed=True;row.revoked_at=datetime.now(UTC);row.enabled=False;row.generation+=1
        await s.flush()
        with pytest.raises(SupportConflict):
            await register(s,d.id,c.id,old)
        fresh=await register(s,d.id,c.id,replacement)
        assert fresh.id==identity_id and fresh.remote_port==port
        assert not fresh.reset_registration_allowed and fresh.revoked_at is None and not fresh.enabled
        assert support_token(fresh,b'pepper')!=token
        with pytest.raises(SupportConflict):
            await register(s,d.id,c.id,old)
