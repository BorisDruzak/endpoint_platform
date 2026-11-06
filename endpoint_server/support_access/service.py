"""Transactional key ownership, independently authenticated policy and leases."""
from dataclasses import dataclass
from datetime import UTC,datetime,timedelta
import hashlib
import hmac
import re
from uuid import UUID,uuid4
from sqlalchemy import select,or_
from sqlalchemy.exc import IntegrityError
from endpoint_server.db.models.devices import Device,DeviceCredential
from .models import SupportAccess


class SupportConflict(ValueError):
    pass


async def key_authority_lock(session):
    if session.bind.dialect.name=='postgresql':
        from sqlalchemy import text
        await session.execute(text('SELECT pg_advisory_xact_lock(197721, 46)'))


def utc(value):
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def tunnel_user(device_id):
    return 'eps-'+device_id.hex[:24]


def support_token(row,pepper):
    if not pepper:
        raise ValueError('Support authority unavailable')
    context=f'endpoint:support-access:v1\0{row.id}\0{row.device_id}\0{row.tunnel_public_key}\0{row.host_public_key}\0{row.generation}'
    return 'eps1.'+row.id.hex+'.'+hmac.new(pepper,context.encode(),hashlib.sha256).hexdigest()


async def register(session,device_id,credential_id,body,*,lifecycle_events=None):
    device=await session.scalar(select(Device).where(Device.id==device_id,Device.retired_at.is_(None)).with_for_update())
    if device is None:
        raise SupportConflict('Support identity unavailable')
    row=await session.scalar(select(SupportAccess).where(SupportAccess.device_id==device_id).with_for_update())
    replacing=bool(row and row.reset_registration_allowed)
    if row and not replacing:
        if row.revoked_at is not None or row.tunnel_public_key!=body.tunnel_public_key or row.host_public_key!=body.host_public_key or row.source_credential_id!=credential_id:
            raise SupportConflict('Support key ownership conflict')
        row.component_version=body.component_version
        return row
    if replacing and (body.tunnel_public_key in (row.tunnel_public_key,row.host_public_key) or body.host_public_key in (row.tunnel_public_key,row.host_public_key)):
        raise SupportConflict('Support reset requires new key roles')
    conflict=await session.scalar(select(SupportAccess.id).where(or_(SupportAccess.tunnel_public_key.in_([body.tunnel_public_key,body.host_public_key]),SupportAccess.host_public_key.in_([body.tunnel_public_key,body.host_public_key]))).limit(1))
    if conflict:
        raise SupportConflict('Support key ownership conflict')
    # Global allocation lock uses existing durable namespace row on PostgreSQL;
    # unique constraints remain final protection on every supported backend.
    if session.bind.dialect.name=='postgresql':
        await key_authority_lock(session)
        conflict=await session.scalar(select(SupportAccess.id).where(or_(SupportAccess.tunnel_public_key.in_([body.tunnel_public_key,body.host_public_key]),SupportAccess.host_public_key.in_([body.tunnel_public_key,body.host_public_key]))).limit(1))
        if conflict:
            raise SupportConflict('Support key ownership conflict')
    operators=(await session.scalars(select(SupportAccess.operator_public_keys).limit(10001))).all()
    if len(operators)>10000 or any(body.tunnel_public_key in keys or body.host_public_key in keys for keys in operators):
        raise SupportConflict('Support key ownership conflict')
    if replacing:
        row.source_credential_id=credential_id
        row.tunnel_public_key=body.tunnel_public_key;row.host_public_key=body.host_public_key
        row.component_version=body.component_version;row.reset_registration_allowed=False
        row.enabled=False;row.revoked_at=None;row.expires_at=None;row.operator_public_keys=[];row.windows_admin_username=None
        row.installed=False;row.tunnel_connected=False;row.reported_at=None;row.last_error_code=None
        row.access_verified_at=None;row.access_verified_by=None;row.revision+=1
        await session.flush()
        if lifecycle_events is not None:
            lifecycle_events.append('registration_reset_consumed')
        return row
    occupied=set((await session.scalars(select(SupportAccess.remote_port))).all())
    port=next((p for p in range(32000,42000) if p not in occupied),None)
    if port is None:
        raise SupportConflict('Support capacity unavailable')
    row=SupportAccess(id=uuid4(),device_id=device_id,source_credential_id=credential_id,tunnel_public_key=body.tunnel_public_key,host_public_key=body.host_public_key,remote_port=port,component_version=body.component_version,enabled=False,revision=1,generation=1,operator_public_keys=[],installed=False,tunnel_connected=False)
    session.add(row)
    try:
        await session.flush()
    except IntegrityError:
        raise SupportConflict('Support key ownership conflict') from None
    return row


async def source_active(session,row,now):
    d=await session.get(Device,row.device_id,populate_existing=True)
    c=await session.get(DeviceCredential,row.source_credential_id,populate_existing=True)
    return bool(d and d.retired_at is None and c and c.device_id==row.device_id and c.revoked_at is None and (c.expires_at is None or utc(c.expires_at)>now))


async def authenticate(session,token,pepper,now=None):
    now=now or datetime.now(UTC)
    if not isinstance(token,str) or re.fullmatch(r'eps1\.[0-9a-f]{32}\.[0-9a-f]{64}',token,flags=re.ASCII) is None:
        return None
    identifier=UUID(hex=token.split('.')[1])
    row=await session.scalar(select(SupportAccess).where(SupportAccess.id==identifier).with_for_update())
    if row is None or row.revoked_at is not None or not hmac.compare_digest(token,support_token(row,pepper)) or not await source_active(session,row,now):
        return None
    return row


@dataclass(frozen=True)
class BrokerLease:
    device_id: UUID
    tunnel_user: str
    remote_port: int
    tunnel_public_key: str
    host_public_key: str
    expires_at: datetime


async def get_broker_leases(session,now):
    rows=(await session.scalars(select(SupportAccess).where(SupportAccess.enabled.is_(True),SupportAccess.revoked_at.is_(None),SupportAccess.expires_at>now).order_by(SupportAccess.device_id).limit(1001))).all()
    if len(rows)>1000:
        raise SupportConflict('Support lease capacity exceeded')
    result=[]
    for row in rows:
        if not row.operator_public_keys or not row.windows_admin_username or not await source_active(session,row,now):
            continue
        credential=await session.get(DeviceCredential,row.source_credential_id)
        expiry=min(utc(row.expires_at),now+timedelta(seconds=60))
        if credential.expires_at:
            expiry=min(expiry,utc(credential.expires_at))
        result.append(BrokerLease(row.device_id,tunnel_user(row.device_id),row.remote_port,row.tunnel_public_key,row.host_public_key,expiry))
    return result
