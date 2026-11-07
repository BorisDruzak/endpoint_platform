"""Transactional key ownership, independently authenticated policy and leases."""
from dataclasses import dataclass
from datetime import UTC,datetime,timedelta
import hashlib
import hmac
import re
from uuid import UUID,uuid4
from sqlalchemy import select,or_
from sqlalchemy.exc import IntegrityError
from endpoint_contracts.support_access import SUPPORT_COMPONENT_VERSION_PATTERN
from endpoint_server.db.models.devices import Device,DeviceCredential
from .models import SupportAccess
from .platforms import LINUX, WINDOWS, verified_platform, principal_bound


class SupportConflict(ValueError):
    pass


class SupportResetRequired(SupportConflict):
    """A locked, explicitly reset device must replace its retained SSH keys."""
    def __init__(self,device_id):
        self.reset_device_id=device_id
        super().__init__('Support reset requires new key roles')


def supports_domain_principal(component_version: str) -> bool:
    """Domain identity validation first shipped in component1.0.1."""
    if not isinstance(component_version,str) or re.fullmatch(SUPPORT_COMPONENT_VERSION_PATTERN,component_version,flags=re.ASCII) is None:
        return False
    return tuple(int(part) for part in component_version.split('.')) >= (1,0,1)


def domain_principal_available(row,now) -> bool:
    return bool(row.installed and row.reported_at is not None and
        -timedelta(seconds=30) <= now-utc(row.reported_at) <= timedelta(seconds=90) and
        supports_domain_principal(row.component_version))


def policy_component_available(row,now) -> bool:
    if getattr(row,'platform',WINDOWS)==LINUX:
        return bool(row.installed and row.reported_at is not None and row.component_version=='1.0.0' and
            row.last_error_code is None and -timedelta(seconds=30)<=now-utc(row.reported_at)<=timedelta(seconds=90))
    return '\\' not in (row.windows_admin_username or '') or domain_principal_available(row,now)


def record_runtime_status(row,body,now) -> bool:
    version=body.component_version if body.component_version is not None else '1.0.0'
    changed=(row.installed!=body.installed or row.tunnel_connected!=body.tunnel_connected or
             row.component_version!=version or row.last_error_code!=body.last_error_code)
    row.installed=body.installed;row.tunnel_connected=body.tunnel_connected
    row.component_version=version;row.last_error_code=body.last_error_code;row.reported_at=now
    return changed


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


async def register(session,device_id,credential_id,body,*,lifecycle_events=None,settings=None,now=None,request_id=None,platform=WINDOWS):
    now=now or datetime.now(UTC)
    configured_keys=tuple(settings.support_install_operator_public_keys)+tuple(settings.support_linux_install_operator_public_keys) if settings is not None else ()
    if settings is not None and (body.tunnel_public_key in (*configured_keys,settings.support_gateway_host_public_key) or
                                body.host_public_key in (*configured_keys,settings.support_gateway_host_public_key)):
        raise SupportConflict('Support key ownership conflict')
    device=await session.scalar(select(Device).where(Device.id==device_id,Device.retired_at.is_(None)).with_for_update())
    if device is None:
        raise SupportConflict('Support identity unavailable')
    if platform not in (WINDOWS,LINUX) or (platform==LINUX and await verified_platform(session,device_id)!=LINUX):
        raise SupportConflict('Support platform is unavailable')
    row=await session.scalar(select(SupportAccess).where(SupportAccess.device_id==device_id).with_for_update())
    if row is not None and row.platform!=platform:
        raise SupportConflict('Support platform does not match registration')
    replacing=bool(row and row.reset_registration_allowed)
    ticket = None
    if row and not replacing and (row.revoked_at is not None or row.tunnel_public_key != body.tunnel_public_key or row.host_public_key != body.host_public_key):
        from .native_rebind import native_ticket
        ticket = await native_ticket(session,row,credential_id,now)
    if row and not replacing and ticket is None:
        if row.revoked_at is not None or row.tunnel_public_key!=body.tunnel_public_key or row.host_public_key!=body.host_public_key or row.source_credential_id!=credential_id:
            raise SupportConflict('Support key ownership conflict')
        # Registration is an installer intent. Only running-service status may
        # advance or downgrade observed runtime capability after activation.
        if settings is not None:
            from .installation import queue_installation_access
            await queue_installation_access(session,row,settings,now,request_id=request_id)
        return row
    if replacing and (body.tunnel_public_key in (row.tunnel_public_key,row.host_public_key) or body.host_public_key in (row.tunnel_public_key,row.host_public_key)):
        raise SupportResetRequired(device_id)
    conflict=await session.scalar(select(SupportAccess.id).where(or_(SupportAccess.tunnel_public_key.in_([body.tunnel_public_key,body.host_public_key]),SupportAccess.host_public_key.in_([body.tunnel_public_key,body.host_public_key])), SupportAccess.id != (row.id if ticket is not None else UUID(int=0))).limit(1))
    if conflict:
        raise SupportConflict('Support key ownership conflict')
    # Global allocation lock uses existing durable namespace row on PostgreSQL;
    # unique constraints remain final protection on every supported backend.
    if session.bind.dialect.name=='postgresql':
        await key_authority_lock(session)
        conflict=await session.scalar(select(SupportAccess.id).where(or_(SupportAccess.tunnel_public_key.in_([body.tunnel_public_key,body.host_public_key]),SupportAccess.host_public_key.in_([body.tunnel_public_key,body.host_public_key])), SupportAccess.id != (row.id if ticket is not None else UUID(int=0))).limit(1))
        if conflict:
            raise SupportConflict('Support key ownership conflict')
    operators=(await session.scalars(select(SupportAccess.operator_public_keys).limit(10001))).all()
    if len(operators)>10000 or any(body.tunnel_public_key in keys or body.host_public_key in keys for keys in operators):
        raise SupportConflict('Support key ownership conflict')
    if ticket is not None:
        if body.tunnel_public_key == row.host_public_key or body.host_public_key == row.tunnel_public_key:
            raise SupportConflict('Support key ownership conflict')
        # The role lock may have waited past the original registration timestamp.
        # Recheck the one-use deadline immediately before changing any key material.
        checked_at=max(now,datetime.now(UTC))
        if ticket.support_rebind_until is None or utc(ticket.support_rebind_until)<=checked_at:
            raise SupportConflict('Native Support rebind expired')
        from .native_rebind import consume_native_ticket
        row.tunnel_public_key=body.tunnel_public_key;row.host_public_key=body.host_public_key
        await consume_native_ticket(session,row,ticket,settings,checked_at,request_id)
        await session.flush()
        return row
    if replacing:
        row.source_credential_id=credential_id
        row.tunnel_public_key=body.tunnel_public_key;row.host_public_key=body.host_public_key
        row.component_version='1.0.0';row.reset_registration_allowed=False
        row.linux_admin_username=None;row.linux_admin_uid=None
        row.enabled=False;row.revoked_at=None;row.expires_at=None;row.operator_public_keys=[];row.windows_admin_username=None
        row.installed=False;row.tunnel_connected=False;row.reported_at=None;row.last_error_code=None
        row.access_verified_at=None;row.access_verified_by=None;row.revision+=1
        row.installation_access_pending_until=None
        await session.flush()
        if lifecycle_events is not None:
            lifecycle_events.append('registration_reset_consumed')
        return row
    occupied=set((await session.scalars(select(SupportAccess.remote_port))).all())
    port=next((p for p in range(32000,42000) if p not in occupied),None)
    if port is None:
        raise SupportConflict('Support capacity unavailable')
    row=SupportAccess(id=uuid4(),platform=platform,device_id=device_id,source_credential_id=credential_id,tunnel_public_key=body.tunnel_public_key,host_public_key=body.host_public_key,remote_port=port,component_version='1.0.0',enabled=False,revision=1,generation=1,operator_public_keys=[],installed=False,tunnel_connected=False)
    session.add(row)
    try:
        await session.flush()
    except IntegrityError:
        raise SupportConflict('Support key ownership conflict') from None
    if settings is not None:
        from .installation import queue_installation_access
        await queue_installation_access(session,row,settings,now,request_id=request_id)
    return row


async def consume_installation_access(session,row,settings,now,*,request_id=None):
    from .installation import consume_installation_access as consume
    await consume(session,row,settings,now,request_id=request_id)


async def source_active(session,row,now):
    d=await session.get(Device,row.device_id,populate_existing=True)
    c=await session.get(DeviceCredential,row.source_credential_id,populate_existing=True)
    if getattr(row,'platform',WINDOWS)==LINUX and await verified_platform(session,row.device_id)!=LINUX:
        return False
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
        if not row.operator_public_keys or not principal_bound(row) or not policy_component_available(row,now) or not await source_active(session,row,now):
            continue
        credential=await session.get(DeviceCredential,row.source_credential_id)
        expiry=min(utc(row.expires_at),now+timedelta(seconds=60))
        if credential.expires_at:
            expiry=min(expiry,utc(credential.expires_at))
        result.append(BrokerLease(row.device_id,tunnel_user(row.device_id),row.remote_port,row.tunnel_public_key,row.host_public_key,expiry))
    return result
