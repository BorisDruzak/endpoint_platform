"""Support bootstrap uses device auth; ongoing supervision has its own bearer."""
from datetime import UTC,datetime,timedelta
from typing import Annotated
from uuid import UUID
from fastapi import APIRouter,Depends,HTTPException,Request,Response
from sqlalchemy import select
from endpoint_contracts.support_access import (SupportRegistration,SupportRegistrationResult,SupportPolicy,SupportPolicyUpdate,SupportReason,SupportStatusReport,canonical_public_key)
from endpoint_server.audit.request_ids import audit_request_id
from endpoint_server.audit.service import append_audit_event
from endpoint_server.auth.admin_sessions import AdminPrincipal,require_admin,require_admin_update_scope
from endpoint_server.updates.agent_routes import _authenticate_device,_revalidate_device_principal,_require_agent_source,_bearer_token,_invalid_credential
from endpoint_server.setup_updates.routes import revalidate_admin
from endpoint_server.device_binding.service import consume_budget,ChallengeThrottled
from .models import SupportAccess
from .service import register,support_token,authenticate,source_active,SupportConflict,utc,tunnel_user,key_authority_lock

agent_router=APIRouter(prefix='/agent/v1/support-access',tags=['agent-support-access'])
admin_router=APIRouter(prefix='/api/admin/support-access',tags=['admin-support-access'])


async def policy(session,row,settings):
    now=datetime.now(UTC)
    configured=False
    try:
        canonical_public_key(settings.support_gateway_host_public_key)
        configured=bool(settings.support_gateway_host=='endpoint.sosnadmin.local' and settings.support_gateway_port==2222)
    except ValueError:
        pass
    enabled=bool(configured and row.enabled and row.revoked_at is None and row.expires_at and utc(row.expires_at)>now and row.operator_public_keys and row.windows_admin_username and await source_active(session,row,now))
    return SupportPolicy(device_id=row.device_id,revision=row.revision,enabled=enabled,expires_at=row.expires_at if enabled else None,gateway_host=settings.support_gateway_host,gateway_port=settings.support_gateway_port,gateway_host_public_key=settings.support_gateway_host_public_key,tunnel_user=tunnel_user(row.device_id),remote_port=row.remote_port,operator_public_keys=row.operator_public_keys if enabled else [],windows_admin_username=row.windows_admin_username if enabled else None)


async def audit(session,request,action,row,actor_kind,actor,reason=None):
    details={'device_id':str(row.device_id),'revision':row.revision}
    if reason is not None:
        details['reason']=reason
    await append_audit_event(session,actor_kind=actor_kind,actor_identifier=str(actor),action='support_access.'+action,object_kind='support_access',object_identifier=str(row.id),request_id=audit_request_id(request),details=details)


@agent_router.post('/register',response_model=SupportRegistrationResult,openapi_extra={'security':[{'AgentBearer':[]}]})
async def registration(body:SupportRegistration,request:Request,response:Response):
    response.headers['Cache-Control']='no-store'
    async with request.app.state.session_provider() as session:
        principal=await _authenticate_device(session,request)
        try:
            await consume_budget(session,'support-register:'+str(principal.device.id),limit=12,window_seconds=600)
            lifecycle=[]
            row=await register(session,principal.device.id,principal.credential.id,body,lifecycle_events=lifecycle)
            await _revalidate_device_principal(session,request,principal)
            result=SupportRegistrationResult(device_id=row.device_id,credential_id=row.id,support_token=support_token(row,request.app.state.settings.device_token_pepper),policy=await policy(session,row,request.app.state.settings))
            await audit(session,request,'registered',row,'device',row.device_id)
            for action in lifecycle:
                await audit(session,request,action,row,'device',row.device_id)
            await session.commit()
            return result
        except ChallengeThrottled:
            await session.commit()
            raise HTTPException(429,'Support registration throttled',headers={'Retry-After':'600'}) from None
        except SupportConflict:
            await session.rollback()
            raise HTTPException(409,'Support key ownership conflict') from None


async def support_identity(session,request):
    _require_agent_source(request)
    row=await authenticate(session,_bearer_token(request),request.app.state.settings.device_token_pepper)
    if row is None:
        raise _invalid_credential()
    return row


@agent_router.get('/policy',response_model=SupportPolicy,openapi_extra={'security':[{'SupportBearer':[]}]})
async def get_policy(request:Request,response:Response):
    response.headers['Cache-Control']='no-store'
    async with request.app.state.session_provider() as session:
        row=await support_identity(session,request)
        return await policy(session,row,request.app.state.settings)


@agent_router.post('/status',response_model=SupportPolicy,openapi_extra={'security':[{'SupportBearer':[]}]})
async def report(body:SupportStatusReport,request:Request,response:Response):
    response.headers['Cache-Control']='no-store'
    async with request.app.state.session_provider() as session:
        row=await support_identity(session,request)
        changed=row.tunnel_connected!=body.tunnel_connected or row.installed!=body.installed
        row.installed=body.installed;row.tunnel_connected=body.tunnel_connected;row.last_error_code=body.last_error_code;row.reported_at=datetime.now(UTC)
        result=await policy(session,row,request.app.state.settings)
        if changed:
            await audit(session,request,'status_changed',row,'device',row.device_id)
        await session.commit()
        return result


@agent_router.post('/unregister',status_code=204,openapi_extra={'security':[{'SupportBearer':[]}]})
async def unregister(request:Request):
    async with request.app.state.session_provider() as session:
        row=await support_identity(session,request)
        row.enabled=False;row.revoked_at=datetime.now(UTC);row.generation+=1;row.revision+=1
        row.reset_registration_allowed=False
        row.installed=False;row.tunnel_connected=False;row.reported_at=datetime.now(UTC)
        row.access_verified_at=None;row.access_verified_by=None
        await audit(session,request,'component_removed',row,'device',row.device_id)
        await session.commit()
    return Response(status_code=204,headers={'Cache-Control':'no-store'})


async def load(session,device_id):
    row=await session.scalar(select(SupportAccess).where(SupportAccess.device_id==device_id).with_for_update())
    if row is None:
        raise HTTPException(404,'Support component is not registered')
    return row


@admin_router.get('/devices/{device_id}')
async def admin_status(device_id:UUID,request:Request,response:Response,_:Annotated[AdminPrincipal,Depends(require_admin)]):
    response.headers['Cache-Control']='no-store'
    async with request.app.state.session_provider() as session:
        row=await load(session,device_id)
        return {'policy':await policy(session,row,request.app.state.settings),'component_version':row.component_version,'installed':row.installed,'tunnel_connected':row.tunnel_connected,'reported_at':row.reported_at,'last_error_code':row.last_error_code,'host_public_key':row.host_public_key,'access_verified_at':row.access_verified_at,'access_verified_by':row.access_verified_by,'verification_kind':'operator_attestation','revoked_at':row.revoked_at,'reset_registration_allowed':row.reset_registration_allowed}


@admin_router.put('/devices/{device_id}/policy',response_model=SupportPolicy)
async def update_policy(device_id:UUID,body:SupportPolicyUpdate,request:Request,principal:Annotated[AdminPrincipal,Depends(require_admin_update_scope)]):
    async with request.app.state.session_provider() as session:
        row=await load(session,device_id)
        now=datetime.now(UTC)
        if body.enabled:
            if row.reset_registration_allowed:
                raise HTTPException(409,'Support registration reset is pending')
            await key_authority_lock(session)
            role_conflict=await session.scalar(select(SupportAccess.id).where(
                (SupportAccess.tunnel_public_key.in_(body.operator_public_keys)) |
                (SupportAccess.host_public_key.in_(body.operator_public_keys))).limit(1))
            if role_conflict:
                raise HTTPException(409,'Support key roles conflict')
            try:
                canonical_public_key(request.app.state.settings.support_gateway_host_public_key)
            except ValueError:
                raise HTTPException(409,'Support gateway is not configured') from None
            if not await source_active(session,row,now) or body.expires_at is None or body.expires_at.tzinfo is None or not now<body.expires_at<=now+timedelta(hours=8) or not body.operator_public_keys or not body.windows_admin_username or any(k in (row.tunnel_public_key,row.host_public_key) for k in body.operator_public_keys):
                raise HTTPException(422,'Invalid bounded support policy')
            # Explicit administrator authorization is required to recover a
            # revoked installation. Generation stays advanced: only durable
            # device bootstrap can obtain the new independent credential.
            row.revoked_at=None
        row.enabled=body.enabled;row.expires_at=body.expires_at if body.enabled else None;row.operator_public_keys=body.operator_public_keys;row.windows_admin_username=body.windows_admin_username;row.revision+=1;row.access_verified_at=None;row.access_verified_by=None
        await audit(session,request,'policy_changed',row,'admin',principal.user.id,body.reason)
        await revalidate_admin(request,session,principal)
        result=await policy(session,row,request.app.state.settings)
        await session.commit()
        return result


@admin_router.post('/devices/{device_id}/revoke',status_code=204)
async def revoke(device_id:UUID,body:SupportReason,request:Request,principal:Annotated[AdminPrincipal,Depends(require_admin_update_scope)]):
    async with request.app.state.session_provider() as session:
        row=await load(session,device_id)
        row.enabled=False;row.revoked_at=datetime.now(UTC);row.revision+=1;row.generation+=1;row.access_verified_at=None;row.access_verified_by=None
        row.reset_registration_allowed=False
        await audit(session,request,'revoked',row,'admin',principal.user.id,body.reason)
        await revalidate_admin(request,session,principal)
        await session.commit()
    return Response(status_code=204)


@admin_router.post('/devices/{device_id}/reset-registration',status_code=204)
async def reset_registration(device_id:UUID,body:SupportReason,request:Request,principal:Annotated[AdminPrincipal,Depends(require_admin_update_scope)]):
    async with request.app.state.session_provider() as session:
        row=await load(session,device_id)
        row.enabled=False;row.revoked_at=datetime.now(UTC);row.generation+=1;row.revision+=1
        row.reset_registration_allowed=True;row.expires_at=None
        row.access_verified_at=None;row.access_verified_by=None
        await audit(session,request,'registration_reset_authorized',row,'admin',principal.user.id,body.reason)
        await revalidate_admin(request,session,principal)
        await session.commit()
    return Response(status_code=204,headers={'Cache-Control':'no-store'})


@admin_router.post('/devices/{device_id}/verify-access')
async def verify_access(device_id:UUID,body:SupportReason,request:Request,principal:Annotated[AdminPrincipal,Depends(require_admin_update_scope)]):
    async with request.app.state.session_provider() as session:
        row=await load(session,device_id)
        if not (await policy(session,row,request.app.state.settings)).enabled:
            raise HTTPException(409,'Support access is not enabled')
        row.access_verified_at=datetime.now(UTC);row.access_verified_by=str(principal.user.id)
        await audit(session,request,'operator_attested_access',row,'admin',principal.user.id,body.reason)
        await revalidate_admin(request,session,principal)
        await session.commit()
        return {'access_verified_at':row.access_verified_at,'verification_kind':'operator_attestation'}
