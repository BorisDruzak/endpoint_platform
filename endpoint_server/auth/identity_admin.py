"""Explicit audited identity administration, separate from technical admin rights."""
from datetime import UTC, datetime
from typing import Literal
from uuid import UUID, uuid4
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, model_validator
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from endpoint_server.auth.admin_sessions import AdminPrincipal, normalize_admin_scopes, require_admin
from endpoint_server.audit.request_ids import audit_request_id
from endpoint_server.audit.service import append_audit_event
from endpoint_server.db.models import AdminUser
from endpoint_server.db.models.identity import ConfirmedIdentity, ScopedRoleGrant


async def require_identity_manager(principal: AdminPrincipal=Depends(require_admin)):
    try:
        scopes=normalize_admin_scopes(principal.user.scopes)
    except (TypeError,ValueError):
        raise HTTPException(403,'Identity management scope required') from None
    if scopes != principal.user.scopes or 'identities:manage' not in scopes:
        raise HTTPException(403,'Identity management scope required')
    return principal


router=APIRouter(prefix='/api/admin/identities',tags=['identity-administration'])


class AdminLink(BaseModel):
    model_config=ConfigDict(extra='forbid')
    admin_user_id: UUID | None


class RoleGrant(BaseModel):
    model_config=ConfigDict(extra='forbid')
    role: Literal['employee','manager','hr','worktime_admin','endpoint_admin','dlp_officer']
    department_id: UUID | None = None

    @model_validator(mode='after')
    def validate_scope(self):
        if self.role=='manager' and self.department_id is None:
            raise ValueError('Manager requires one explicit department')
        return self


async def confirmed_target(request,session,identity_id):
    target=await session.scalar(select(ConfirmedIdentity).where(ConfirmedIdentity.id==identity_id).with_for_update())
    if target is None or target.state!='active' or target.revoked_at is not None:
        raise HTTPException(404,'Active confirmed identity required')
    client=request.app.state.helpdesk_identity_client
    if client is None:
        raise HTTPException(503,'Identity authority unavailable')
    try:
        remote=await client.resolve(target.issuer,target.subject,target.ad_object_guid)
        if remote.person_id!=target.person_id:
            raise ValueError('Binding changed')
    except Exception:
        raise HTTPException(503,'Identity authority unavailable') from None
    return target


async def audit(request,session,principal,target,action,details):
    await append_audit_event(session,actor_kind='admin',actor_identifier=str(principal.user.id),action=action,
        object_kind='confirmed_identity',object_identifier=str(target.id),request_id=audit_request_id(request),details=details)


@router.post('/{identity_id}/admin-link')
async def link_admin(identity_id:UUID,body:AdminLink,request:Request,response:Response,principal=Depends(require_identity_manager)):
    async with request.app.state.session_provider() as session:
        if body.admin_user_id is None:
            target=await session.scalar(select(ConfirmedIdentity).where(ConfirmedIdentity.id==identity_id).with_for_update())
            if target is None:
                raise HTTPException(404,'Identity unavailable')
        else:
            target=await confirmed_target(request,session,identity_id)
        if body.admin_user_id is not None:
            user=await session.scalar(select(AdminUser).where(AdminUser.id==body.admin_user_id,AdminUser.disabled_at.is_(None)))
            if user is None:
                raise HTTPException(404,'Active existing administrator required')
            if user.sso_migrated_at is None:
                user.sso_migrated_at=datetime.now(UTC)
        previous=target.admin_user_id
        target.admin_user_id=body.admin_user_id
        await audit(request,session,principal,target,'identity.admin_link.changed',{'previous_admin_id':str(previous) if previous else None,'admin_id':str(body.admin_user_id) if body.admin_user_id else None})
        try:
            await session.commit()
        except IntegrityError:
            await session.rollback()
            raise HTTPException(409,'Administrator already linked') from None
    response.headers['Cache-Control']='no-store'
    return {'identity_id':str(identity_id),'admin_user_id':str(body.admin_user_id) if body.admin_user_id else None}


@router.post('/{identity_id}/grants',status_code=201)
async def grant_role(identity_id:UUID,body:RoleGrant,request:Request,response:Response,principal=Depends(require_identity_manager)):
    async with request.app.state.session_provider() as session:
        target=await confirmed_target(request,session,identity_id)
        grant=await session.scalar(select(ScopedRoleGrant).where(ScopedRoleGrant.identity_id==identity_id,ScopedRoleGrant.role==body.role,
            ScopedRoleGrant.department_id==body.department_id,ScopedRoleGrant.revoked_at.is_(None)))
        if grant is None:
            grant=ScopedRoleGrant(id=uuid4(),identity_id=identity_id,role=body.role,department_id=body.department_id,granted_by=principal.user.id,revoked_at=None)
            session.add(grant)
            await audit(request,session,principal,target,'identity.role.granted',{'grant_id':str(grant.id),'role':body.role,'department_id':str(body.department_id) if body.department_id else None})
            await session.commit()
    response.headers['Cache-Control']='no-store'
    return {'grant_id':str(grant.id),'role':grant.role,'department_id':str(grant.department_id) if grant.department_id else None}


@router.delete('/{identity_id}/grants/{grant_id}',status_code=204)
async def revoke_role(identity_id:UUID,grant_id:UUID,request:Request,principal=Depends(require_identity_manager)):
    async with request.app.state.session_provider() as session:
        # Revocation must remain available during provider outages.
        target=await session.scalar(select(ConfirmedIdentity).where(ConfirmedIdentity.id==identity_id).with_for_update())
        grant=await session.scalar(select(ScopedRoleGrant).where(ScopedRoleGrant.id==grant_id,ScopedRoleGrant.identity_id==identity_id).with_for_update())
        if target is None or grant is None:
            raise HTTPException(404,'Grant unavailable')
        if grant.revoked_at is None:
            grant.revoked_at=datetime.now(UTC)
            await audit(request,session,principal,target,'identity.role.revoked',{'grant_id':str(grant.id),'role':grant.role})
            await session.commit()
    return Response(status_code=204,headers={'Cache-Control':'no-store'})
