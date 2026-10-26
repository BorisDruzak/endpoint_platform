"""Employee cookie authority, independent of devices, services and administrators."""
from dataclasses import dataclass
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import select

from endpoint_server.auth.admin_sessions import _is_opaque_session_token, session_digest
from endpoint_server.auth.csrf import csrf_token_for_session, enforce_csrf
from endpoint_server.auth.oidc import EMPLOYEE_SESSION_COOKIE, revalidate_upstream
from endpoint_server.db.models.identity import ConfirmedIdentity, EmployeeSession, ScopedRoleGrant, UpstreamSession

router = APIRouter(prefix='/api/employee',tags=['employee-session'])


@dataclass(frozen=True, slots=True)
class EmployeePrincipal:
    identity: ConfirmedIdentity
    session: EmployeeSession
    authority_client: object | None = None
    achieved_acr: str = ''
    required_acr: str = ''


def require_privileged_assurance(principal):
    if not getattr(principal,'required_acr','') or getattr(principal,'achieved_acr','') != principal.required_acr:
        raise HTTPException(403,detail={'code':'mfa_step_up_required','login_url':'/auth/employee/step-up'})


async def require_employee(request: Request) -> EmployeePrincipal:
    raw = request.cookies.get(EMPLOYEE_SESSION_COOKIE,'')
    if not request.app.state.settings.oidc.enabled or not _is_opaque_session_token(raw):
        raise HTTPException(401,'Invalid employee session')
    async with request.app.state.session_provider() as session:
        record = await session.scalar(select(EmployeeSession).where(EmployeeSession.session_digest==session_digest(raw,request.app.state.settings.session_secret)))
        now = datetime.now(UTC)
        if record is None or record.revoked_at is not None or record.expires_at.tzinfo is None or record.expires_at <= now:
            raise HTTPException(401,'Invalid employee session')
        identity = await session.scalar(select(ConfirmedIdentity).where(ConfirmedIdentity.id==record.identity_id))
        if identity is None or identity.state != 'active' or identity.revoked_at is not None:
            raise HTTPException(401,'Invalid employee identity')
        upstream = await session.scalar(select(UpstreamSession).where(UpstreamSession.id==record.upstream_session_id))
        await revalidate_upstream(request,session,identity,upstream,'employee')
    enforce_csrf(request,raw,request.app.state.settings.session_secret)
    return EmployeePrincipal(identity,record,request.app.state.helpdesk_identity_client,upstream.achieved_acr,request.app.state.settings.oidc.admin_required_acr)


@router.get('/session')
async def employee_session(request: Request,response: Response,principal: EmployeePrincipal=Depends(require_employee)):
    async with request.app.state.session_provider() as session:
        grants = (await session.scalars(select(ScopedRoleGrant).where(ScopedRoleGrant.identity_id==principal.identity.id,ScopedRoleGrant.revoked_at.is_(None)))).all()
    response.headers['Cache-Control']='no-store'
    return {'person_id':str(principal.identity.person_id), 'department_id':str(principal.identity.department_id) if principal.identity.department_id else None,
        'csrf_token':csrf_token_for_session(request.cookies[EMPLOYEE_SESSION_COOKIE],request.app.state.settings.session_secret),
        'privileged_assurance':bool(principal.required_acr and principal.achieved_acr==principal.required_acr),
        'grants':[{'role':g.role,'department_id':str(g.department_id) if g.department_id else None} for g in grants]}


@router.delete('/session',status_code=204)
async def logout_employee(request: Request):
    raw=request.cookies.get(EMPLOYEE_SESSION_COOKIE,'')
    if not _is_opaque_session_token(raw):
        raise HTTPException(401,'Invalid employee session')
    enforce_csrf(request,raw,request.app.state.settings.session_secret)
    async with request.app.state.session_provider() as session:
        record = await session.scalar(select(EmployeeSession).where(EmployeeSession.session_digest==session_digest(raw,request.app.state.settings.session_secret)).with_for_update())
        if record is None:
            raise HTTPException(401,'Invalid employee session')
        record.revoked_at = datetime.now(UTC)
        upstream = await session.scalar(select(UpstreamSession).where(UpstreamSession.id==record.upstream_session_id).with_for_update())
        if upstream is not None:
            upstream.revoked_at = datetime.now(UTC)
        from endpoint_server.audit.service import append_audit_event
        from endpoint_server.audit.request_ids import audit_request_id
        await append_audit_event(session,actor_kind='employee',actor_identifier=str(record.identity_id),action='employee_session.revoked',
            object_kind='employee_session',object_identifier=str(record.id),request_id=audit_request_id(request),details={})
        await session.commit()
    response = Response(status_code=204,headers={'Cache-Control':'no-store'})
    response.delete_cookie(EMPLOYEE_SESSION_COOKIE,path='/',secure=True,httponly=True,samesite='strict')
    return response


def require_scoped_role(role: str):
    async def dependency(request: Request, principal: EmployeePrincipal=Depends(require_employee)):
        async with request.app.state.session_provider() as session:
            grant = await session.scalar(select(ScopedRoleGrant).where(ScopedRoleGrant.identity_id==principal.identity.id,
                ScopedRoleGrant.role==role,ScopedRoleGrant.revoked_at.is_(None),ScopedRoleGrant.department_id.is_(None)))
        if grant is None:
            raise HTTPException(403,'Explicit organization role required')
        require_privileged_assurance(principal)
        return principal
    return dependency
