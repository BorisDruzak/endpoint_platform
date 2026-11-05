"""Selected WorkTime cookie/CSRF authority; never authorizes DLP or admin APIs."""
from datetime import UTC, datetime
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import select
from endpoint_server.auth.admin_sessions import session_digest
from endpoint_server.auth.csrf import csrf_token_for_session, enforce_csrf
from endpoint_server.auth.employee_sessions import EmployeePrincipal, require_employee, employee_session, logout_employee
from endpoint_server.auth.oidc import unseal
from endpoint_server.auth.worktime_protocol import WORKTIME_COOKIE, opaque, configured
from endpoint_server.db.models.identity import ConfirmedIdentity
from endpoint_server.db.models.worktime_sessions import HelpdeskWorktimeSession
from endpoint_server.identity.worktime_client import WorktimeAuthorityError

router=APIRouter(prefix='/api/employee/worktime',tags=['worktime-session'])


@router.get('/login-options')
async def worktime_login_options(request:Request,response:Response):
    response.headers['Cache-Control']='no-store'
    try: configured(request)
    except HTTPException: return {'helpdesk_login_enabled':False}
    return {'helpdesk_login_enabled':True}


async def require_worktime_employee(request:Request):
    raw=request.cookies.get(WORKTIME_COOKIE)
    if raw is None:return await require_employee(request)
    configured(request)
    if not opaque(raw):raise HTTPException(401,'Invalid WorkTime session')
    settings=request.app.state.settings
    async with request.app.state.session_provider() as session:
        record=await session.scalar(select(HelpdeskWorktimeSession).where(HelpdeskWorktimeSession.session_digest==session_digest(raw,settings.session_secret)))
        now=datetime.now(UTC)
        if record is None or record.revoked_at is not None or record.expires_at<=now:raise HTTPException(401,'Invalid WorkTime session')
        identity=await session.get(ConfirmedIdentity,record.identity_id)
        if identity is None or identity.state!='active' or identity.revoked_at is not None:raise HTTPException(401,'Invalid WorkTime identity')
        try:
            material=unseal(settings.oidc,record.lease_encrypted)
            if set(material)!={'handle'} or not opaque(material['handle']):raise ValueError()
            verified=await request.app.state.worktime_identity_client.introspect(material['handle'])
        except WorktimeAuthorityError as error:raise HTTPException(error.status,'WorkTime authority unavailable' if error.status==503 else 'Invalid WorkTime session') from None
        except Exception:raise HTTPException(503,'WorkTime authority unavailable') from None
        if verified.person_id!=identity.person_id:raise HTTPException(401,'WorkTime person changed')
        identity.department_id=verified.department_id
        record.expires_at=min(record.expires_at,verified.expires_at)
        enforce_csrf(request,raw,settings.session_secret)
        await session.commit()
    return EmployeePrincipal(identity,record,request.app.state.worktime_identity_client,auth_source='helpdesk')


@router.get('/session')
async def worktime_session(request:Request,response:Response,principal:EmployeePrincipal=Depends(require_worktime_employee)):
    if principal.auth_source!='helpdesk':
        result=await employee_session(request,response,principal)
        return dict(result,auth_source='oidc')
    response.headers['Cache-Control']='no-store'
    return {'person_id':str(principal.identity.person_id),'department_id':str(principal.identity.department_id) if principal.identity.department_id else None,
        'csrf_token':csrf_token_for_session(request.cookies[WORKTIME_COOKIE],request.app.state.settings.session_secret),
        'grants':[],'privileged_assurance':False,'auth_source':'helpdesk'}


@router.delete('/session',status_code=204)
async def logout_worktime(request:Request):
    raw=request.cookies.get(WORKTIME_COOKIE)
    if raw is None:return await logout_employee(request)
    if not opaque(raw):raise HTTPException(401,'Invalid WorkTime session')
    enforce_csrf(request,raw,request.app.state.settings.session_secret)
    async with request.app.state.session_provider() as session:
        record=await session.scalar(select(HelpdeskWorktimeSession).where(HelpdeskWorktimeSession.session_digest==session_digest(raw,request.app.state.settings.session_secret)).with_for_update())
        if record is None:raise HTTPException(401,'Invalid WorkTime session')
        record.revoked_at=datetime.now(UTC)
        from endpoint_server.audit.service import append_audit_event
        from endpoint_server.audit.request_ids import audit_request_id
        await append_audit_event(session,actor_kind='employee',actor_identifier=str(record.identity_id),action='worktime.helpdesk_session_revoked',object_kind='worktime_session',object_identifier=str(record.id),request_id=audit_request_id(request),details={})
        await session.commit()
    response=Response(status_code=204,headers={'Cache-Control':'no-store'})
    response.delete_cookie(WORKTIME_COOKIE,path='/',secure=True,httponly=True,samesite='strict')
    return response
