"""Browser-bound state/PKCE exchange into an isolated WorkTime employee session."""
from collections import deque
from datetime import UTC, datetime, timedelta
import secrets
import time
from urllib.parse import parse_qs,urlencode

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select, delete
from endpoint_server.auth.admin_sessions import session_digest
from endpoint_server.auth.oidc import seal,unseal
from endpoint_server.auth.worktime_protocol import WORKTIME_COOKIE,FLOW_COOKIE,opaque,configured,pkce_challenge,fixed_helpdesk_endpoints
from endpoint_server.db.models.worktime_sessions import WorktimeLoginFlow,HelpdeskWorktimeSession
from endpoint_server.identity.worktime_client import WorktimeAuthorityError
from endpoint_server.identity.worktime_identity import local_worktime_identity

router=APIRouter(prefix='/auth/worktime/helpdesk',tags=['worktime-handoff'])
_STARTS={}


def throttle(request):
    now=time.monotonic();key=request.client.host if request.client else 'unknown'
    for old_key,old_queue in list(_STARTS.items()):
        if not old_queue or old_queue[-1]<=now-60:del _STARTS[old_key]
    if key not in _STARTS and len(_STARTS)>=10000:raise HTTPException(429,'Too many login attempts')
    queue=_STARTS.setdefault(key,deque())
    while queue and queue[0]<=now-60:queue.popleft()
    if len(queue)>=30:raise HTTPException(429,'Too many login attempts')
    queue.append(now)


@router.get('/login')
async def login(request:Request):
    callback=configured(request);throttle(request)
    settings=request.app.state.settings
    state,browser,verifier=(secrets.token_urlsafe(32) for _ in range(3))
    async with request.app.state.session_provider() as session:
        await session.execute(delete(WorktimeLoginFlow).where(WorktimeLoginFlow.expires_at<=datetime.now(UTC)))
        session.add(WorktimeLoginFlow(state_digest=session_digest(state,settings.session_secret),browser_digest=session_digest(browser,settings.session_secret),
            verifier_encrypted=seal(settings.oidc,{'verifier':verifier}),expires_at=datetime.now(UTC)+timedelta(minutes=5)))
        await session.commit()
    query=urlencode({'state':state,'code_challenge':pkce_challenge(verifier),'code_challenge_method':'S256','redirect_uri':callback})
    response=RedirectResponse(settings.oidc.helpdesk_base_url+'/api/web/session/worktime/authorize?'+query,303,headers={'Cache-Control':'no-store','Referrer-Policy':'no-referrer'})
    response.set_cookie(FLOW_COOKIE,browser,max_age=300,path='/auth/worktime',secure=True,httponly=True,samesite='lax')
    return response


@router.post('/callback')
async def callback(request:Request):
    target=configured(request);settings=request.app.state.settings
    if request.headers.get('origin')!=settings.oidc.helpdesk_base_url or request.headers.get('content-type','').split(';')[0]!='application/x-www-form-urlencoded':
        raise HTTPException(400,'Invalid WorkTime callback')
    raw=bytearray()
    async for chunk in request.stream():
        raw.extend(chunk)
        if len(raw)>4096:raise HTTPException(400,'Invalid WorkTime callback')
    try:
        body=parse_qs(raw.decode('ascii'),strict_parsing=True,keep_blank_values=True)
        if set(body)!={'code','state'} or any(len(values)!=1 for values in body.values()):raise ValueError()
        code,state=body['code'][0],body['state'][0];browser=request.cookies.get(FLOW_COOKIE,'')
        if not all(opaque(value) for value in (code,state,browser)):raise ValueError()
    except (ValueError,UnicodeError):raise HTTPException(400,'Invalid WorkTime callback') from None
    now=datetime.now(UTC)
    async with request.app.state.session_provider() as session:
        flow=await session.scalar(select(WorktimeLoginFlow).where(WorktimeLoginFlow.state_digest==session_digest(state,settings.session_secret)).with_for_update().execution_options(populate_existing=True))
        if flow is None or flow.consumed_at is not None or flow.expires_at<=now or not secrets.compare_digest(flow.browser_digest,session_digest(browser,settings.session_secret)):
            raise HTTPException(401,'Invalid WorkTime login flow')
        material=unseal(settings.oidc,flow.verifier_encrypted)
        flow.consumed_at=now
        await session.commit()
    try:
        verified=await request.app.state.worktime_identity_client.exchange(code,material['verifier'],target)
        async with request.app.state.session_provider() as session:
            identity=await local_worktime_identity(session,verified,settings.oidc.helpdesk_base_url)
            cookie=secrets.token_urlsafe(32)
            record=HelpdeskWorktimeSession(identity_id=identity.id,session_digest=session_digest(cookie,settings.session_secret),lease_encrypted=seal(settings.oidc,{'handle':verified.handle}),expires_at=min(verified.expires_at,now+timedelta(hours=8)))
            session.add(record);await session.flush()
            from endpoint_server.audit.service import append_audit_event
            from endpoint_server.audit.request_ids import audit_request_id
            await append_audit_event(session,actor_kind='employee',actor_identifier=str(identity.person_id),action='worktime.helpdesk_login_succeeded',object_kind='worktime_session',object_identifier=str(record.id),request_id=audit_request_id(request),details={'source':'helpdesk'})
            await session.commit()
    except WorktimeAuthorityError as error:
        response=RedirectResponse('/employee/login?handoff_error='+('unavailable' if error.status==503 else 'invalid'),303,headers={'Cache-Control':'no-store','Referrer-Policy':'no-referrer'})
        response.delete_cookie(FLOW_COOKIE,path='/auth/worktime',secure=True,httponly=True,samesite='lax')
        return response
    response=RedirectResponse('/employee',303,headers={'Cache-Control':'no-store','Referrer-Policy':'no-referrer'})
    response.set_cookie(WORKTIME_COOKIE,cookie,max_age=max(1,int((record.expires_at-now).total_seconds())),path='/',secure=True,httponly=True,samesite='strict')
    response.delete_cookie(FLOW_COOKIE,path='/auth/worktime',secure=True,httponly=True,samesite='lax')
    return response
