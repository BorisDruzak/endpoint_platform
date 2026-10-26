"""Authlib authorization-code PKCE BFF with persisted one-use browser state."""
from __future__ import annotations

import hmac
import json
import secrets
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit
from uuid import UUID, uuid4

import httpx
from authlib.integrations.starlette_client import OAuth
from authlib.integrations.httpx_client import AsyncOAuth2Client
from cryptography.fernet import Fernet
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select

from endpoint_server.auth.admin_sessions import issue_admin_session, session_digest, set_admin_session_cookie
from endpoint_server.auth.oidc_config import OIDCSettings
from endpoint_server.db.models import AdminUser
from endpoint_server.db.models.identity import ConfirmedIdentity, EmployeeSession, OIDCFlow, UpstreamSession
from endpoint_server.identity.helpdesk_client import HelpdeskIdentityClient, bounded_json, https_origin, verified_tls_context

router = APIRouter(prefix='/auth', tags=['oidc'])
FLOW_COOKIES = {'employee':'endpoint_employee_oidc_flow','admin':'endpoint_admin_oidc_flow'}
EMPLOYEE_SESSION_COOKIE = 'endpoint_employee_session'


class BoundedTransport(httpx.AsyncBaseTransport):
    """Apply the body limit before HTTPX/Authlib buffers trusted-provider replies."""
    def __init__(self, inner=None, *, verify=True):
        self.inner = inner or httpx.AsyncHTTPTransport(verify=verify)

    async def handle_async_request(self, request):
        response = await self.inner.handle_async_request(request)
        content = bytearray()
        try:
            async for chunk in response.aiter_bytes():
                content.extend(chunk)
                if len(content)>65536:
                    raise ValueError('OIDC response too large')
        finally:
            await response.aclose()
        headers = [(key,value) for key,value in response.headers.multi_items() if key.lower() not in {'content-encoding','content-length'}]
        return httpx.Response(response.status_code,headers=headers,content=bytes(content),request=request)

    async def aclose(self):
        await self.inner.aclose()


def _denied():
    return HTTPException(401, 'Invalid or expired SSO authority')


def _material_cipher(settings):
    return Fernet(settings.encryption_key)


def seal(settings, payload: dict) -> str:
    return _material_cipher(settings).encrypt(json.dumps(payload, separators=(',',':')).encode()).decode('ascii')


def unseal(settings, value: str) -> dict:
    return json.loads(_material_cipher(settings).decrypt(value.encode('ascii')))


def validate_claim_identity(claims, issuer: str) -> tuple[str,str,UUID]:
    subject = claims.get('sub')
    if claims.get('iss') != issuer or not isinstance(subject,str) or not 1 <= len(subject) <= 255 or any(ord(c)<32 for c in subject):
        raise ValueError('Exact identity claims required')
    guid = UUID(claims['ad_object_guid']) if isinstance(claims.get('ad_object_guid'), str) else None
    if guid is None or str(guid) != claims['ad_object_guid']:
        raise ValueError('Canonical AD GUID claim required')
    return issuer, subject, guid


async def consume_flow(session, state: str, browser_digest: str, realm: str, secret: bytes, *, now=None) -> OIDCFlow:
    now = now or datetime.now(UTC)
    if not state or len(state) > 128 or realm not in FLOW_COOKIES:
        raise _denied()
    record = await session.scalar(select(OIDCFlow).where(OIDCFlow.state_digest == session_digest(state,secret)).with_for_update())
    if (record is None or record.realm != realm or record.consumed_at is not None or record.expires_at.tzinfo is None
        or now >= record.expires_at or not hmac.compare_digest(record.browser_digest,browser_digest)):
        raise _denied()
    record.consumed_at = now
    # Consume in its own committed transaction before remote code exchange. A failed
    # exchange must never make a callback replayable after rollback.
    await session.commit()
    return record


class OIDCProvider:
    """Maintained Authlib flow/claim validation and bounded verified metadata."""
    def __init__(self, settings: OIDCSettings, *, transport=None):
        self.settings = settings
        self.transport = transport
        self.tls_context = verified_tls_context(settings.ca_file)

    def client_credentials(self, realm):
        if realm == 'admin':
            return self.settings.admin_client_id, self.settings.admin_client_secret
        if realm == 'employee':
            return self.settings.employee_client_id, self.settings.employee_client_secret
        raise ValueError('Unknown realm')

    async def remote(self, realm):
        issuer = self.settings.issuer
        async with httpx.AsyncClient(timeout=5, verify=self.tls_context, follow_redirects=False, trust_env=False,transport=BoundedTransport(self.transport,verify=self.tls_context)) as client:
            async with client.stream('GET',issuer+'/.well-known/openid-configuration') as response:
                metadata = await bounded_json(response)
        if metadata.get('issuer') != issuer:
            raise ValueError('Provider issuer mismatch')
        origin = urlsplit(issuer)
        for name in ('authorization_endpoint','token_endpoint','jwks_uri','introspection_endpoint'):
            value = https_origin(metadata[name])
            parsed = urlsplit(value)
            if (parsed.scheme,parsed.netloc) != (origin.scheme,origin.netloc):
                raise ValueError('OIDC endpoints must use the configured HTTPS issuer origin')
        if 'RS256' not in metadata.get('id_token_signing_alg_values_supported',[]):
            raise ValueError('RS256 provider signing required')
        metadata['id_token_signing_alg_values_supported'] = ['RS256']
        client_id, client_secret = self.client_credentials(realm)
        registry = OAuth()
        remote = registry.register('endpoint_'+realm, client_id=client_id, client_secret=client_secret,
            client_kwargs={'scope':'openid','code_challenge_method':'S256', 'timeout':5,'verify':self.tls_context,'follow_redirects':False,'trust_env':False,'transport':BoundedTransport(self.transport,verify=self.tls_context)}, **metadata)
        return remote

    async def authorize(self, realm, redirect_uri, state, nonce, verifier):
        remote = await self.remote(realm)
        args = {'state':state,'nonce':nonce,'code_verifier':verifier}
        args['acr_values'] = self.settings.admin_required_acr
        client_id, client_secret = self.client_credentials(realm)
        # The public OAuth2 client API performs S256. The integration wrapper's
        # authorization helper logs the verifier at DEBUG, so do not use it here.
        async with AsyncOAuth2Client(client_id,client_secret,scope='openid',redirect_uri=redirect_uri,code_challenge_method='S256') as client:
            return client.create_authorization_url(remote.server_metadata['authorization_endpoint'],**args)[0]

    async def exchange(self, realm, redirect_uri, code, nonce, verifier):
        remote = await self.remote(realm)
        token = await remote.fetch_access_token(redirect_uri,code=code,code_verifier=verifier,grant_type='authorization_code')
        if not isinstance(token.get('access_token'),str) or len(token['access_token']) > 16384 or not isinstance(token.get('id_token'),str) or len(token['id_token']) > 16384:
            raise ValueError('Token response invalid')
        claims = await remote.parse_id_token(token,nonce=nonce,leeway=0,claims_options={
            'iss':{'essential':True,'value':self.settings.issuer},
            'aud':{'essential':True,'value':remote.client_id},
            'exp':{'essential':True},'sub':{'essential':True},'nonce':{'essential':True}})
        validate_claim_identity(claims,self.settings.issuer)
        if not isinstance(claims.get('sid'),str) or not 1 <= len(claims['sid']) <= 255:
            raise ValueError('Upstream session id required')
        if realm == 'admin' and claims.get('acr') != self.settings.admin_required_acr:
            raise ValueError('Configured MFA assurance required')
        introspection = await self.introspect(realm,token['access_token'])
        self.validate_introspection(introspection, realm, claims['sub'], claims['sid'])
        expires_at = min(float(token['expires_at']),float(claims['exp']),float(introspection['exp']))
        if expires_at <= datetime.now(UTC).timestamp():
            raise ValueError('Expired upstream token')
        return token, claims, datetime.fromtimestamp(expires_at,UTC)

    async def introspect(self, realm, access_token):
        remote = await self.remote(realm)
        client_id, client_secret = self.client_credentials(realm)
        async with AsyncOAuth2Client(client_id,client_secret,timeout=5,verify=self.tls_context,follow_redirects=False,trust_env=False,transport=BoundedTransport(self.transport,verify=self.tls_context)) as client:
            response = await client.introspect_token(remote.server_metadata['introspection_endpoint'],token=access_token,token_type_hint='access_token')
            return await bounded_json(response)

    async def refresh(self,realm,tokens,identity,sid,achieved_acr):
        """Rotate provider refresh authority through Authlib; never reuse stale data."""
        refresh_token=tokens.get('refresh_token')
        if not isinstance(refresh_token,str) or not 1<=len(refresh_token)<=16384:
            raise ValueError('No refresh authority')
        remote=await self.remote(realm)
        client_id,client_secret=self.client_credentials(realm)
        async with AsyncOAuth2Client(client_id,client_secret,timeout=5,verify=self.tls_context,follow_redirects=False,trust_env=False,transport=BoundedTransport(self.transport,verify=self.tls_context)) as client:
            refreshed=await client.refresh_token(remote.server_metadata['token_endpoint'],refresh_token=refresh_token)
        if not isinstance(refreshed.get('access_token'),str) or len(refreshed['access_token'])>16384:
            raise ValueError('Invalid refreshed token')
        # Keycloak is configured for refresh rotation. Absence/reuse is fail-closed.
        if not isinstance(refreshed.get('refresh_token'),str) or not 1<=len(refreshed['refresh_token'])<=16384 or refreshed['refresh_token']==refresh_token:
            raise ValueError('Refresh token did not rotate')
        expiry=float(refreshed['expires_at'])
        if 'id_token' in refreshed:
            claims=await remote.parse_id_token(refreshed,nonce=None,leeway=0,claims_options={
                'iss':{'essential':True,'value':self.settings.issuer},'aud':{'essential':True,'value':client_id},
                'exp':{'essential':True},'sub':{'essential':True}})
            if (validate_claim_identity(claims,self.settings.issuer)!=(identity.issuer,identity.subject,identity.ad_object_guid)
                or claims.get('sid')!=sid or claims.get('acr','')!=achieved_acr
                or claims.get('nonce') not in (None,tokens.get('_oidc_nonce'))):
                raise ValueError('Refresh identity or assurance changed')
            expiry=min(expiry,float(claims['exp']))
        payload=await self.introspect(realm,refreshed['access_token'])
        self.validate_introspection(payload,realm,identity.subject,sid)
        refreshed['_oidc_nonce']=tokens.get('_oidc_nonce')
        return dict(refreshed),datetime.fromtimestamp(min(expiry,float(payload['exp'])),UTC)

    def validate_introspection(self,payload,realm,subject,sid):
        client_id, _ = self.client_credentials(realm)
        if (payload.get('active') is not True or payload.get('sub') != subject or payload.get('sid') != sid
            or payload.get('iss') != self.settings.issuer or payload.get('client_id') != client_id
            or type(payload.get('exp')) not in (int,float) or payload['exp'] <= datetime.now(UTC).timestamp()):
            raise ValueError('Inactive or substituted upstream session')


async def revalidate_upstream(request: Request, session, identity, record, realm: str, *, commit: bool=True):
    settings = request.app.state.settings.oidc
    if not settings.enabled or record is None or record.realm != realm or record.identity_id != identity.id:
        raise _denied()
    now = datetime.now(UTC)
    absolute=getattr(record,'absolute_expires_at',record.expires_at)
    if record.revoked_at is not None or absolute.tzinfo is None or absolute <= now or record.expires_at.tzinfo is None or identity.state != 'active' or identity.revoked_at is not None:
        raise _denied()
    refresh_due=(record.expires_at-now).total_seconds()<=30
    if refresh_due or record.checked_at.tzinfo is None or record.checked_at > now or (now-record.checked_at).total_seconds() >= 60:
        try:
            provider = request.app.state.oidc_provider
            tokens = unseal(settings,record.encrypted_tokens)
            if refresh_due:
                # Lock and reload current persisted ciphertext before rotating so
                # concurrent requests cannot spend the same refresh token twice.
                record=await session.scalar(select(UpstreamSession).where(UpstreamSession.id==record.id).with_for_update().execution_options(populate_existing=True))
                if record is None or record.revoked_at is not None or record.absolute_expires_at<=now:
                    raise ValueError('Upstream authority expired')
                if (record.expires_at-now).total_seconds()<=30:
                    tokens=unseal(settings,record.encrypted_tokens)
                    refreshed,new_expiry=await provider.refresh(realm,tokens,identity,record.sid,record.achieved_acr)
                    record.encrypted_tokens=seal(settings,refreshed)
                    record.expires_at=min(new_expiry,record.absolute_expires_at)
                    tokens=refreshed
                else:
                    tokens=unseal(settings,record.encrypted_tokens)
            payload = await provider.introspect(realm,tokens['access_token'])
            provider.validate_introspection(payload,realm,identity.subject,record.sid)
            resolved = await request.app.state.helpdesk_identity_client.resolve(identity.issuer,identity.subject,identity.ad_object_guid)
            if resolved.person_id != identity.person_id:
                raise ValueError('Identity changed')
            identity.department_id = resolved.department_id
            record.checked_at = now
            record.expires_at = min(record.expires_at,datetime.fromtimestamp(payload['exp'],UTC))
            if commit:
                await session.commit()
            else:
                await session.flush()
        except Exception:
            record.revoked_at = now
            if commit:
                await session.commit()
            else:
                await session.flush()
            raise _denied() from None


@router.get('/employee/step-up')
async def employee_step_up(request:Request):
    return await login(request,'employee')


@router.get('/{realm}/login')
async def login(request: Request, realm: str):
    settings = request.app.state.settings.oidc
    if not settings.enabled or realm not in FLOW_COOKIES:
        raise HTTPException(404,'SSO unavailable')
    state, browser, nonce, verifier = (secrets.token_urlsafe(32) for _ in range(4))
    redirect_uri = request.app.state.settings.public_base_url+'/auth/'+realm+'/callback'
    try:
        url = await request.app.state.oidc_provider.authorize(realm,redirect_uri,state,nonce,verifier)
    except Exception:
        raise HTTPException(503,'Identity provider unavailable') from None
    now = datetime.now(UTC)
    async with request.app.state.session_provider() as session:
        session.add(OIDCFlow(id=uuid4(),state_digest=session_digest(state,request.app.state.settings.session_secret),
            browser_digest=session_digest(browser,request.app.state.settings.session_secret),realm=realm,
            encrypted_material=seal(settings,{'nonce':nonce,'verifier':verifier}),expires_at=now+timedelta(minutes=5),consumed_at=None))
        await session.commit()
    response = RedirectResponse(url,303,headers={'Cache-Control':'no-store','Referrer-Policy':'no-referrer'})
    response.set_cookie(FLOW_COOKIES[realm],browser,max_age=300,path='/auth/'+realm,secure=True,httponly=True,samesite='lax')
    return response


@router.get('/{realm}/callback')
async def callback(request: Request, realm: str):
    settings = request.app.state.settings.oidc
    if not settings.enabled or realm not in FLOW_COOKIES:
        raise HTTPException(404,'SSO unavailable')
    # Reject duplicate parameters instead of choosing one of contradictory values.
    if any(len(request.query_params.getlist(name)) != 1 for name in ('state','code')) or request.query_params.get('error'):
        raise _denied()
    state, code = request.query_params['state'], request.query_params['code']
    browser = request.cookies.get(FLOW_COOKIES[realm],'')
    if not browser or len(browser)>128 or not browser.isascii() or not state.isascii() or len(code)>4096:
        raise _denied()
    async with request.app.state.session_provider() as session:
        flow = await consume_flow(session,state,session_digest(browser,request.app.state.settings.session_secret),realm,request.app.state.settings.session_secret)
        material = unseal(settings,flow.encrypted_material)
    try:
        token, claims, expires_at = await request.app.state.oidc_provider.exchange(realm,
            request.app.state.settings.public_base_url+'/auth/'+realm+'/callback',code,material['nonce'],material['verifier'])
        issuer,subject,guid = validate_claim_identity(claims,settings.issuer)
        resolved = await request.app.state.helpdesk_identity_client.resolve(issuer,subject,guid)
    except Exception:
        raise _denied() from None
    now = datetime.now(UTC)
    async with request.app.state.session_provider() as session:
        identity = await session.scalar(select(ConfirmedIdentity).where(ConfirmedIdentity.issuer==issuer, ConfirmedIdentity.subject==subject).with_for_update())
        if identity is None:
            if realm == 'admin':
                raise _denied()
            identity = ConfirmedIdentity(id=uuid4(),person_id=resolved.person_id,department_id=resolved.department_id,
                issuer=issuer,subject=subject,ad_object_guid=guid,state='active',confirmed_at=now,revoked_at=None)
            session.add(identity)
            await session.flush()
        if identity.state != 'active' or identity.revoked_at is not None or identity.person_id != resolved.person_id or identity.ad_object_guid != guid:
            raise _denied()
        identity.department_id = resolved.department_id
        token['_oidc_nonce']=material['nonce']
        absolute_expires_at=now+timedelta(hours=8)
        upstream = UpstreamSession(id=uuid4(),identity_id=identity.id,realm=realm,sid=claims['sid'],
            encrypted_tokens=seal(settings,dict(token)),expires_at=expires_at,checked_at=now,revoked_at=None,
            absolute_expires_at=absolute_expires_at,achieved_acr=claims.get('acr',''))
        if realm=='employee':
            from endpoint_server.db.models.identity import ScopedRoleGrant
            grants=(await session.scalars(select(ScopedRoleGrant).where(ScopedRoleGrant.identity_id==identity.id,ScopedRoleGrant.revoked_at.is_(None)))).all()
            if any(grant.role in {'manager','hr','worktime_admin','dlp_officer'} for grant in grants) and claims.get('acr')!=settings.admin_required_acr:
                raise _denied()
        response = RedirectResponse('/admin' if realm=='admin' else '/employee',303,headers={'Cache-Control':'no-store','Referrer-Policy':'no-referrer'})
        if realm == 'admin':
            user = await session.scalar(select(AdminUser).where(AdminUser.id==identity.admin_user_id)) if identity.admin_user_id else None
            if user is None or user.disabled_at is not None or claims.get('acr') != settings.admin_required_acr:
                raise _denied()
            issued = issue_admin_session(user.id,request.app.state.settings.session_secret,now=now,lifetime=absolute_expires_at-now)
            issued.record.auth_method = 'oidc'
            upstream.admin_session_id = issued.record.id
            session.add(issued.record)
            await session.flush()
            set_admin_session_cookie(response,issued.token,absolute_expires_at)
        else:
            raw = secrets.token_urlsafe(32)
            session.add(upstream)
            await session.flush()
            session.add(EmployeeSession(id=uuid4(),identity_id=identity.id,upstream_session_id=upstream.id,
                session_digest=session_digest(raw,request.app.state.settings.session_secret),expires_at=absolute_expires_at,revoked_at=None))
            response.set_cookie(EMPLOYEE_SESSION_COOKIE,raw,max_age=max(0,int((absolute_expires_at-now).total_seconds())),expires=absolute_expires_at,path='/',secure=True,httponly=True,samesite='strict')
        session.add(upstream)
        from endpoint_server.audit.service import append_audit_event
        from endpoint_server.audit.request_ids import audit_request_id
        await append_audit_event(session,actor_kind='employee' if realm=='employee' else 'admin',actor_identifier=str(identity.person_id),
            action='sso_session.created',object_kind='identity',object_identifier=str(identity.id),request_id=audit_request_id(request),details={'realm':realm})
        await session.commit()
    response.delete_cookie(FLOW_COOKIES[realm],path='/auth/'+realm,secure=True,httponly=True,samesite='lax')
    return response
