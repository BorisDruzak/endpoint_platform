"""Fail-closed identity, OIDC and personnel authorization regression checks."""
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4
from unittest.mock import AsyncMock

import httpx
import pytest
from fastapi import HTTPException

from endpoint_server.identity.helpdesk_client import HelpdeskIdentityClient, IdentityResolutionError
from endpoint_server.auth.authorization import authorize_person
from endpoint_server.auth.oidc import OIDCSettings, OIDCProvider, validate_claim_identity, consume_flow, revalidate_upstream
from endpoint_server.db.models.identity import ConfirmedIdentity, OIDCFlow


def identity(**kw):
    data = dict(id=uuid4(), person_id=uuid4(), department_id=uuid4(), issuer='https://sso.example/realms/org', subject='CaseSensitive', ad_object_guid=uuid4(), state='active', revoked_at=None)
    data.update(kw)
    return ConfirmedIdentity(**data)


def principal_for(actor,target):
    return SimpleNamespace(identity=actor,authority_client=SimpleNamespace(resolve=AsyncMock(return_value=SimpleNamespace(person_id=target.person_id,department_id=target.department_id))),achieved_acr='mfa',required_acr='mfa')


@pytest.mark.asyncio
async def test_resolver_exact_request_and_strict_response():
    person = identity()
    def handler(request):
        assert request.url.path == '/api/integration/v1/identities/resolve'
        assert request.headers['authorization'] == 'Bearer ' + 'a' * 48
        return httpx.Response(200, json=dict(version=1, person_id=str(person.person_id), issuer=person.issuer, subject=person.subject, ad_object_guid=str(person.ad_object_guid), state='active', department_id=None))
    client = HelpdeskIdentityClient('https://helpdesk.example', 'a' * 48, transport=httpx.MockTransport(handler))
    result = await client.resolve(person.issuer, person.subject, person.ad_object_guid)
    assert result.person_id == person.person_id
    assert result.department_id is None


@pytest.mark.asyncio
@pytest.mark.parametrize('change', [dict(version=True), dict(subject='casesensitive'), dict(state='disabled'), dict(person_id='invalid'), dict(ad_object_guid=str(uuid4())), dict(extra='private')])
async def test_resolver_rejects_substitution_and_malformed_contract(change):
    person = identity()
    payload = dict(version=1, person_id=str(person.person_id), issuer=person.issuer, subject=person.subject, ad_object_guid=str(person.ad_object_guid), state='active', department_id=None)
    payload.update(change)
    client = HelpdeskIdentityClient('https://helpdesk.example', 'a' * 48, transport=httpx.MockTransport(lambda _: httpx.Response(200, json=payload)))
    with pytest.raises(IdentityResolutionError):
        await client.resolve(person.issuer, person.subject, person.ad_object_guid)


@pytest.mark.asyncio
async def test_technical_admin_has_no_personnel_right():
    actor, target = identity(), identity()
    session = SimpleNamespace(scalar=AsyncMock(return_value=target), scalars=AsyncMock(return_value=SimpleNamespace(all=lambda: [SimpleNamespace(role='endpoint_admin', department_id=None, revoked_at=None)])))
    with pytest.raises(HTTPException) as error:
        await authorize_person(session, principal_for(actor,target), target.person_id, 'worktime.read')
    assert error.value.status_code == 403


@pytest.mark.asyncio
async def test_department_comes_from_persisted_target():
    actor, target = identity(), identity()
    grants = [SimpleNamespace(role='manager', department_id=actor.department_id, revoked_at=None)]
    session = SimpleNamespace(scalar=AsyncMock(return_value=target), scalars=AsyncMock(return_value=SimpleNamespace(all=lambda: grants)))
    with pytest.raises(HTTPException):
        await authorize_person(session, principal_for(actor,target), target.person_id, 'worktime.approve')
    grants[0].department_id = target.department_id
    assert await authorize_person(session, principal_for(actor,target), target.person_id, 'worktime.approve') is target


def test_oidc_identity_claims_are_exact_and_no_fallback():
    guid = uuid4()
    assert validate_claim_identity({'iss':'https://issuer.example', 'sub':'MixedCase', 'ad_object_guid':str(guid)}, 'https://issuer.example') == ('https://issuer.example','MixedCase',guid)
    for claims in ({'iss':'https://issuer.example','sub':'','ad_object_guid':str(guid)}, {'iss':'https://evil.example','sub':'MixedCase','ad_object_guid':str(guid)}, {'iss':'https://issuer.example','sub':'MixedCase','preferred_username':'employee'}):
        with pytest.raises(ValueError):
            validate_claim_identity(claims, 'https://issuer.example')


@pytest.mark.asyncio
async def test_flow_is_one_use_and_browser_and_realm_bound():
    now = datetime.now(UTC)
    flow = OIDCFlow(id=uuid4(), state_digest='x', browser_digest='correct', realm='employee', encrypted_material='encrypted', expires_at=now+timedelta(minutes=2), consumed_at=None)
    session = SimpleNamespace(scalar=AsyncMock(return_value=flow), commit=AsyncMock())
    with pytest.raises(HTTPException):
        await consume_flow(session, 'state', 'wrong', 'employee', b'secret', now=now)
    with pytest.raises(HTTPException):
        await consume_flow(session, 'state', 'correct', 'admin', b'secret', now=now)
    assert await consume_flow(session,'state','correct','employee',b'secret',now=now) is flow
    assert flow.consumed_at == now
    session.commit.assert_awaited_once()
    with pytest.raises(HTTPException):
        await consume_flow(session,'state','correct','employee',b'secret',now=now)


def test_sso_defaults_disabled():
    assert not OIDCSettings().enabled
    with pytest.raises(ValueError):
        OIDCSettings(enabled=True)


@pytest.mark.asyncio
async def test_migrated_admin_password_and_old_local_session_are_disabled():
    from endpoint_server.auth.admin_sessions import local_password_policy
    user=SimpleNamespace(id=uuid4(),username='migrated',sso_migrated_at=datetime.now(UTC))
    settings=SimpleNamespace(oidc=OIDCSettings())
    session=SimpleNamespace(scalar=AsyncMock(return_value=uuid4()))
    assert await local_password_policy(session,user,settings)==(False,False)
    assert await local_password_policy(session,user,settings,record=SimpleNamespace(auth_method='local'))==(False,False)


@pytest.mark.asyncio
async def test_breakglass_is_explicit_bounded_and_cannot_reuse_old_local_session():
    from endpoint_server.auth.admin_sessions import local_password_policy
    user=SimpleNamespace(id=uuid4(),username='emergency',sso_migrated_at=datetime.now(UTC))
    until=datetime.now(UTC)+timedelta(hours=1)
    settings=SimpleNamespace(oidc=OIDCSettings(breakglass_usernames=('emergency',),breakglass_until=until))
    session=SimpleNamespace(scalar=AsyncMock(return_value=uuid4()))
    assert await local_password_policy(session,user,settings)==(True,True)
    assert await local_password_policy(session,user,settings,record=SimpleNamespace(auth_method='local'))==(False,False)
    assert await local_password_policy(session,user,settings,record=SimpleNamespace(auth_method='breakglass',expires_at=until))==(True,True)
    expired=SimpleNamespace(oidc=OIDCSettings(breakglass_usernames=('emergency',),breakglass_until=datetime.now(UTC)-timedelta(seconds=1)))
    assert await local_password_policy(session,user,expired)==(False,False)


@pytest.mark.asyncio
async def test_target_transfer_and_revocation_are_checked_without_target_login():
    from endpoint_server.identity.helpdesk_client import IdentityResolutionError
    actor,target=identity(),identity()
    grant=SimpleNamespace(role='manager',department_id=target.department_id,revoked_at=None)
    session=SimpleNamespace(scalar=AsyncMock(return_value=target),scalars=AsyncMock(return_value=SimpleNamespace(all=lambda:[grant])))
    remote=SimpleNamespace(person_id=target.person_id,department_id=uuid4())
    client=SimpleNamespace(resolve=AsyncMock(return_value=remote))
    principal=SimpleNamespace(identity=actor,authority_client=client,achieved_acr='mfa',required_acr='mfa')
    with pytest.raises(HTTPException):
        await authorize_person(session,principal,target.person_id,'worktime.read')
    assert target.department_id==remote.department_id
    client.resolve.side_effect=IdentityResolutionError('inactive')
    with pytest.raises(HTTPException):
        await authorize_person(session,principal,target.person_id,'worktime.read')


@pytest.mark.asyncio
async def test_low_assurance_employee_cannot_gain_privileged_roles_after_login():
    from endpoint_server.auth.employee_sessions import require_privileged_assurance
    for role in ('manager','hr','worktime_admin','dlp_officer'):
        with pytest.raises(HTTPException):
            require_privileged_assurance(SimpleNamespace(achieved_acr='loa1',required_acr='mfa'))
    require_privileged_assurance(SimpleNamespace(achieved_acr='mfa',required_acr='mfa'))


def provider_fixture(mutation=None, *, outage=False, forged=False):
    from cryptography.fernet import Fernet
    from joserfc import jwk, jwt
    from urllib.parse import parse_qs
    now = int(datetime.now(UTC).timestamp())
    key = jwk.RSAKey.generate_key(2048, parameters={'kid':'test-key'})
    signing_key = jwk.RSAKey.generate_key(2048, parameters={'kid':'test-key'}) if forged else key
    settings = OIDCSettings(enabled=True,issuer='https://sso.example/realms/org',employee_client_id='employee',employee_client_secret='employee-secret',admin_client_id='admin',admin_client_secret='admin-secret',admin_required_acr='urn:test:mfa',helpdesk_base_url='https://helpdesk.example',helpdesk_credential='a'*48,encryption_key=Fernet.generate_key())
    claims = {'iss':settings.issuer,'sub':'CaseSensitive','aud':'employee','iat':now,'exp':now+300,'nonce':'expected-nonce','sid':'upstream-session','ad_object_guid':str(uuid4())}
    claims.update(mutation or {})
    def handler(request):
        if outage:
            raise httpx.ConnectError('unavailable',request=request)
        if request.url.path.endswith('openid-configuration'):
            return httpx.Response(200,json={'issuer':settings.issuer,'authorization_endpoint':'https://sso.example/auth','token_endpoint':'https://sso.example/token','jwks_uri':'https://sso.example/jwks','introspection_endpoint':'https://sso.example/introspect','id_token_signing_alg_values_supported':['RS256']})
        if request.url.path == '/jwks':
            return httpx.Response(200,json={'keys':[key.as_dict(private=False)]})
        if request.url.path == '/token':
            body=parse_qs(request.content.decode())
            if body['grant_type']==['refresh_token']:
                assert body['refresh_token']==['initial-refresh-token']
                provider.refresh_requests=getattr(provider,'refresh_requests',0)+1
                refresh_token='rotated-refresh-token'
            else:
                assert body['code_verifier']==[getattr(provider,'expected_verifier','v'*43)]
                assert body['grant_type']==['authorization_code']
                refresh_token='initial-refresh-token'
            return httpx.Response(200,json={'access_token':'access-token','refresh_token':refresh_token,'id_token':jwt.encode({'alg':'RS256','kid':'test-key'},claims,signing_key),'expires_in':300,'token_type':'Bearer'})
        if request.url.path == '/introspect':
            return httpx.Response(200,json={'active':True,'sub':'CaseSensitive','sid':'upstream-session','iss':settings.issuer,'client_id':'employee','exp':now+200})
        raise AssertionError(str(request.url))
    provider = OIDCProvider(settings,transport=httpx.MockTransport(handler))
    provider.fixture_claims = claims
    return provider


@pytest.mark.asyncio
async def test_real_authlib_code_pkce_and_signed_id_token():
    from urllib.parse import parse_qs,urlsplit
    import base64,hashlib
    provider=provider_fixture()
    url=await provider.authorize('employee','https://endpoint.example/auth/employee/callback','state','expected-nonce','v'*43)
    query=parse_qs(urlsplit(url).query)
    assert query['code_challenge_method']==['S256']
    assert query['code_challenge']==[base64.urlsafe_b64encode(hashlib.sha256(('v'*43).encode()).digest()).rstrip(b'=').decode()]
    assert query['nonce']==['expected-nonce']
    assert query['response_type']==['code']
    token,claims,expiry=await provider.exchange('employee','https://endpoint.example/auth/employee/callback','code','expected-nonce','v'*43)
    assert claims['sub']=='CaseSensitive'
    assert expiry.timestamp()<=int(datetime.now(UTC).timestamp())+200


@pytest.mark.asyncio
@pytest.mark.parametrize('mutation',[{'nonce':'wrong'},{'aud':'admin'},{'iss':'https://evil.example'},{'exp':1},{'sid':''},{'sub':'another-subject'}])
async def test_real_authlib_rejects_bad_nonce_audience_issuer_expiry_sid(mutation):
    provider=provider_fixture(mutation)
    with pytest.raises(Exception):
        await provider.exchange('employee','https://endpoint.example/auth/employee/callback','code','expected-nonce','v'*43)


@pytest.mark.asyncio
async def test_provider_outage_revokes_and_fails_closed():
    from endpoint_server.auth.oidc import seal
    provider=provider_fixture(outage=True)
    person=identity()
    now=datetime.now(UTC)
    upstream=SimpleNamespace(identity_id=person.id,realm='employee',sid='upstream-session',encrypted_tokens=seal(provider.settings,{'access_token':'test'}),expires_at=now+timedelta(minutes=5),checked_at=now-timedelta(seconds=61),revoked_at=None)
    request=SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(settings=SimpleNamespace(oidc=provider.settings),oidc_provider=provider)))
    session=SimpleNamespace(commit=AsyncMock())
    with pytest.raises(HTTPException) as error:
        await revalidate_upstream(request,session,person,upstream,'employee')
    assert error.value.status_code==401
    assert upstream.revoked_at is not None


@pytest.mark.asyncio
async def test_admin_requires_explicit_mfa_acr():
    provider=provider_fixture({'aud':'admin'})
    with pytest.raises(ValueError,match='MFA'):
        await provider.exchange('admin','https://endpoint.example/auth/admin/callback','code','expected-nonce','v'*43)


@pytest.mark.asyncio
async def test_admin_linking_requires_explicit_management_scope():
    from endpoint_server.auth.identity_admin import require_identity_manager
    principal=SimpleNamespace(user=SimpleNamespace(scopes=['updates:write']))
    with pytest.raises(HTTPException) as error:
        await require_identity_manager(principal)
    assert error.value.status_code==403
    principal.user.scopes=['identities:manage']
    assert await require_identity_manager(principal) is principal


@pytest.mark.asyncio
async def test_authlib_rejects_forged_signature():
    from joserfc.errors import BadSignatureError
    provider=provider_fixture(forged=True)
    with pytest.raises(BadSignatureError):
        await provider.exchange('employee','https://endpoint.example/auth/employee/callback','code','expected-nonce','v'*43)


@pytest.mark.asyncio
async def test_expired_or_missing_state_cannot_be_consumed():
    now=datetime.now(UTC)
    flow=OIDCFlow(state_digest='state',browser_digest='browser',realm='employee',encrypted_material='ciphertext',expires_at=now-timedelta(seconds=1),consumed_at=None)
    session=SimpleNamespace(scalar=AsyncMock(return_value=flow),commit=AsyncMock())
    with pytest.raises(HTTPException):
        await consume_flow(session,'state','browser','employee',b'secret',now=now)
    with pytest.raises(HTTPException):
        await consume_flow(session,'','browser','employee',b'secret',now=now)
    session.commit.assert_not_awaited()


@pytest.mark.asyncio
async def test_inactive_identity_and_self_approval_are_denied():
    actor=identity()
    session=SimpleNamespace(scalar=AsyncMock(return_value=actor),scalars=AsyncMock(return_value=SimpleNamespace(all=lambda:[SimpleNamespace(role='hr',department_id=None,revoked_at=None)])))
    with pytest.raises(HTTPException):
        await authorize_person(session,principal_for(actor,actor),actor.person_id,'worktime.approve')
    actor.state='revoked'
    with pytest.raises(HTTPException):
        await authorize_person(session,principal_for(actor,actor),actor.person_id,'worktime.read')


@pytest.mark.asyncio
async def test_bounded_transport_rejects_large_oidc_document():
    from endpoint_server.auth.oidc import BoundedTransport
    transport=BoundedTransport(httpx.MockTransport(lambda _:httpx.Response(200,content=b'x'*65537)))
    async with httpx.AsyncClient(transport=transport) as client:
        with pytest.raises(ValueError,match='too large'):
            await client.get('https://issuer.example/discovery')


@pytest.mark.asyncio
async def test_authlib_refresh_rotates_and_rejects_changed_signed_assurance():
    provider=provider_fixture()
    issuer,subject,guid=validate_claim_identity(provider.fixture_claims,provider.settings.issuer)
    person=identity(issuer=issuer,subject=subject,ad_object_guid=guid)
    tokens={'refresh_token':'initial-refresh-token','_oidc_nonce':'expected-nonce'}
    refreshed,expiry=await provider.refresh('employee',tokens,person,'upstream-session','')
    assert refreshed['refresh_token']=='rotated-refresh-token'
    assert expiry>datetime.now(UTC)
    provider.fixture_claims['acr']='changed'
    with pytest.raises(ValueError,match='assurance'):
        await provider.refresh('employee',tokens,person,'upstream-session','')
