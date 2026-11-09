from datetime import UTC, datetime, timedelta
import json
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
from fastapi import HTTPException

from endpoint_server.identity.worktime_client import WorktimeIdentityClient, WorktimeAuthorityError
from endpoint_server.auth.worktime_handoff import fixed_helpdesk_endpoints, pkce_challenge
from endpoint_server.auth.employee_sessions import require_privileged_assurance


def test_fixed_pair_and_pkce_vector():
    assert fixed_helpdesk_endpoints('https://endpoint-staging.sosnadmin.local','https://helpdesk-staging.sosnadmin.local')=='https://endpoint-staging.sosnadmin.local/auth/worktime/helpdesk/callback'
    assert pkce_challenge('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk')=='E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'
    with pytest.raises(ValueError):fixed_helpdesk_endpoints('https://endpoint-staging.sosnadmin.local','https://helpdesk.sosnadmin.local')


def test_expired_ip_buckets_do_not_permanently_lock_out_new_employees(monkeypatch):
    from collections import deque
    from endpoint_server.auth import worktime_handoff as module
    monkeypatch.setattr(module,'_STARTS',{str(index):deque([0.0]) for index in range(10000)})
    monkeypatch.setattr(module.time,'monotonic',lambda:61.0)
    module.throttle(SimpleNamespace(client=SimpleNamespace(host='new')))
    assert set(module._STARTS)=={'new'}


@pytest.mark.asyncio
async def test_consumer_strict_contract_and_distinct_outage():
    person=str(uuid4());expiry=(datetime.now(UTC)+timedelta(hours=1)).isoformat()
    seen=[]
    def route(request):
        seen.append(request)
        assert request.headers['authorization']=='Bearer '+'s'*48
        assert json.loads(request.content)=={'handle':'h'*43}
        return httpx.Response(200,json={'version':1,'state':'active','person_id':person,'department_id':None,'expires_at':expiry})
    client=WorktimeIdentityClient('https://helpdesk-staging.sosnadmin.local','s'*48,transport=httpx.MockTransport(route))
    result=await client.introspect('h'*43);assert str(result.person_id)==person
    assert seen[0].url.path=='/api/integration/v1/worktime/sessions/introspect'
    for status,expected in [(401,401),(403,401),(429,503),(503,503)]:
        client.transport=httpx.MockTransport(lambda request:httpx.Response(status,json={'error':'fixture'}))
        with pytest.raises(WorktimeAuthorityError) as error:await client.introspect('h'*43)
        assert error.value.status==expected


@pytest.mark.asyncio
async def test_consumer_never_accepts_extra_authority_or_noncanonical_identity():
    def route(request):return httpx.Response(200,json={'version':1,'state':'active','person_id':str(uuid4()),'department_id':None,'expires_at':(datetime.now(UTC)+timedelta(hours=1)).isoformat(),'role':'admin'})
    client=WorktimeIdentityClient('https://helpdesk-staging.sosnadmin.local','s'*48,transport=httpx.MockTransport(route))
    with pytest.raises(WorktimeAuthorityError):await client.introspect('h'*43)


def test_handoff_principal_never_inherits_existing_privileged_assurance():
    principal=SimpleNamespace(auth_source='helpdesk',required_acr='mfa',achieved_acr='mfa')
    with pytest.raises(HTTPException) as error:require_privileged_assurance(principal)
    assert error.value.status_code==403
