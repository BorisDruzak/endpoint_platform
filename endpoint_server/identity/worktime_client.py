"""Strict confidential consumer of the Helpdesk WorkTime session contract v1."""
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
import json
import re
from uuid import UUID

import httpx
from endpoint_server.identity.helpdesk_client import HelpdeskIdentityClient


class WorktimeAuthorityError(Exception):
    def __init__(self,status=503):
        self.status=status
        super().__init__('WorkTime identity authority unavailable' if status==503 else 'WorkTime authority invalid')


@dataclass(frozen=True)
class WorktimeIdentity:
    person_id: UUID
    department_id: UUID | None
    expires_at: datetime | None = None
    handle: str = field(default='',repr=False)


def canonical_uuid(value):
    if type(value) is not str or str(UUID(value))!=value:raise ValueError('Invalid UUID')
    return UUID(value)


class WorktimeIdentityClient(HelpdeskIdentityClient):
    async def _post(self,path,body,*,expiry=True,handle=False):
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(5),follow_redirects=False,verify=self.tls_context,trust_env=False,transport=self.transport) as client:
                async with client.stream('POST',self.base_url+'/api/integration/v1/worktime/'+path,
                    headers={'Authorization':'Bearer '+self.credential,'Cache-Control':'no-store'},json=body) as response:
                    raw=bytearray()
                    async for chunk in response.aiter_bytes():
                        raw.extend(chunk)
                        if len(raw)>8192:raise ValueError('Oversized response')
                    payload=json.loads(raw)
                    if not isinstance(payload,dict):raise ValueError('Invalid response')
                    if response.status_code!=200:
                        invalid=response.status_code in {400,401,403,404} and payload.get('error')!='service_authority_required'
                        raise WorktimeAuthorityError(401 if invalid else 503)
            expected={'version','person_id','department_id'} | ({'handle'} if handle else {'state'}) | ({'expires_at'} if expiry else set())
            if set(payload)!=expected or type(payload['version']) is not int or payload['version']!=1:raise ValueError('Invalid protocol')
            if not handle and payload['state']!='active':raise WorktimeAuthorityError(401)
            person=canonical_uuid(payload['person_id'])
            department=canonical_uuid(payload['department_id']) if payload['department_id'] is not None else None
            expires=None
            if expiry:
                if not isinstance(payload['expires_at'],str):raise ValueError('Invalid expiry')
                expires=datetime.fromisoformat(payload['expires_at'])
                if expires.tzinfo is None or not datetime.now(UTC)<expires<=datetime.now(UTC)+timedelta(hours=8,minutes=1):raise WorktimeAuthorityError(401)
            if handle and (not isinstance(payload['handle'],str) or re.fullmatch(r'[A-Za-z0-9_-]{43}',payload['handle']) is None):raise ValueError('Invalid lease')
            return WorktimeIdentity(person,department,expires,payload['handle'] if handle else '')
        except WorktimeAuthorityError:raise
        except (httpx.HTTPError,ValueError,TypeError,KeyError,AttributeError):raise WorktimeAuthorityError() from None

    async def exchange(self,code,verifier,callback):
        return await self._post('sessions/exchange',{'code':code,'code_verifier':verifier,'redirect_uri':callback},handle=True)

    async def introspect(self,handle):
        return await self._post('sessions/introspect',{'handle':handle})

    async def resolve_person(self,person_id):
        result=await self._post('people/resolve',{'person_id':str(person_id)},expiry=False)
        if result.person_id!=person_id:raise WorktimeAuthorityError()
        return result
