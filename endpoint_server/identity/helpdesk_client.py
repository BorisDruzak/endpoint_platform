"""Bounded, TLS verified client for the minimal Helpdesk identity contract v1."""
from dataclasses import dataclass
from urllib.parse import urlsplit
from uuid import UUID
import json
import ssl

import httpx


class IdentityResolutionError(Exception):
    """Remote authority unavailable or supplied no exact active binding."""


def verified_tls_context(ca_file: str | None = None) -> ssl.SSLContext:
    context = ssl.create_default_context()
    if ca_file:
        context.load_verify_locations(cafile=ca_file)
    return context


@dataclass(frozen=True)
class ResolvedIdentity:
    person_id: UUID
    issuer: str
    subject: str
    ad_object_guid: UUID
    department_id: UUID | None


def https_origin(value: str) -> str:
    parsed = urlsplit(value)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment):
        raise ValueError('A fixed HTTPS URL without credentials is required')
    return value.rstrip('/')


async def bounded_json(response: httpx.Response, limit: int = 65536) -> dict:
    response.raise_for_status()
    body = bytearray()
    async for chunk in response.aiter_bytes():
        body.extend(chunk)
        if len(body) > limit:
            raise ValueError('Response too large')
    payload = json.loads(body)
    if not isinstance(payload, dict):
        raise ValueError('Expected JSON object')
    return payload


class HelpdeskIdentityClient:
    def __init__(self, base_url: str, credential: str, *, transport=None, ca_file: str | None=None):
        self.base_url = https_origin(base_url)
        if urlsplit(base_url).path not in ('', '/') or len(credential) < 43 or not credential.isascii() or any(c.isspace() for c in credential):
            raise ValueError('Fixed origin and dedicated high entropy credential required')
        self.credential = credential
        self.transport = transport
        self.tls_context = verified_tls_context(ca_file)

    async def resolve(self, issuer: str, subject: str, ad_object_guid: UUID) -> ResolvedIdentity:
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(5), follow_redirects=False, verify=self.tls_context, trust_env=False, transport=self.transport) as client:
                async with client.stream('POST', self.base_url + '/api/integration/v1/identities/resolve',
                    headers={'Authorization':'Bearer ' + self.credential, 'Cache-Control':'no-store'},
                    json={'issuer':issuer, 'subject':subject, 'ad_object_guid':str(ad_object_guid)}) as response:
                    payload = await bounded_json(response, 8192)
            if (set(payload) != {'version','person_id','issuer','subject','ad_object_guid','state','department_id'}
                or type(payload['version']) is not int or payload['version'] != 1
                or payload['state'] != 'active' or payload['issuer'] != issuer
                or payload['subject'] != subject or payload['ad_object_guid'] != str(ad_object_guid)):
                raise ValueError('Invalid identity response')
            person_id = UUID(payload['person_id'])
            department_id = UUID(payload['department_id']) if payload['department_id'] is not None else None
            if str(person_id) != payload['person_id'] or (department_id is not None and str(department_id) != payload['department_id']):
                raise ValueError('Noncanonical identifier')
            return ResolvedIdentity(person_id,issuer,subject,ad_object_guid,department_id)
        except (httpx.HTTPError, ValueError, TypeError, KeyError, AttributeError) as error:
            raise IdentityResolutionError('Confirmed identity is unavailable') from None
