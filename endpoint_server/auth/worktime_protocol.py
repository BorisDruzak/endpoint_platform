"""Closed environment and cryptographic format rules for WorkTime handoff."""
import base64
import hashlib
import re
from fastapi import HTTPException

WORKTIME_COOKIE='endpoint_worktime_session'
FLOW_COOKIE='endpoint_worktime_flow'


def opaque(value):
    return isinstance(value,str) and re.fullmatch(r'[A-Za-z0-9_-]{43}',value) is not None


def pkce_challenge(verifier):
    if not isinstance(verifier,str) or re.fullmatch(r'[A-Za-z0-9._~-]{43,128}',verifier) is None:raise ValueError('Invalid verifier')
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode('ascii')).digest()).rstrip(b'=').decode('ascii')


def fixed_helpdesk_endpoints(endpoint,helpdesk):
    expected={'https://endpoint.sosnadmin.local':'https://helpdesk.sosnadmin.local',
        'https://endpoint-staging.sosnadmin.local':'https://helpdesk-staging.sosnadmin.local'}.get(endpoint)
    if expected is None or expected!=helpdesk:raise ValueError('WorkTime environment mismatch')
    return endpoint+'/auth/worktime/helpdesk/callback'


def configured(request):
    settings=request.app.state.settings
    if not getattr(settings,'worktime_helpdesk_enabled',False) or not settings.worktime_enabled or not settings.oidc.enabled:
        raise HTTPException(404,'Helpdesk login unavailable')
    try:return fixed_helpdesk_endpoints(settings.public_base_url,settings.oidc.helpdesk_base_url)
    except ValueError:raise HTTPException(503,'Helpdesk login unavailable') from None
