import base64
import struct
import pytest
from pydantic import ValidationError


def key(seed=1):
    kind = b'ssh-ed25519'
    return 'ssh-ed25519 ' + base64.b64encode(struct.pack('>I', len(kind))+kind+struct.pack('>I',32)+bytes([seed])*32).decode()


def test_registration_bounds_and_role_separation():
    from endpoint_contracts.support_access import SupportRegistration
    valid = dict(tunnel_public_key=key(), host_public_key=key(2), component_version='1.0.0')
    assert SupportRegistration(**valid).component_version == '1.0.0'
    for invalid in [dict(valid, host_public_key=key()), dict(valid, tunnel_public_key='ssh-ed25519 bad'), dict(valid, component_version='x'*129), dict(valid, device_id='forged')]:
        with pytest.raises(ValidationError):
            SupportRegistration(**invalid)


def test_agent_cannot_claim_access_verification():
    from endpoint_contracts.support_access import SupportStatusReport
    with pytest.raises(ValidationError):
        SupportStatusReport(installed=True,tunnel_connected=True,access_verified=True)


def test_tunnel_report_requires_installed_component():
    from endpoint_contracts.support_access import SupportStatusReport
    with pytest.raises(ValidationError):
        SupportStatusReport(installed=False,tunnel_connected=True)
