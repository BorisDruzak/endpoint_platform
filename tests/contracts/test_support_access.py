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


@pytest.mark.parametrize(('value','expected'), [
    ('test_agent_win','test_agent_win'), ('admin-2','admin-2'), ('Local_Admin','Local_Admin'),
    (r'SOSNADM\admin-2',r'sosnadm\admin-2'), ('D'*15+'\\'+'S'*48,'d'*15+'\\'+'s'*48),
])
def test_policy_accepts_existing_local_or_explicit_domain_principal(value,expected):
    from endpoint_contracts.support_access import SupportPolicyUpdate
    policy=SupportPolicyUpdate(enabled=False,windows_admin_username=value,reason='Principal validation')
    assert policy.windows_admin_username==expected


@pytest.mark.parametrize('value', [
    'a'*65, 'D'*16+'\\sam', 'D'*15+'\\'+'s'*49, 'DOMAIN\\'+'s'*65, r'\sam', 'DOMAIN\\', r'DOMAIN\SAM\extra',
    'user@domain', 'DOMAIN/user', 'DOMAIN\\user name', ' user', 'user ', 'user\nMatch all',
    'DOMAIN\\user\r\nAllowUsers *', 'DOMAIN\\user\t', 'DOMAIN\\user\0', 'ДОМЕН\\user',
    'DOMAIN\\усер', 'DOMAIN\\*', 'DOMAIN\\user?', 'DOMAIN\\[user]', 'DOMAIN\\user;cmd',
    'DOMAIN\\user|cmd', '-oProxyCommand', '.\\sam',
])
def test_policy_rejects_ambiguous_or_ssh_injectable_principal(value):
    from endpoint_contracts.support_access import SupportPolicyUpdate
    with pytest.raises(ValidationError):
        SupportPolicyUpdate(enabled=False,windows_admin_username=value,reason='Principal validation')


def test_support_runtime_status_accepts_optional_canonical_version_and_legacy_wire():
    from endpoint_contracts.support_access import SupportStatusReport
    assert SupportStatusReport(installed=True,tunnel_connected=False).component_version is None
    assert SupportStatusReport(installed=True,tunnel_connected=False,component_version='1.0.1').component_version=='1.0.1'


@pytest.mark.parametrize('version',['01.0.1','1.0','1.0.1evil','1.0.1\n','1.0.１００','999999.0.0'])
def test_support_runtime_version_is_closed_and_bounded(version):
    from endpoint_contracts.support_access import SupportStatusReport
    with pytest.raises(ValidationError):
        SupportStatusReport(installed=True,tunnel_connected=False,component_version=version)
