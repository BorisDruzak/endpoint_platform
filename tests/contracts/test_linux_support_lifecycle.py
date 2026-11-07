from datetime import UTC, datetime
from uuid import uuid4

import pytest
from pydantic import ValidationError

from tests.contracts.test_support_access import key


def native_data():
    return dict(version='3.2.178', source_revision='a'*40,
        core_nevra='endpoint-agent-core-3.2.178-alt1.x86_64', core_rpm_sha256='b'*64,
        user_sensor_nevra=None, user_sensor_rpm_sha256=None, exit_code=0)


def event_data(**changes):
    return dict(schema_version='endpoint_linux_installation_event_v1', device_id=str(uuid4()),
        event_id=str(uuid4()), generation_id=str(uuid4()), sequence=1, previous_event_id=None,
        action='installed', occurred_at=datetime.now(UTC).isoformat(), native=native_data(),
        cleanup={'support':'complete','browser':'complete'}) | changes


def test_linux_policy_has_explicit_principal_and_no_windows_wire_field():
    from endpoint_contracts.linux_support_access import LinuxSupportPolicyUpdate
    body=LinuxSupportPolicyUpdate(enabled=True, linux_admin_username='osn-admin', linux_admin_uid=1000, reason='Diagnose canary')
    assert body.platform=='linux_amd64'
    assert 'windows_admin_username' not in body.model_dump()
    with pytest.raises(ValidationError):
        LinuxSupportPolicyUpdate(**{**body.model_dump(),'windows_admin_username':'admin'})


@pytest.mark.parametrize('changes', [
    {'linux_admin_username':'-oProxyCommand=bad'}, {'linux_admin_username':'root\nAllowUsers *'},
    {'linux_admin_username':'SOSNADM\\admin-2'}, {'linux_admin_uid':True}, {'linux_admin_uid':-1},
    {'linux_admin_uid':'1000'}, {'platform':'windows_amd64'},
    {'linux_admin_username':'admin', 'linux_admin_uid':None},
])
def test_linux_unsafe_principal_refused(changes):
    from endpoint_contracts.linux_support_access import LinuxSupportPolicyUpdate
    data=dict(enabled=True,linux_admin_username='osn-admin',linux_admin_uid=1000,reason='Diagnose canary')
    with pytest.raises(ValidationError):
        LinuxSupportPolicyUpdate(**{**data,**changes})


def test_linux_runtime_requires_explicit_own_component_capability():
    from endpoint_contracts.linux_support_access import LinuxSupportStatusReport, LinuxSupportRegistration
    LinuxSupportRegistration(tunnel_public_key=key(),host_public_key=key(2),component_version='1.0.0')
    for changes in ({}, {'component_version':'1.0.1'}, {'component_version':None}):
        with pytest.raises(ValidationError):
            LinuxSupportStatusReport(installed=True,tunnel_connected=False,**changes)


def test_linux_native_source_pair_and_causal_validation():
    from endpoint_contracts.linux_installation_lifecycle import LinuxInstallationEventV1
    body=LinuxInstallationEventV1.model_validate(event_data())
    assert body.native.core_rpm_sha256=='b'*64
    for native in ({'exit_code':True},{'exit_code':1},{'user_sensor_nevra':'sensor-3.2.178-alt1.x86_64'},
                   {'core_nevra':'--root /'},{'product_code':'{fake}'}):
        with pytest.raises(ValidationError):
            LinuxInstallationEventV1.model_validate({**body.model_dump(),'native':{**native_data(),**native}})
    with pytest.raises(ValidationError):
        LinuxInstallationEventV1.model_validate({**body.model_dump(),'sequence':2})


def test_windows_policy_shape_remains_unchanged():
    from endpoint_contracts.support_access import SupportPolicyUpdate
    body=SupportPolicyUpdate(enabled=False,reason='Manual disable')
    assert set(body.model_dump())=={'enabled','expires_at','operator_public_keys','windows_admin_username','reason'}
