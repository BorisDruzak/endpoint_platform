"""Linux reuses PolicyRuntime and reports unavailable adapters honestly."""
import pytest

from pc_agent.policy.runtime import PolicyApplicationError
from pc_agent.tests.policy.test_runtime import _delivery


@pytest.mark.asyncio
async def test_linux_activity_requires_listener_but_disabled_policy_does_not():
    from pc_agent.policy.linux_sensors import apply_linux_policy_sensors

    await apply_linux_policy_sensors(_delivery(active=False).policy)
    disabled = _delivery(active=False).policy
    active = disabled.model_copy(update={'activity': disabled.activity.model_copy(update={'enabled': True, 'foreground_application': True})})
    with pytest.raises(PolicyApplicationError, match='SENSOR_NOT_READY'):
        await apply_linux_policy_sensors(active)
    await apply_linux_policy_sensors(active, activity_available=True)


@pytest.mark.asyncio
@pytest.mark.parametrize('field,available', [('usb_device_events', 'usb_available'), ('print_events', 'print_available'), ('browser_upload_events', 'browser_audit_available'), ('browser_paste_events', 'browser_audit_available')])
async def test_requested_audit_source_must_exist(field, available, monkeypatch):
    monkeypatch.setattr('pc_agent.policy.linux_sensors.send_policy_request', lambda *_args:'EXTERNALLY_MANAGED')
    from pc_agent.policy.linux_sensors import apply_linux_policy_sensors

    disabled = _delivery(active=False).policy
    requested = disabled.model_copy(update={'dlp': disabled.dlp.model_copy(update={field: 'audit'})})
    with pytest.raises(PolicyApplicationError, match='SENSOR_NOT_READY'):
        await apply_linux_policy_sensors(requested)
    await apply_linux_policy_sensors(requested, **{available: True})


@pytest.mark.asyncio
async def test_unimplemented_managed_browser_is_not_reported_applied():
    from pc_agent.policy.linux_sensors import apply_linux_policy_sensors

    disabled = _delivery(active=False).policy
    managed = disabled.model_copy(update={'browser_sensor': disabled.browser_sensor.model_copy(update={'deployment_mode': 'agent_managed'})})
    with pytest.raises(PolicyApplicationError, match='SENSOR_NOT_READY'):
        await apply_linux_policy_sensors(managed, activity_available=True)


@pytest.mark.asyncio
async def test_managed_policy_uses_fixed_helper_operations_after_source_readiness(monkeypatch):
    from pc_agent.policy import linux_sensors
    calls = []
    monkeypatch.setattr(linux_sensors, 'send_policy_request',
        lambda operation, family: calls.append((operation, family)) or 'APPLIED')
    disabled = _delivery(active=False).policy
    managed = disabled.model_copy(update={'browser_sensor': disabled.browser_sensor.model_copy(update={'deployment_mode':'agent_managed'})})
    await linux_sensors.apply_linux_policy_sensors(managed, browser_audit_available=True)
    assert calls == [('apply','chrome'), ('apply','yandex')]


@pytest.mark.asyncio
async def test_external_mode_relinquishes_owned_policy_and_reports_conflict(monkeypatch):
    from pc_agent.policy import linux_sensors
    calls = []
    monkeypatch.setattr(linux_sensors, 'send_policy_request',
        lambda operation, family: calls.append((operation, family)) or 'EXTERNALLY_MANAGED')
    await linux_sensors.apply_linux_policy_sensors(_delivery(active=False).policy, browser_audit_available=True)
    assert calls == [('relinquish','chrome'), ('relinquish','yandex')]
    monkeypatch.setattr(linux_sensors, 'send_policy_request', lambda *_args: 'POLICY_CONFLICT')
    with pytest.raises(PolicyApplicationError, match='POLICY_CONFLICT'):
        await linux_sensors.apply_linux_policy_sensors(_delivery(active=False).policy, browser_audit_available=True)
