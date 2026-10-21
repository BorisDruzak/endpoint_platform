"""The user mode bypasses all enrollment/settings/credential work."""
from pc_agent.runtime import main as entry


def test_linux_user_entry_needs_no_ca_or_device_configuration(monkeypatch):
    from pc_agent.platform.linux import user_sensor_runtime

    monkeypatch.setattr(entry.sys, 'platform', 'linux')
    monkeypatch.setattr(user_sensor_runtime, 'main', lambda: 23)
    monkeypatch.setattr(entry, '_service_endpoint_origin', lambda value: (_ for _ in ()).throw(AssertionError('server settings touched')))
    assert entry.main(['--linux-user-sensor']) == 23


def test_linux_user_entry_refuses_other_platforms(monkeypatch):
    monkeypatch.setattr(entry.sys, 'platform', 'win32')
    assert entry.main(['--linux-user-sensor']) == 1


def test_linux_browser_entry_needs_no_ca_or_device_configuration(monkeypatch):
    from pc_agent.platform.linux import browser_bridge_entry
    origin = 'chrome-extension://' + 'a' * 32 + '/'
    monkeypatch.setattr(entry.sys, 'platform', 'linux')
    seen = []
    monkeypatch.setattr(browser_bridge_entry, 'main', lambda args: seen.append(args) or 23)
    monkeypatch.setattr(entry, '_service_endpoint_origin', lambda value: (_ for _ in ()).throw(AssertionError('server settings touched')))
    assert entry.main(['--linux-browser-bridge', origin]) == 23
    assert seen == [[origin]]


def test_linux_browser_entry_refuses_other_platforms(monkeypatch):
    monkeypatch.setattr(entry.sys, 'platform', 'win32')
    assert entry.main(['--linux-browser-bridge']) == 1
