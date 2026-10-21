import importlib.util
from pathlib import Path
import os
import pytest
import shutil
import subprocess

SOURCE = Path(__file__).resolve().parents[2] / 'packaging/alt/SOURCES/start-user-sensor.py'


def test_user_unit_preserves_host_uid_namespace_for_mutual_ipc():
    from configparser import ConfigParser
    unit = ConfigParser(interpolation=None)
    unit.read(SOURCE.with_name('endpoint-user-sensor.service'), encoding='utf-8')
    service = unit['Service']
    assert service.get('PrivateUsers') == 'no'
    # User-unit mount sandboxing implies a user namespace: unmapped root becomes
    # UID 65534, breaking root-owned selector and service socket authentication.
    assert service.get('ProtectSystem', 'no') == 'no'
    assert service.get('ProtectHome', 'no') == 'no'
    assert service.get('NoNewPrivileges') == 'yes'
    assert service.get('RestrictAddressFamilies') == 'AF_UNIX'

def _module():
    spec = importlib.util.spec_from_file_location('alt_sensor_start', SOURCE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def test_sensor_autostart_does_not_import_global_manager_environment(monkeypatch):
    module = _module()
    calls = []
    monkeypatch.setattr(module.os, 'getuid', lambda: 1000, raising=False)
    monkeypatch.setattr(module.os, 'geteuid', lambda: 1000, raising=False)
    monkeypatch.setattr(module.sys, 'argv', ['start-user-sensor', '--autostart'])
    monkeypatch.setattr(module, 'write_session_environment', lambda: calls.append('own-environment'))
    monkeypatch.setattr(module.subprocess, 'run', lambda args, **kwargs: calls.append(args))
    assert module.main() == 0
    assert calls == ['own-environment', ['systemctl', '--user', 'start', 'endpoint-user-sensor.service']]

def test_sensor_wrapper_refuses_root_and_unexpected_arguments(monkeypatch):
    module = _module()
    monkeypatch.setattr(module.os, 'getuid', lambda: 0, raising=False)
    assert module.main() == 1
    monkeypatch.setattr(module.os, 'getuid', lambda: 1000, raising=False)
    monkeypatch.setattr(module.os, 'geteuid', lambda: 1000, raising=False)
    monkeypatch.setattr(module.sys, 'argv', ['start-user-sensor', '--arbitrary-command'])
    assert module.main() == 1


def test_native_host_wrapper_uses_the_protected_selector_and_no_device_credential(monkeypatch):
    source = SOURCE.with_name('start-browser-bridge.py')
    spec = importlib.util.spec_from_file_location('alt_bridge_start', source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module.os, 'getuid', lambda: 0, raising=False)
    assert module.main() == 78
    monkeypatch.setattr(module.os, 'getuid', lambda: 1000, raising=False)
    monkeypatch.setattr(module.os, 'geteuid', lambda: 1000, raising=False)
    origin='chrome-extension://'+'a'*32+'/'
    monkeypatch.setattr(module.sys, 'argv', ['browser-bridge',origin])
    def selected(arguments, **kwargs):
        assert arguments == ['/usr/lib/endpoint-agent/check-start-prerequisites','--print-selected-version']
        return subprocess.CompletedProcess(arguments, 0, stdout=b'3.2.123\n')
    monkeypatch.setattr(module.subprocess, 'run', selected)
    def execute(path, arguments):
        assert Path(path).as_posix() == '/opt/endpoint-agent/versions/3.2.123/endpoint-agent/endpoint-agent'
        assert arguments[1:] == ['--linux-browser-bridge',origin]
        raise RuntimeError('exec reached')
    monkeypatch.setattr(module.os, 'execv', execute)
    with pytest.raises(RuntimeError, match='exec reached'):
        module.main()


def test_optional_sensor_spec_parses_with_the_native_alt_macroset():
    if not shutil.which('rpmspec') or not shutil.which('rpm'):
        pytest.skip('native ALT RPM tools unavailable')
    probe = subprocess.run(['rpm', '--eval', '%{?def_without:ALT_MACROS}'], capture_output=True, text=True, timeout=5, check=True)
    if 'ALT_MACROS' not in probe.stdout:
        pytest.skip('ALT RPM conditional macros unavailable')
    spec = SOURCE.parent.parent / 'endpoint-agent.spec'
    result = subprocess.run(['rpmspec', '-q', '--qf', '%{NAME}\n',
        '--define', '_with_user_sensor 1', '--define', 'agent_version 3.2.122',
        '--define', 'source_revision ' + 'a' * 40, str(spec)], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert set(result.stdout.splitlines()) == {'endpoint-agent', 'endpoint-agent-user-sensor'}
