import importlib.util
from pathlib import Path
import os
import pytest
import shutil
import subprocess

SOURCE = Path(__file__).resolve().parents[2] / 'packaging/alt/SOURCES/start-user-sensor.py'

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
