from pathlib import Path
from types import SimpleNamespace

import pytest

from pc_agent.platform.windows import setup_update_bootstrap as bootstrap


def test_assets_absent_verification_remains_network_free_and_has_no_install(monkeypatch):
    monkeypatch.setattr(bootstrap, 'packaged_client', lambda: None)
    monkeypatch.setattr(bootstrap.subprocess, 'run', lambda *a, **k: pytest.fail('must not execute'))
    assert bootstrap.bootstrap_setup_client(SimpleNamespace()) == 0


def test_non_system_process_cannot_install_privileged_client(monkeypatch, tmp_path):
    asset = tmp_path / 'EndpointSetupUpdater.ps1'
    asset.write_text('signed fixture placeholder')
    monkeypatch.setattr(bootstrap, 'packaged_client', lambda: asset)
    monkeypatch.setattr(bootstrap, 'is_local_system', lambda: False)
    monkeypatch.setattr(bootstrap.subprocess, 'run', lambda *a, **k: pytest.fail('must not execute'))
    assert bootstrap.bootstrap_setup_client(SimpleNamespace()) == 0


def test_bootstrap_has_fixed_signed_script_action_and_no_secret_arguments(monkeypatch, tmp_path):
    asset = tmp_path / 'EndpointSetupUpdater.ps1'
    asset.write_text('signed fixture placeholder')
    monkeypatch.setattr(bootstrap, 'packaged_client', lambda: asset)
    monkeypatch.setattr(bootstrap, 'is_local_system', lambda: True)
    monkeypatch.setattr(bootstrap, 'assert_fixed_verifier_context', lambda settings: None)
    monkeypatch.setattr(bootstrap, 'system_powershell', lambda: Path('C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe'))
    calls = []
    monkeypatch.setattr(bootstrap.subprocess, 'run', lambda args, **kw: calls.append((args, kw)) or SimpleNamespace(returncode=0))
    assert bootstrap.bootstrap_setup_client(SimpleNamespace()) == 0
    args, kwargs = calls[0]
    import base64
    assert '-EncodedCommand' in args
    code = base64.b64decode(args[-1]).decode('utf-16-le')
    assert str(asset).replace("'", "''") in code
    assert "-Mode Install" in code and 'TrustedPublisher' in code
    assert '4D4C23389F5FF77BC4EB32044761019EAE8FB776' in code
    assert 'Bypass' not in code
    assert args[args.index('-ExecutionPolicy') + 1] == 'AllSigned'
    assert kwargs['shell'] is False and kwargs['timeout'] <= 90
    assert all('credential' not in arg.lower() for arg in args)


def test_failed_bootstrap_refuses_core_candidate_verification(monkeypatch, tmp_path):
    asset = tmp_path / 'EndpointSetupUpdater.ps1'
    asset.write_text('fixture')
    monkeypatch.setattr(bootstrap, 'packaged_client', lambda: asset)
    monkeypatch.setattr(bootstrap, 'is_local_system', lambda: True)
    monkeypatch.setattr(bootstrap, 'assert_fixed_verifier_context', lambda settings: None)
    monkeypatch.setattr(bootstrap, 'system_powershell', lambda: Path('C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe'))
    monkeypatch.setattr(bootstrap.subprocess, 'run', lambda *a, **k: SimpleNamespace(returncode=20))
    assert bootstrap.bootstrap_setup_client(SimpleNamespace()) != 0


def test_msi_verification_without_core_assignment_does_not_install_client(monkeypatch, tmp_path):
    asset = tmp_path / 'EndpointSetupUpdater.ps1'
    asset.write_text('fixture')
    monkeypatch.setattr(bootstrap, 'packaged_client', lambda: asset)
    monkeypatch.setattr(bootstrap, 'is_local_system', lambda: True)
    monkeypatch.setattr(bootstrap, 'assert_fixed_verifier_context', lambda settings: False)
    monkeypatch.setattr(bootstrap.subprocess, 'run', lambda *a, **k: pytest.fail('MSI verification must not bootstrap'))
    assert bootstrap.bootstrap_setup_client(SimpleNamespace()) == 0
