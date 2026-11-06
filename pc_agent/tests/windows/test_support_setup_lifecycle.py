"""Support activation follows accepted native work, never rollback/UNKNOWN."""
from types import SimpleNamespace

import pytest

from pc_agent.platform.windows import provision, setup_entry
from pc_agent.tests.windows.test_setup_entry import literal_msi_costing_boundary, _write_public_payload
from pc_agent.tests.windows.test_staged_update_state import staged, native_protected_root


@pytest.mark.parametrize('native', [67, 3010, 1641, 'unknown'])
def test_failed_or_unaccepted_native_work_never_activates_support(monkeypatch, tmp_path, native):
    _write_public_payload(tmp_path)
    monkeypatch.setattr(setup_entry, '_data_root', lambda: tmp_path / 'data')
    monkeypatch.setattr(setup_entry, '_resource_root', lambda: tmp_path)
    monkeypatch.setattr(setup_entry, '_classify_installation_state', lambda *_a, **_kw: 'valid')
    monkeypatch.setattr(setup_entry, '_installed_msi_version', lambda: '1.0.0')
    monkeypatch.setattr(setup_entry, '_msi_reconciliation_required', lambda _: True)
    events = []
    def wrapper(_):
        events.append('native-owner')
        if native == 'unknown':
            raise setup_entry.SetupInstallError('MSI_EVIDENCE_FAILED')
        return native
    monkeypatch.setattr(setup_entry, '_install_embedded_msi', wrapper)
    monkeypatch.setattr(provision, 'install_enrolled_support', lambda _: pytest.fail('unaccepted native work touched Support'))
    monkeypatch.setattr(setup_entry, '_wait_for_agent_service_running', lambda: pytest.fail('unaccepted candidate reached final health'))
    result = setup_entry.main(['--quiet'])
    assert result == (setup_entry.EXIT_INSTALL_FAILED if native == 'unknown' else native)
    assert events == ['native-owner']


def test_same_version_retry_preserves_active_native_ownership(monkeypatch, tmp_path):
    from contextlib import contextmanager
    @contextmanager
    def busy(*_a, **_kw):
        raise setup_entry.UpdateInProgress('UPDATE_IN_PROGRESS')
        yield
    monkeypatch.setattr(setup_entry, '_data_root', lambda: tmp_path / 'data')
    monkeypatch.setattr(setup_entry, 'update_transaction', busy)
    monkeypatch.setattr(provision, 'install_enrolled_support', lambda _: pytest.fail('busy native ownership touched Support'))
    assert setup_entry.main(['--quiet']) == setup_entry.EXIT_UPDATE_IN_PROGRESS


def test_installer_uses_staged_helper_without_passing_device_credential(monkeypatch, tmp_path):
    from pc_agent.platform.windows import update_paths
    data = tmp_path / 'ProgramData/Endpoint Platform/Agent'
    staged = tmp_path / 'ProgramFiles/Endpoint Platform/Agent/EndpointSupportAccess.exe'
    staged.parent.mkdir(parents=True)
    staged.write_bytes(b'signed staged helper model')
    monkeypatch.setattr(update_paths, '_native_folder', lambda folder: tmp_path / ('ProgramData' if folder == 0x23 else 'ProgramFiles'))
    calls = []
    def run(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(returncode=0, stdout='{"installed":true}')
    monkeypatch.setattr(provision.subprocess if hasattr(provision, 'subprocess') else __import__('subprocess'), 'run', run)
    assert provision.install_enrolled_support(data) == {'installed': True}
    assert calls[0][0] == [str(staged), '--install']
    assert calls[0][1]['shell'] is False


@pytest.mark.parametrize('schema,status', [(3, 'incomplete'), (3, 'complete'), (2, 'complete')])
def test_known_native_uninstall_finishes_fence_before_reporting_support_cleanup(staged, monkeypatch, schema, status):
    import json
    from pc_agent.platform.windows import installer_transaction_bridge as bridge, installer_fence as fence, msi_inventory
    _, paths, binding, _ = staged
    package = SimpleNamespace(sha256='a'*64, product_code=binding.new_release['product_code'],
        package_code='{11111111-1111-4111-8111-111111111111}', version='3.2.122')
    expected = SimpleNamespace(package=package, identity=SimpleNamespace(source_revision='b'*40), foundation_schema=schema)
    cap = dict(operation='uninstall', transaction_id=binding.operation_id, selected=None, previous=None,
               service_states={'EndpointAgent': 'stopped', 'EndpointAgentUpdater': 'stopped'})
    events = []
    monkeypatch.setattr(bridge, '_request_data', lambda *_: {'package_path': paths.install_root / 'known.msi'})
    monkeypatch.setattr(msi_inventory, 'read_expected_package', lambda *_: expected)
    cap['package'] = binding.new_release
    monkeypatch.setattr(msi_inventory, 'verify_uninstalled', lambda *_: events.append('native-absence'))
    def support_absence(*_):
        events.append('support-absence')
        if status == 'incomplete':
            raise ValueError('SUPPORT_CLEANUP_INCOMPLETE')
    monkeypatch.setattr(msi_inventory, 'verify_support_uninstalled', support_absence)
    original = bridge._public_fence(expected, cap)
    original['phase'] = 'reconciling'
    fence.publish_fence(paths, original)
    client = SimpleNamespace(capability=cap, phase='finish', checkpoint=lambda: None,
        identity=SimpleNamespace(value={'pid': 1, 'created': 1, 'hash': 'c'*64}),
        request=lambda *args: events.append(args))
    result = bridge._execute_authorized_phase(client, paths)
    # The real fence transitions, durable completion and unlink all run. Only
    # native product/independent-resource observation is modeled here.
    assert fence.read_fence(paths) is None
    archive = bridge.completion_root(paths, cap)
    completed = json.loads((archive / 'completed.json').read_text())
    assert completed['phase'] == 'complete' and completed['startup_restored'] is True
    assert events[0] == 'native-absence'
    if schema == 3:
        receipt = json.loads((archive / 'support-cleanup.json').read_text())
        assert receipt['native_result'] == 0 and receipt['native_uninstalled'] is True
        assert receipt['support_cleanup'] == status
        assert result == {'result': 'native-uninstalled', 'support_cleanup': status}
        assert events[-1] == ('complete', result)
    else:
        assert not (archive / 'support-cleanup.json').exists()
        assert 'support-absence' not in events


def test_setup_reports_known_native_cleanup_failure_separately(monkeypatch, tmp_path):
    import json
    _write_public_payload(tmp_path)
    monkeypatch.setattr(setup_entry, '_data_root', lambda: tmp_path / 'data')
    monkeypatch.setattr(setup_entry, '_resource_root', lambda: tmp_path)
    monkeypatch.setattr(setup_entry, '_classify_installation_state', lambda *_a, **_kw: 'valid')
    monkeypatch.setattr(setup_entry, '_installed_msi_version', lambda: '1.0.0')
    monkeypatch.setattr(setup_entry, '_msi_reconciliation_required', lambda _: True)
    monkeypatch.setattr(setup_entry, '_install_embedded_msi', lambda _: 68)
    monkeypatch.setattr(provision, 'install_enrolled_support', lambda _: pytest.fail('uninstall cleanup failure attempted activation'))
    assert setup_entry.main(['--quiet']) == 68
    result = json.loads((tmp_path / 'diagnostics/install-result.json').read_text())
    assert result['status'] == 'SUPPORT_CLEANUP_INCOMPLETE'
    assert result['detail'] == 'NATIVE_UNINSTALLED_SUPPORT_CLEANUP_INCOMPLETE'
