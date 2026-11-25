from datetime import UTC, datetime
import json
import os
from types import SimpleNamespace

import pytest

from pc_agent.platform.windows import installation_lifecycle, installer_fence as fence, native_setup_observer
from pc_agent.platform.windows.update_paths import WindowsUpdatePaths
from pc_agent.tests.windows.test_installer_fence import state


def _record(paths, transaction, release, *, action='removed', year=2026, device_id=None, support='not_applicable'):
    return installation_lifecycle.outbox_for(paths).record(
        transaction_id=transaction, action=action, device_id=device_id, occurred_at=datetime(year, 1, 1, tzinfo=UTC),
        native=dict(version=release['version'], product_code=release['product_code'],
                    source_revision=release['source_revision'], msi_sha256=release['package_sha256'], exit_code=0),
        cleanup={'support': support, 'browser': 'not_applicable'})


@pytest.fixture
def retry(tmp_path, monkeypatch, request):
    paths = WindowsUpdatePaths(tmp_path / 'Agent', tmp_path / 'data' / 'updates' / 'pending_update.json')
    transactions = fence.state_root(paths) / 'transactions'
    transaction = '12345678-1234-4234-8234-123456789abc'
    archive = transactions / transaction
    archive.mkdir(parents=True)
    completed = state()
    completed.update(transaction_id=transaction, operation='uninstall', phase='complete', startup_restored=True)
    completed['helpers'] = [{'pid': 1, 'creation_time': 100, 'image_sha256': 'e' * 64, 'phase': 'complete', 'complete': True}]
    package = {**completed['package'], 'package_sha256': completed['package']['sha256']}
    payload = dict(schema_version=1, transaction_id=transaction, package_sha256=package['package_sha256'],
                   native_result=0, native_uninstalled=True, observer_cleanup='incomplete')
    (archive / 'completed.json').write_text(json.dumps(completed))
    (archive / 'observer-cleanup.json').write_text(json.dumps(payload))
    monkeypatch.setattr(fence, 'assert_state_security', lambda path: None)
    monkeypatch.setattr(installation_lifecycle, '_assert_private', lambda path: None)
    monkeypatch.setattr(installation_lifecycle, '_protect_private', lambda path: None)
    fact_delivery = getattr(request, 'param', 'undeliverable')
    if fact_delivery != 'missing':
        device = '11111111-1111-4111-8111-111111111111' if fact_delivery == 'pending' else None
        _record(paths, transaction, package, device_id=device,
                support='incomplete' if fact_delivery == 'support-incomplete' else 'not_applicable')
    from pc_agent.platform.windows import durable_state, installation_provenance, installer_transaction_bridge, msi_inventory
    monkeypatch.setattr(durable_state, 'installer_mutation_checkpoint', lambda **kw: None)
    monkeypatch.setattr(installation_provenance, '_assert_security', lambda path: None)
    monkeypatch.setattr(installer_transaction_bridge, '_settled', lambda paths: None)
    calls = []
    monkeypatch.setattr(msi_inventory, 'NativeMsi', lambda: SimpleNamespace(related_products=lambda code: ()))
    monkeypatch.setattr(msi_inventory, 'verify_uninstalled', lambda pkg, root, **kw: calls.append('absence'))
    monkeypatch.setattr(native_setup_observer, 'retire_packaged_observer', lambda paths: calls.append('retire') or 'removed')
    monkeypatch.setattr(native_setup_observer, 'write_observer_cleanup_receipt',
                        lambda *args: calls.append(('receipt', args[-1])))
    return paths, transaction, package, archive, completed, payload, calls


@pytest.mark.parametrize('retry', ['undeliverable', 'pending'], indirect=True)
def test_retry_only_rechecks_absence_and_updates_observer_receipt(retry):
    from pc_agent.platform.windows.observer_cleanup_retry import retry_observer_cleanup

    paths, transaction, package, archive, completed, payload, calls = retry
    expected = SimpleNamespace(package=SimpleNamespace(package_code=completed['package']['package_code']))
    assert retry_observer_cleanup(paths, transaction, package, expected) == {
        'observer_cleanup': 'removed', 'support_cleanup': 'not_applicable'}
    assert calls == ['absence', 'retire', ('receipt', 'removed')]
    assert json.loads((archive / 'completed.json').read_text()) == completed


@pytest.mark.parametrize('task', ['absent', 'reappeared', 'inaccessible'])
def test_retry_already_removed_is_read_only(retry, monkeypatch, task):
    from pc_agent.platform.windows.observer_cleanup_retry import retry_observer_cleanup

    paths, transaction, package, archive, completed, payload, calls = retry
    expected = SimpleNamespace(package=SimpleNamespace(package_code=completed['package']['package_code']))
    payload['observer_cleanup'] = 'removed'
    (archive / 'observer-cleanup.json').write_text(json.dumps(payload))

    def lookup(folder, name):
        assert name == 'EndpointSetupUpdater'
        if task == 'inaccessible':
            raise PermissionError
        return None if task == 'absent' else object()

    monkeypatch.setattr(native_setup_observer, '_scheduler_folder', lambda: object())
    monkeypatch.setattr(native_setup_observer, 'find_task', lookup)
    outcome = retry_observer_cleanup(paths, transaction, package, expected)
    assert outcome == {'observer_cleanup': 'removed' if task == 'absent' else 'incomplete',
                       'support_cleanup': 'not_applicable'}
    assert calls == ['absence']
    assert json.loads((archive / 'observer-cleanup.json').read_text()) == payload


@pytest.mark.parametrize('defect', ['new-owner', 'wrong-receipt', 'present-product', 'active-fence', 'related-product'])
def test_retry_rejects_stale_or_unproven_authority(retry, monkeypatch, defect):
    from pc_agent.platform.windows.observer_cleanup_retry import retry_observer_cleanup
    from pc_agent.platform.windows import msi_inventory

    paths, transaction, package, archive, completed, payload, calls = retry
    expected = SimpleNamespace(package=SimpleNamespace(package_code=completed['package']['package_code']))
    if defect == 'new-owner':
        newer = archive.parent / '12345678-1234-4234-8234-123456789def'
        newer.mkdir()
        completed.update(transaction_id=newer.name, operation='install')
        completed['helpers'][0]['creation_time'] += 1
        (newer / 'completed.json').write_text(json.dumps(completed))
        _record(paths, newer.name, package, action='installed')
    elif defect == 'wrong-receipt':
        payload['native_result'] = 1
        (archive / 'observer-cleanup.json').write_text(json.dumps(payload))
    elif defect == 'present-product':
        def present(pkg, root, **kw):
            raise ValueError('PROVENANCE_CONFLICT')
        monkeypatch.setattr(msi_inventory, 'verify_uninstalled', present)
    elif defect == 'active-fence':
        monkeypatch.setattr(fence, 'read_fence', lambda paths: completed)
    else:
        def related(code):
            assert code == msi_inventory.UPGRADE_CODE
            return ('{00000000-0000-0000-0000-000000000001}',)

        monkeypatch.setattr(msi_inventory, 'NativeMsi', lambda: SimpleNamespace(related_products=related))
    with pytest.raises(ValueError):
        retry_observer_cleanup(paths, transaction, package, expected)
    assert 'retire' not in calls


def test_newer_install_blocks_retry_even_when_all_clocks_go_back(retry):
    from pc_agent.platform.windows.observer_cleanup_retry import retry_observer_cleanup

    paths, transaction, package, archive, completed, payload, calls = retry
    expected = SimpleNamespace(package=SimpleNamespace(package_code=completed['package']['package_code']))
    newer = archive.parent / '12345678-1234-4234-8234-123456789def'
    newer.mkdir()
    completed.update(transaction_id=newer.name, operation='install')
    completed['helpers'][0]['creation_time'] -= 1
    receipt = newer / 'completed.json'
    receipt.write_text(json.dumps(completed))
    os.utime(receipt, (1_600_000_000, 1_600_000_000))
    _record(paths, newer.name, package, action='installed', year=2025)

    with pytest.raises(ValueError, match='PROVENANCE_CONFLICT'):
        retry_observer_cleanup(paths, transaction, package, expected)
    assert calls == []


@pytest.mark.parametrize('retry', ['missing'], indirect=True)
def test_retry_requires_original_native_fact(retry):
    from pc_agent.platform.windows.observer_cleanup_retry import retry_observer_cleanup

    paths, transaction, package, archive, completed, payload, calls = retry
    expected = SimpleNamespace(package=SimpleNamespace(package_code=completed['package']['package_code']))

    with pytest.raises(ValueError, match='PROVENANCE_CONFLICT'):
        retry_observer_cleanup(paths, transaction, package, expected)
    assert calls == []


@pytest.mark.parametrize('invalid', [None, 'compound', 'recovery', 'selected', 'uninstall_finalization'])
def test_cleanup_phase_uses_only_standalone_uninstall_authority(monkeypatch, invalid):
    from pc_agent.platform.windows import installer_transaction_bridge as bridge, msi_inventory, observer_cleanup_retry
    from pc_agent.platform.windows.installer_native_entry import _parser

    phase = _parser().parse_args(['--installer-phase', 'retry-observer-cleanup']).installer_phase
    cap = dict.fromkeys(bridge._CAP_FIELDS)
    cap.update(operation='uninstall', transaction_id='original', package={'package_sha256': 'a' * 64})
    if invalid:
        cap[invalid] = True
    calls = []
    client = SimpleNamespace(phase=phase, capability=cap, checkpoint=lambda: None,
                             request=lambda *response: calls.append(response))
    monkeypatch.setattr(bridge, '_request_data', lambda paths, cap: {'package_path': 'pinned.msi'})
    expected = object()
    monkeypatch.setattr(msi_inventory, 'read_expected_package', lambda path, release: expected)

    def cleanup(paths, transaction, release, inventory):
        assert transaction == cap['transaction_id'] and inventory is expected
        calls.append('cleanup')
        return {'observer_cleanup': 'incomplete', 'support_cleanup': 'incomplete'}

    monkeypatch.setattr(observer_cleanup_retry, 'retry_observer_cleanup', cleanup)
    if invalid:
        with pytest.raises(ValueError, match='OWNER_AUTH_FAILED'):
            bridge.execute_authorized_phase(client, None)
        assert calls == []
    else:
        result = bridge.execute_authorized_phase(client, None)
        assert result == {'result': 'observer-cleanup-retried', 'transaction_id': 'original',
                          'observer_cleanup': 'incomplete', 'support_cleanup': 'incomplete'}
        assert calls == ['cleanup', ('complete', result)]


@pytest.mark.parametrize('retry', ['support-incomplete'], indirect=True)
@pytest.mark.parametrize('live_support_absent', [False, True])
def test_retry_rechecks_original_incomplete_support(retry, monkeypatch, live_support_absent):
    from pc_agent.platform.windows import msi_inventory, observer_cleanup_retry

    paths, transaction, package, archive, completed, payload, calls = retry
    expected = SimpleNamespace(foundation_schema=3,
                               package=SimpleNamespace(package_code=completed['package']['package_code']))
    support_receipt = archive / 'support-cleanup.json'
    original = {key: value for key, value in payload.items() if key != 'observer_cleanup'}
    original['support_cleanup'] = 'incomplete'
    support_receipt.write_text(json.dumps(original))

    def verify_support(_expected, _install_root, *, native):
        assert _expected is expected and _install_root == paths.install_root
        calls.append('support-read-only')
        if not live_support_absent:
            raise ValueError('SUPPORT_CLEANUP_INCOMPLETE')

    monkeypatch.setattr(msi_inventory, 'verify_support_uninstalled', verify_support)
    result = observer_cleanup_retry.retry_observer_cleanup(paths, transaction, package, expected)
    assert result == {'observer_cleanup': 'removed',
                      'support_cleanup': 'complete' if live_support_absent else 'incomplete'}
    assert calls == ['absence', 'support-read-only', 'retire', ('receipt', 'removed')]
    assert json.loads(support_receipt.read_text()) == original
    assert json.loads((archive / 'completed.json').read_text()) == completed



@pytest.mark.parametrize('retry', ['support-incomplete'], indirect=True)
@pytest.mark.parametrize('defect', ['missing', 'wrong-id', 'wrong-package', 'wrong-state'])
def test_retry_refuses_unbound_support_receipt(retry, monkeypatch, defect):
    from pc_agent.platform.windows import msi_inventory, observer_cleanup_retry

    paths, transaction, package, archive, completed, payload, calls = retry
    expected = SimpleNamespace(foundation_schema=3,
                               package=SimpleNamespace(package_code=completed['package']['package_code']))
    if defect != 'missing':
        original = {key: value for key, value in payload.items() if key != 'observer_cleanup'}
        original['support_cleanup'] = 'incomplete'
        if defect == 'wrong-id':
            original['transaction_id'] = '12345678-1234-4234-8234-123456789def'
        if defect == 'wrong-package':
            original['package_sha256'] = 'b' * 64
        if defect == 'wrong-state':
            original['support_cleanup'] = 'complete'
        (archive / 'support-cleanup.json').write_text(json.dumps(original))

    monkeypatch.setattr(msi_inventory, 'verify_support_uninstalled',
                        lambda *args, **kwargs: pytest.fail('Support checked without bound evidence'))
    with pytest.raises(ValueError, match='PROVENANCE_CONFLICT'):
        observer_cleanup_retry.retry_observer_cleanup(paths, transaction, package, expected)
    assert calls == []
    assert json.loads((archive / 'observer-cleanup.json').read_text()) == payload


def test_retry_legacy_fact_without_support_receipt_uses_read_only_proof(retry, monkeypatch):
    from pc_agent.platform.windows import msi_inventory, observer_cleanup_retry

    paths, transaction, package, archive, completed, payload, calls = retry
    expected = SimpleNamespace(foundation_schema=3,
                               package=SimpleNamespace(package_code=completed['package']['package_code']))

    def verify_support(*args, **kwargs):
        calls.append('support-read-only')
        raise ValueError('SUPPORT_CLEANUP_INCOMPLETE')

    monkeypatch.setattr(msi_inventory, 'verify_support_uninstalled', verify_support)
    assert observer_cleanup_retry.retry_observer_cleanup(paths, transaction, package, expected) == {
        'observer_cleanup': 'removed', 'support_cleanup': 'incomplete'}
    assert calls == ['absence', 'support-read-only', 'retire', ('receipt', 'removed')]
    assert not (archive / 'support-cleanup.json').exists()
