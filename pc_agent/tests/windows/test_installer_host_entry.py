"""The installer executable must not import or expose online service roles."""
import contextlib
import subprocess
import sys

import pytest


def test_installer_import_does_not_load_service_or_online_runtime():
    code = """
import sys
from pc_agent.platform.windows import installer_host_entry
assert 'pc_agent.platform.windows.service_launcher' not in sys.modules
assert 'pc_agent.endpoint_gateway' not in sys.modules
assert 'pc_agent.gateway_update_runtime' not in sys.modules
"""
    subprocess.run([sys.executable, '-c', code], check=True)


@pytest.mark.parametrize('option', ['--agent-service', '--updater-service'])
def test_installer_host_rejects_service_modes(option):
    from pc_agent.platform.windows import installer_host_entry as entry
    with pytest.raises(SystemExit) as error:
        entry.main([option])
    assert error.value.code == 2


def test_installer_keeps_owner_scope_and_all_native_inputs(monkeypatch, tmp_path):
    from pc_agent.platform.windows import installer_host_entry as entry
    from pc_agent.platform.windows import installer_transaction_bridge as bridge
    from pc_agent.platform.windows import installer_phase_diagnostics as diagnostics
    from pc_agent.platform.windows import msi_inventory
    calls = []
    client = type('Client', (), {'capability': {'exact': 'fixture'}})()
    paths = entry.WindowsUpdatePaths(tmp_path / 'Agent', tmp_path / 'updates/pending.json')
    monkeypatch.setattr(entry.WindowsUpdatePaths, 'production', classmethod(lambda _: paths))

    @contextlib.contextmanager
    def owner(session, phase):
        calls.append(('owner-enter', session, phase))
        yield client
        calls.append(('owner-exit',))

    monkeypatch.setattr(bridge, 'owner_authorized_phase', owner)
    monkeypatch.setattr(msi_inventory, 'immutable_installer_media_roots', lambda *_: ())
    monkeypatch.setattr(msi_inventory, 'package_read_scope', lambda **_: contextlib.nullcontext())
    monkeypatch.setattr(diagnostics, 'profile_installer_phase', lambda *_: contextlib.nullcontext())
    monkeypatch.setattr(bridge, 'execute_authorized_phase',
                        lambda actual, paths, **kw: calls.append(('execute', actual is client, kw)))
    assert entry.main(['--installer-phase', 'msi-preflight', '--installer-session', 'session',
                       '--foundation-state', '3', '--foundation-action', '2',
                       '--runtime-state', '3', '--runtime-action', '4',
                       '--rollback-disabled', '0', '--uninstall-finalization', '1',
                       '--staged-removal', '1', '--upgrade-detected', 'product']) == 0
    assert calls == [('owner-enter', 'session', 'msi-preflight'),
                     ('execute', True, {'feature_states': (3, 2, 3, 4), 'rollback_disabled': '0',
                                       'uninstall_finalization': '1', 'upgrade_detected': 'product',
                                       'staged_removal': '1'}), ('owner-exit',)]
