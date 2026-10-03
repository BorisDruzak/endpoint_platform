"""Fixed offline entry cannot run workers through arbitrary CLI paths."""
import pytest


def test_entry_dispatches_only_fixed_scm_mode(monkeypatch):
    from pc_agent.platform.windows import updater_entry
    calls = []
    monkeypatch.setattr(updater_entry, 'run_windows_updater_service', lambda: calls.append('SCM') or 0)
    assert updater_entry.main(['--updater-service']) == 0
    assert calls == ['SCM']


@pytest.mark.parametrize('args', [[], ['--run-once'], ['--updater-service', '--path', 'other']])
def test_entry_rejects_unsafe_worker_invocations(args, monkeypatch):
    from pc_agent.platform.windows import updater_entry
    monkeypatch.setattr(updater_entry, 'run_windows_updater_service', lambda: pytest.fail('SCM called'))
    with pytest.raises(ValueError, match='fixed'):
        updater_entry.main(args)


def test_harmless_packaged_self_check_never_runs_worker(monkeypatch):
    from pc_agent.platform.windows import updater_entry
    monkeypatch.setattr(updater_entry, 'run_windows_updater_service', lambda: pytest.fail('SCM called'))
    assert updater_entry.main(['--verify-offline']) == 0


def test_msi_owned_runtime_validation_does_not_import_excluded_agent_launcher(tmp_path, monkeypatch):
    import json
    import sys
    from pc_agent.platform.windows.selector_migration import _is_msi_owned_runtime
    from pc_agent.platform.windows.update_paths import WindowsUpdatePaths
    paths = WindowsUpdatePaths(tmp_path / 'install', tmp_path / 'updates' / 'pending_update.json')
    runtime = paths.versions_root / '3.2.81'
    runtime.mkdir(parents=True)
    (runtime / 'pc_agent.exe').write_bytes(b'unchanged MSI-owned bytes')
    (runtime / '.endpoint-msi-runtime.json').write_text(json.dumps({
        'schema_version': 1, 'version': '3.2.81',
        'component_guid': '421BA1C1-4612-49F6-B504-74E62922EDD9'}), encoding='utf-8')
    monkeypatch.setitem(sys.modules, 'pc_agent.platform.windows.service_launcher', None)
    assert _is_msi_owned_runtime(paths, '3.2.81') is True
