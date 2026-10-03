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
