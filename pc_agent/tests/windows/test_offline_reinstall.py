"""Restore Support only after the exact reinstall events are acknowledged."""
from contextlib import nullcontext
from uuid import uuid4

import pytest


def test_setup_arms_retry_when_events_are_pending(monkeypatch, tmp_path):
    from pc_agent.platform.windows import installation_notification, offline_reinstall, provision, setup_entry

    calls = []
    monkeypatch.setattr(installation_notification, 'sync_enrolled_installation', lambda _: 'pending')
    monkeypatch.setattr(offline_reinstall, 'schedule_retry', lambda root: calls.append(root))
    monkeypatch.setattr(provision, 'install_enrolled_support', lambda _: pytest.fail('Support before ACK'))
    monkeypatch.setattr(setup_entry, '_write_support_install_result', lambda *args: None)

    setup_entry._install_support_after_native(tmp_path)

    assert calls == [tmp_path]


@pytest.mark.parametrize('case', ['offline', 'unacknowledged', 'complete', 'obsolete', 'superseded', 'activation-fails'])
def test_resume_requires_current_reinstall_and_durable_ack(monkeypatch, tmp_path, case):
    from pc_agent.platform.windows import offline_reinstall as retry

    event_id = str(uuid4())
    calls = []
    fact = {'ack': object() if case in {'complete', 'activation-fails'} else None}
    folder = type('Folder', (), {'DeleteTask': lambda _, name, flags: calls.append('retire')})()
    monkeypatch.setattr(retry, 'update_transaction', lambda *args, **kw: nullcontext())
    monkeypatch.setattr(retry.WindowsUpdatePaths, 'production', classmethod(lambda cls: type('Paths', (), {'pending_path': tmp_path/'data/updates/pending.json'})()))
    monkeypatch.setattr(retry, '_running_setup', lambda _: tmp_path / 'EndpointAgentSetup.exe')
    monkeypatch.setattr(retry, '_folder', lambda: folder)
    monkeypatch.setattr(retry, '_get_task', lambda *args: True)
    def authorize(*_):
        if case == 'obsolete' or (case == 'superseded' and 'send' in calls):
            return None
        return fact

    monkeypatch.setattr(retry, '_authorized_fact', authorize)
    monkeypatch.setattr(retry, '_verify_release', lambda *args: calls.append('MSI verified'))
    monkeypatch.setattr(retry, 'bounded_delivery',
                        lambda: calls.append('send') or ('pending' if case == 'offline' else 'delivered'))
    def activate(root):
        assert root == tmp_path/'data'
        calls.append('activate')
        return case != 'activation-fails'

    result = retry.resume(event_id, activate)

    if case == 'complete':
        assert result == 0 and calls == ['send', 'MSI verified', 'activate', 'retire']
    elif case == 'obsolete':
        assert result == 0 and calls == ['retire']
    elif case == 'superseded':
        assert result == 0 and calls == ['send', 'retire']
    elif case == 'activation-fails':
        assert result == 75 and calls == ['send', 'MSI verified', 'activate']
    else:
        assert result == 75 and calls == ['send']


def test_reinstall_pair_uses_latest_events_for_current_identity(monkeypatch, tmp_path):
    from pc_agent.platform.windows import offline_reinstall as retry

    device, other = str(uuid4()), str(uuid4())
    paths = type('Paths', (), {'pending_path': tmp_path / 'data/updates/pending.json'})()
    removed = {'action': 'removed', 'device_id': device, 'cleanup': {'support': 'complete'}}
    installed = {'action': 'installed', 'device_id': device, 'event': {'event_id': str(uuid4())}}
    facts = [removed, installed, {'action': 'removed', 'device_id': other}]
    monkeypatch.setattr(retry, '_identity', lambda _: device)
    monkeypatch.setattr(retry, 'outbox_for', lambda _: type('Box', (), {
        '_load': lambda self: (None, {'facts': facts})})())

    assert retry._current_reinstall(paths) is installed
    facts.append({**installed, 'event': {'event_id': str(uuid4())}})
    assert retry._current_reinstall(paths) is None



@pytest.mark.parametrize('defect', [None, 'wrong-bytes', 'other-package'])
def test_schedule_authenticates_the_cached_setup_for_the_installed_fact(monkeypatch, tmp_path, defect):
    from types import SimpleNamespace
    from pc_agent.platform.windows import offline_reinstall as retry

    program = tmp_path / 'Endpoint Platform'
    paths = SimpleNamespace(install_root=program / 'Agent',
                            pending_path=tmp_path / 'data/updates/pending.json')
    package = {'msi_sha256': 'a'*64, 'product_code': '{B00DB00D-1111-1111-1111-111111111111}',
               'source_revision': 'b'*40, 'version': '3.2.224'}
    release = {**package, 'package_sha256': package['msi_sha256']}
    fact = {'native': package, 'event': {'event_id': str(uuid4())}}
    current = tmp_path / 'launch.exe'
    cached = retry._cached_setup(paths, fact)
    cached.parent.mkdir(parents=True)
    current.write_bytes(b'authenticated Setup')
    cached.write_bytes(b'other Setup' if defect == 'wrong-bytes' else current.read_bytes())
    if defect == 'other-package':
        release['package_sha256'] = 'c'*64
    monkeypatch.setattr(retry.sys, 'frozen', True, raising=False)
    monkeypatch.setattr(retry.sys, 'executable', str(current))
    monkeypatch.setattr(retry.WindowsUpdatePaths, 'production', classmethod(lambda cls: paths))
    monkeypatch.setattr(retry, 'update_transaction', lambda *args, **kw: nullcontext())
    monkeypatch.setattr(retry, '_current_reinstall', lambda _: fact)
    monkeypatch.setattr(retry, 'verified_foundation_release', lambda _: release)
    monkeypatch.setattr(retry.installer_fence, 'assert_state_security', lambda *args, **kw: None)
    monkeypatch.setattr(retry.durable_state, '_pinned_copy_source', lambda _: nullcontext())
    tasks = []
    monkeypatch.setattr(retry, '_register', lambda *args: tasks.append(args))

    if defect is None:
        retry.schedule_retry(tmp_path / 'data')
        assert tasks == [(fact['event']['event_id'], cached)]
    else:
        with pytest.raises(ValueError, match='INSTALLATION_RETRY_.*_CONFLICT'):
            retry.schedule_retry(tmp_path / 'data')
        assert tasks == []


def test_private_resume_mode_never_enters_native_setup(monkeypatch):
    from pc_agent.platform.windows import offline_reinstall, setup_entry

    event_id = str(uuid4())
    monkeypatch.setattr(setup_entry, '_install_embedded_msi', lambda *args: pytest.fail('MSI replay'))
    monkeypatch.setattr(offline_reinstall, 'resume', lambda event, activate: 75
                        if event == event_id and activate is setup_entry._activate_enrolled_support else 67)
    assert setup_entry.main([offline_reinstall.MODE, event_id]) == 75


def test_setup_arms_retry_when_support_fails_after_ack(monkeypatch, tmp_path):
    from pc_agent.platform.windows import installation_notification, offline_reinstall, setup_entry

    calls = []
    monkeypatch.setattr(installation_notification, 'sync_enrolled_installation', lambda _: 'delivered')
    monkeypatch.setattr(setup_entry, '_activate_enrolled_support',
                        lambda root: calls.append(('activate', root)) or False)
    monkeypatch.setattr(offline_reinstall, 'schedule_retry', lambda root: calls.append(('schedule', root)))

    setup_entry._install_support_after_native(tmp_path)

    assert calls == [('activate', tmp_path), ('schedule', tmp_path)]


def test_missing_task_from_windows_scheduler_allows_initial_registration(tmp_path):
    from pc_agent.platform.windows import offline_reinstall

    pytest.importorskip('win32com.client')
    event_id = str(uuid4())
    folder = offline_reinstall._folder()
    assert offline_reinstall._get_task(folder, event_id, tmp_path / 'EndpointAgentSetup.exe') is None
