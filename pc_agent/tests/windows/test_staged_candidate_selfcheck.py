"""Exercise an unselected candidate without starting its device lifecycle."""
import os
import subprocess

import pytest

from pc_agent.platform.windows import durable_state, staged_candidate_payload as module
from pc_agent.tests.windows.test_staged_candidate_payload import candidate, prepare
from pc_agent.tests.windows.test_staged_update_state import staged
from pc_agent.tests.windows.test_installer_fence import native_protected_root


def published(candidate):
    _, paths, record, expected, _ = candidate
    prepare(candidate)
    with durable_state.installer_mutation_checkpoints(lambda: None):
        target = module.publish_candidate_payload(paths, record, expected)
    return paths, record, expected, target


class Child:
    def __init__(self, output, value, *, running=False):
        output.write(value)
        output.flush()
        self.returncode = None if running else 0
        self.killed = False
        self.waited = False

    def poll(self):
        return self.returncode

    def kill(self):
        self.killed = True
        self.returncode = 1

    def wait(self, timeout=None):
        self.waited = True
        return self.returncode


def test_check_uses_only_fixed_version_mode_and_preserves_selection(candidate, monkeypatch):
    paths, record, expected, target = published(candidate)
    before = paths.current_path.read_bytes()
    calls = []

    def start(command, **options):
        assert command == [str(target / 'pc_agent.exe'), '--print-version']
        assert options['cwd'] == str(target)
        assert options['stdin'] == subprocess.DEVNULL
        assert options['stderr'] == subprocess.STDOUT
        assert options['shell'] is False and options['close_fds'] is True
        calls.append(Child(options['stdout'], (expected.identity.version + '\r\n').encode()))
        return calls[-1]

    monkeypatch.setattr(subprocess, 'Popen', start)
    with durable_state.installer_mutation_checkpoints(lambda: None):
        assert module.check_candidate_executable(paths, record, expected) is True
    assert len(calls) == 1 and calls[0].waited and not calls[0].killed
    assert paths.current_path.read_bytes() == before
    assert not (target / '.endpoint-msi-runtime.json').exists()
    assert module.state.read_staged_update(paths).phase == 'preparing'


@pytest.mark.parametrize('value', [b'3.2.999\n', b'3.2.122\nPRIVATE-ERROR', b'x' * 4097], ids=['wrong-version', 'stderr', 'overflow'])
def test_bad_or_excess_output_fails_without_logging_it(candidate, monkeypatch, capsys, value):
    paths, record, expected, _ = published(candidate)
    children = []

    def start(_command, **options):
        children.append(Child(options['stdout'], value, running=len(value) > 4096))
        return children[-1]

    monkeypatch.setattr(subprocess, 'Popen', start)
    before = paths.current_path.read_bytes()
    with durable_state.installer_mutation_checkpoints(lambda: None), pytest.raises(ValueError, match='^PROVENANCE_CONFLICT$'):
        module.check_candidate_executable(paths, record, expected)
    assert paths.current_path.read_bytes() == before
    captured = capsys.readouterr()
    assert not captured.out and not captured.err
    if len(value) > 4096:
        assert children[0].killed and children[0].waited


@pytest.mark.parametrize('reason', ['timeout', 'owner-loss'])
def test_failure_reaps_only_the_exact_owned_child(candidate, monkeypatch, reason):
    paths, record, expected, _ = published(candidate)
    children = []

    def start(_command, **options):
        children.append(Child(options['stdout'], b'', running=True))
        return children[-1]

    monkeypatch.setattr(subprocess, 'Popen', start)
    if reason == 'timeout':
        from itertools import count
        ticks = count(step=61)
        monkeypatch.setattr(module.time, 'monotonic', lambda: next(ticks))

    def checkpoint():
        if children and reason == 'owner-loss':
            raise ValueError('OWNER_AUTH_FAILED')

    with durable_state.installer_mutation_checkpoints(checkpoint), pytest.raises(ValueError):
        module.check_candidate_executable(paths, record, expected)
    assert len(children) == 1 and children[0].killed and children[0].waited


@pytest.mark.parametrize('defect', ['hash', 'extra-file', 'selected'])
def test_changed_or_selected_candidate_is_never_executed(candidate, monkeypatch, defect):
    paths, record, expected, target = published(candidate)
    if defect == 'hash':
        (target / 'pc_agent.exe').write_bytes(b'changed')
    elif defect == 'extra-file':
        (target / 'foreign.txt').write_bytes(b'foreign')
    else:
        paths.current_path.write_bytes(b'{"version":"3.2.122"}')
    monkeypatch.setattr(subprocess, 'Popen', lambda *_a, **_k: pytest.fail('unverified candidate executed'))
    with durable_state.installer_mutation_checkpoints(lambda: None), pytest.raises(ValueError):
        module.check_candidate_executable(paths, record, expected)


def test_no_execution_without_live_mutation_scope(candidate, monkeypatch):
    paths, record, expected, _ = published(candidate)
    monkeypatch.setattr(subprocess, 'Popen', lambda *_a, **_k: pytest.fail('unscoped launch'))
    with pytest.raises(ValueError, match='installer mutation scope is absent'):
        module.check_candidate_executable(paths, record, expected)


def test_process_creation_time_counts_toward_deadline(candidate, monkeypatch):
    paths, record, expected, _ = published(candidate)
    ticks = iter([0, 61])
    monkeypatch.setattr(module.time, 'monotonic', lambda: next(ticks))
    monkeypatch.setattr(subprocess, 'Popen', lambda _command, **options:
                        Child(options['stdout'], (expected.identity.version + '\n').encode()))
    with durable_state.installer_mutation_checkpoints(lambda: None), pytest.raises(ValueError):
        module.check_candidate_executable(paths, record, expected)


def test_historical_wrapper_without_candidate_does_not_execute(candidate, monkeypatch):
    _, paths, record, expected, _ = candidate
    monkeypatch.setattr(subprocess, 'Popen', lambda *_a, **_k: pytest.fail('historical launch'))
    with durable_state.installer_mutation_checkpoints(lambda: None):
        assert module.check_candidate_executable(paths, record, expected) is None


@pytest.mark.skipif(os.name != 'nt', reason='native deny-write/delete pins')
def test_every_candidate_file_remains_pinned_until_child_exits(candidate, monkeypatch):
    paths, record, expected, target = published(candidate)

    def start(_command, **options):
        for item in expected.identity.files:
            with pytest.raises(PermissionError):
                (target / item.path).write_bytes(b'blocked')
        return Child(options['stdout'], (expected.identity.version + '\n').encode())

    monkeypatch.setattr(subprocess, 'Popen', start)
    with durable_state.installer_mutation_checkpoints(lambda: None):
        module.check_candidate_executable(paths, record, expected)


@pytest.mark.skipif(os.name != 'nt', reason='fresh native ACL check under byte pins')
def test_acl_changes_are_rejected_after_child_exit(candidate, monkeypatch):
    import win32security
    from pc_agent.platform.windows import installer_fence
    paths, record, expected, target = published(candidate)
    leaf = target / 'pc_agent.exe'

    def start(_command, **options):
        descriptor = win32security.GetNamedSecurityInfo(str(leaf), 1, 4)
        dacl = descriptor.GetSecurityDescriptorDacl()
        dacl.AddAccessAllowedAce(win32security.ACL_REVISION, 0x40000000,
                                win32security.CreateWellKnownSid(win32security.WinWorldSid, None))
        win32security.SetNamedSecurityInfo(str(leaf), 1, 4, None, None, dacl, None)
        return Child(options['stdout'], (expected.identity.version + '\n').encode())

    monkeypatch.setattr(subprocess, 'Popen', start)
    try:
        with durable_state.installer_mutation_checkpoints(lambda: None), pytest.raises(ValueError):
            module.check_candidate_executable(paths, record, expected)
    finally:
        installer_fence.protect_state(leaf)
