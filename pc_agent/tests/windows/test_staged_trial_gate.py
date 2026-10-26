"""Native kernel authority and lifetime checks, without installing an agent."""
import os
import threading
import subprocess
import sys
import ctypes
import hashlib
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

from pc_agent.platform.windows import staged_trial_gate as gate

pytestmark = pytest.mark.skipif(os.name != 'nt', reason='requires Windows kernel objects')


@pytest.fixture
def request_value():
    return {'operation_id': str(uuid4()), 'attempt_id': str(uuid4()),
            'binding_sha256': 'a' * 64, 'created_ns': 1}


@pytest.fixture
def native_gate(request_value):
    value = gate._new_gate(request_value)
    yield value
    # Tests deliberately poison their own unique objects; clean them up here.
    for poisoned in list(gate._POISONED):
        if poisoned.mutex == value.mutex or getattr(poisoned, 'names', None) == getattr(value, 'names', None):
            poisoned.api.kernel.ReleaseMutex(poisoned.mutex)
            poisoned.poisoned = False
            poisoned.close()
            gate._POISONED.remove(poisoned)
            gate._POISONED_NAMES.discard(poisoned.names)
    value.close()


def test_gate_is_reset_and_shared_manual_event(native_gate, request_value):
    other = gate.open_gate(request_value)
    try:
        with native_gate.locked():
            assert not native_gate.ready()
            native_gate.publish()
        with other.locked():
            assert other.ready()
            assert other.ready()  # Manual reset: observation never consumes it.
            other.reset()
        with native_gate.locked(): assert not native_gate.ready()
    finally:
        other.close()


def test_even_correctly_secured_precreated_gate_is_rejected(native_gate, request_value):
    with pytest.raises(gate.GateUnavailable, match='preexisting'):
        gate._new_gate(request_value)


def test_missing_gate_has_no_file_fallback(request_value):
    with pytest.raises(FileNotFoundError): gate.open_gate(request_value)


def test_precreated_default_dacl_cannot_be_adopted(request_value):
    import win32event
    mutex = win32event.CreateMutex(None, False, gate._names(request_value)[0])
    try:
        with pytest.raises(gate.GateUnavailable): gate.open_gate(request_value)
    finally:
        mutex.Close()


def test_writer_waits_until_acceptance_lock_is_released(native_gate, request_value):
    started, reset, failures = threading.Event(), threading.Event(), []
    def writer():
        other = gate.open_gate(request_value)
        try:
            started.set()
            with other.locked(timeout_ms=0xFFFFFFFF):
                other.reset()
                reset.set()
        except BaseException as error: failures.append(error)
        finally: other.close()
    with native_gate.locked():
        native_gate.publish()
        worker = threading.Thread(target=writer)
        worker.start()
        assert started.wait(2)
        assert not reset.wait(.05)
        assert native_gate.ready()
    worker.join(2)
    assert not worker.is_alive()
    assert not failures
    assert reset.is_set()
    assert not native_gate.ready()


def test_bounded_reader_contention_is_retryable_and_does_not_poison(native_gate, request_value):
    held, release, failures = threading.Event(), threading.Event(), []
    def publication():
        try:
            with native_gate.locked():
                native_gate.publish()
                held.set()
                assert release.wait(3)
        except BaseException as error: failures.append(error)
    worker = threading.Thread(target=publication)
    worker.start()
    assert held.wait(2)
    other = gate.open_gate(request_value)
    try:
        with pytest.raises(gate.GateBusy):
            with other.locked(timeout_ms=10): pytest.fail('contended snapshot exposed')
        assert not other.poisoned
        release.set(); worker.join(2)
        assert not failures
        with other.locked(): assert other.ready()
    finally:
        release.set(); worker.join(2)
        other.close()


def test_abandoned_mutex_permanently_withholds_ready(native_gate, request_value):
    retained = []
    def abandoned_writer():
        other = gate.open_gate(request_value)
        retained.append(other)
        assert other.api.kernel.WaitForSingleObject(other.mutex, 1000) == 0
        other.publish()
        # Thread exits with ownership. Keep the handle so this is abandonment,
        # not disappearance/recreation of the named object.
    worker = threading.Thread(target=abandoned_writer)
    worker.start(); worker.join(2)
    try:
        with pytest.raises(gate.GateUnavailable, match='abandoned'):
            with native_gate.locked(): pytest.fail('abandoned proof accepted')
        assert not native_gate.ready()
        reopened = gate.open_gate(request_value)
        try:
            with pytest.raises(gate.GateUnavailable):
                with reopened.locked(timeout_ms=0): pytest.fail('poison was lost')
        finally: reopened.close()
    finally:
        for value in retained: value.close()


def test_reset_failure_cannot_release_previous_ready(native_gate, request_value, monkeypatch):
    with native_gate.locked(): native_gate.publish()
    original = native_gate.api.checked
    def failed(name, *args):
        if name == 'ResetEvent': raise OSError('simulated kernel failure')
        return original(name, *args)
    monkeypatch.setattr(native_gate.api, 'checked', failed)
    with pytest.raises(OSError):
        with native_gate.locked(): native_gate.reset()
    assert native_gate.poisoned
    reopened = gate.open_gate(request_value)
    try:
        with pytest.raises(gate.GateUnavailable):
            with reopened.locked(timeout_ms=0): pytest.fail('old signalled proof escaped poison')
    finally: reopened.close()


def test_process_creation_and_image_query_match_retained_identity():
    from pc_agent.platform.windows.installer_transaction_bridge import NativeIdentity
    identity = NativeIdentity(os.getpid())
    try:
        assert gate.process_created() == identity.value['created']
        # A Windows venv redirector can differ from the OS process image.
        image = Path(gate._process_path(identity.process))
        assert image.is_file()
        assert hashlib.sha256(image.read_bytes()).hexdigest() == identity.value['hash']
    finally: identity.close()


@pytest.mark.parametrize('defect', ['owner', 'unprotected', 'extra', 'duplicate', 'service_full', 'inherited'])
def test_exact_owner_and_dacl_are_required(native_gate, monkeypatch, defect):
    import win32security as security
    rights = list(gate._rights('event').items())
    if defect == 'extra': rights.append(('S-1-5-11', 0x100000))
    if defect == 'duplicate': rights.append(rights[-1])
    if defect == 'service_full': rights = [(sid, 0x1F0003 if sid == gate.SERVICE_SID else mask) for sid, mask in rights]
    sddl = ('O:LS' if defect == 'owner' else 'O:BA') + ('D:' if defect == 'unprotected' else 'D:P')
    sddl += ''.join(f'(A;{"CI" if defect == "inherited" else ""};0x{mask:x};;;{sid})' for sid, mask in rights)
    descriptor = security.ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, 1)
    monkeypatch.setattr(security, 'GetSecurityInfo', lambda *_: descriptor)
    with pytest.raises(gate.GateUnavailable): gate._validate(native_gate.event, 'event')


def test_authenticated_owner_retains_only_zero_access_noninherited_handles(request_value, monkeypatch):
    from ctypes import wintypes
    from pc_agent.platform.windows.installer_transaction_bridge import NativeIdentity
    identity = NativeIdentity(os.getpid())
    copied = []
    checked = gate._Api.checked
    def recording(self, name, *args):
        result = checked(self, name, *args)
        if name == 'DuplicateHandle' and args[-1] == 0:
            assert args[4:6] == (0, False)
            copied.append(ctypes.cast(args[3], ctypes.POINTER(wintypes.HANDLE)).contents.value)
        return result
    monkeypatch.setattr(gate._Api, 'checked', recording)
    try:
        gate.create_trial_gate(request_value, identity.value)
        assert len(copied) == 2
        api = gate._Api()
        for handle in copied:
            assert api.kernel.WaitForSingleObject(handle, 0) == 0xFFFFFFFF  # No SYNCHRONIZE right.
            import win32api
            assert win32api.GetHandleInformation(handle) & 1 == 0
        boundary = gate.open_gate(request_value)
        try:
            with boundary.locked(): assert not boundary.ready()
        finally: boundary.close()
    finally:
        for handle in copied: gate._Api().kernel.CloseHandle(handle)
        identity.close()
    with pytest.raises(FileNotFoundError): gate.open_gate(request_value)


def test_gate_lifetime_survives_helper_until_authenticated_owner_exits(request_value):
    from pc_agent.platform.windows.installer_transaction_bridge import NativeIdentity
    owner = subprocess.Popen([sys.executable, '-c', 'import sys; sys.stdin.buffer.read(1)'],
                             stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    identity = None
    try:
        identity = NativeIdentity(owner.pid)
        gate.create_trial_gate(request_value, identity.value)
        # All create/helper handles have closed; only the other process's
        # zero-access keepalives retain these exact named objects.
        boundary = gate.open_gate(request_value)
        try:
            with boundary.locked(): assert not boundary.ready()
        finally: boundary.close()
        owner.stdin.write(b'x'); owner.stdin.flush()
        assert owner.wait(timeout=5) == 0
        with pytest.raises(FileNotFoundError): gate.open_gate(request_value)
    finally:
        if owner.poll() is None:
            owner.terminate(); owner.wait(timeout=5)
        owner.stdin.close()
        if identity is not None: identity.close()


def test_pid_reuse_of_authenticated_owner_is_rejected_before_creation(request_value):
    from pc_agent.platform.windows.installer_transaction_bridge import NativeIdentity
    identity = NativeIdentity(os.getpid())
    try:
        stale = {**identity.value, 'created': identity.value['created'] + 1}
        with pytest.raises(gate.GateUnavailable, match='identity changed'):
            gate.create_trial_gate(request_value, stale)
    finally: identity.close()
    with pytest.raises(FileNotFoundError): gate.open_gate(request_value)


def test_partial_handle_transfer_removes_objects_and_copies(request_value, monkeypatch):
    from pc_agent.platform.windows.installer_transaction_bridge import NativeIdentity
    identity = NativeIdentity(os.getpid())
    checked, count = gate._Api.checked, []
    def failed(self, name, *args):
        if name == 'DuplicateHandle':
            count.append(name)
            if len(count) == 2: raise OSError('second handle transfer failed')
        return checked(self, name, *args)
    monkeypatch.setattr(gate._Api, 'checked', failed)
    try:
        with pytest.raises(OSError, match='second handle'): gate.create_trial_gate(request_value, identity.value)
    finally: identity.close()
    with pytest.raises(FileNotFoundError): gate.open_gate(request_value)


def test_retained_candidate_accepts_nonelevated_localservice_token(monkeypatch):
    """Real process/image handles with the non-elevated service token model."""
    import win32security as security
    original = security.GetTokenInformation
    def service_token(token, kind):
        if kind == security.TokenUser: return security.ConvertStringSidToSid('S-1-5-19'), 0
        if kind == security.TokenGroups: return [(security.ConvertStringSidToSid(gate.SERVICE_SID), 4)]
        if kind == security.TokenElevation: return False
        return original(token, kind)
    monkeypatch.setattr(security, 'GetTokenInformation', service_token)
    identity = gate._CandidateProcess(os.getpid())
    try:
        assert identity.value['sid'] == 'S-1-5-19'
        assert identity.value['created'] == gate.process_created()
        assert hashlib.sha256(identity.image_path.read_bytes()).hexdigest() == identity.value['hash']
        identity.assert_alive()
    finally: identity.close()


@pytest.mark.parametrize('defect', ['account', 'missing_service', 'disabled_service', 'deny_only_service'])
def test_retained_candidate_rejects_other_token_authority(monkeypatch, defect):
    import win32security as security
    original = security.GetTokenInformation
    def token_value(token, kind):
        if kind == security.TokenUser:
            return security.ConvertStringSidToSid('S-1-5-18' if defect == 'account' else 'S-1-5-19'), 0
        if kind == security.TokenGroups:
            return [] if defect == 'missing_service' else [(security.ConvertStringSidToSid(gate.SERVICE_SID),
                                                          0 if defect == 'disabled_service' else 4 | 16)]
        return original(token, kind)
    monkeypatch.setattr(security, 'GetTokenInformation', token_value)
    with pytest.raises(gate.GateUnavailable): gate._CandidateProcess(os.getpid())


@pytest.fixture
def candidate_source(tmp_path, monkeypatch):
    from pc_agent.platform.windows import installation_provenance as provenance
    paths = SimpleNamespace(versions_root=tmp_path)
    binding = SimpleNamespace(candidate_version='3.2.156', candidate_source_revision='a' * 40,
                              candidate_tree_sha256='b' * 64, new_release={'version': '3.2.156'})
    process = SimpleNamespace(value={'created': 123, 'hash': 'c' * 64},
                              image_path=tmp_path / '3.2.156' / 'pc_agent.exe', closed=False)
    def alive():
        if process.closed: raise gate.GateUnavailable('candidate exited')
    def close(): process.closed = True
    process.assert_alive, process.close = alive, close
    core = SimpleNamespace(version=binding.candidate_version, source_revision=binding.candidate_source_revision,
                           tree_sha256=binding.candidate_tree_sha256,
                           files=(SimpleNamespace(path='pc_agent.exe', sha256='c' * 64),))
    def inspected(given_paths, raw, selector, foundation):
        assert given_paths is paths
        assert selector == {'schema_version': 1, 'version': '3.2.156', 'source_revision': 'a' * 40}
        assert foundation == '3.2.156'
        return SimpleNamespace(identity=core)
    monkeypatch.setattr(gate, '_CandidateProcess', lambda _: process)
    monkeypatch.setattr(provenance, '_inspect_core_value', inspected)
    return paths, binding, process, core


def test_live_candidate_holds_exact_source_and_process_until_snapshot_finishes(candidate_source):
    paths, binding, process, _ = candidate_source
    with gate.live_candidate(paths, binding, 42, 123) as actual:
        assert actual is process
        assert not process.closed
    assert process.closed


@pytest.mark.parametrize('defect', ['creation', 'path', 'version', 'source', 'tree', 'image_hash', 'missing_image', 'dead'])
def test_live_candidate_rejects_pid_or_source_substitution(candidate_source, defect):
    paths, binding, process, core = candidate_source
    if defect == 'creation': process.value['created'] += 1
    elif defect == 'path': process.image_path = paths.versions_root / 'other' / 'pc_agent.exe'
    elif defect == 'version': core.version = '3.2.155'
    elif defect == 'source': core.source_revision = 'd' * 40
    elif defect == 'tree': core.tree_sha256 = 'd' * 64
    elif defect == 'image_hash': process.value['hash'] = 'd' * 64
    elif defect == 'missing_image': core.files = ()
    elif defect == 'dead': process.closed = True
    with pytest.raises(gate.GateUnavailable):
        with gate.live_candidate(paths, binding, 42, 123): pytest.fail('unbound source accepted')
    assert process.closed
