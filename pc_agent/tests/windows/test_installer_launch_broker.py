"""A warm launcher may only start fixed, independently authenticated phases."""
from copy import deepcopy
from types import SimpleNamespace
import os
import sys

import pytest

from pc_agent.platform.windows import installer_launch_broker as broker
from pc_agent.tests.windows.test_installer_fence import native_protected_root


SESSION = '11111111-1111-4111-8111-111111111111'
ORIGINAL = '22222222-2222-4222-8222-222222222222'


@pytest.fixture
def origin():
    return {'transaction_id': ORIGINAL, 'helper_sha256': 'a' * 64,
            'owner': {'pid': 12, 'created': 13, 'hash': 'b' * 64,
                      'sid': 'S-1-5-18', 'elevated': True}}


def test_launch_accepts_only_same_operation_owner_and_helper(origin):
    request = {'sequence': 1, 'action': 'launch', 'phase': 'prepare', 'session': SESSION}
    assert broker.validate_launch_request(request, 1, origin, lambda session: deepcopy(origin)) == ('prepare', SESSION)


@pytest.mark.parametrize('defect', ['sequence', 'unknown-key', 'native-phase', 'arguments', 'bad-session',
                                  'other-operation', 'other-owner', 'other-helper', 'bool-sequence'])
def test_forged_or_arbitrary_launch_is_denied(origin, defect):
    request = {'sequence': 1, 'action': 'launch', 'phase': 'prepare', 'session': SESSION}
    target = deepcopy(origin)
    if defect == 'sequence': request['sequence'] = 2
    elif defect == 'unknown-key': request['executable'] = 'untrusted.exe'
    elif defect == 'native-phase': request['phase'] = 'msi-enter'
    elif defect == 'arguments': request['phase'] = 'inspect --agent-service'
    elif defect == 'bad-session': request['session'] = '../outside'
    elif defect == 'other-operation': target['transaction_id'] = SESSION
    elif defect == 'other-owner': target['owner']['created'] += 1
    elif defect == 'other-helper': target['helper_sha256'] = '0' * 64
    elif defect == 'bool-sequence': request['sequence'] = True
    with pytest.raises(ValueError, match='OWNER_AUTH_FAILED'):
        broker.validate_launch_request(request, 1, origin, lambda session: target)


def test_close_is_bounded_and_does_not_read_capabilities(origin):
    def forbidden(_): pytest.fail('close read a capability')
    assert broker.validate_launch_request({'sequence': 1, 'action': 'close'}, 1, origin, forbidden) is None
    with pytest.raises(ValueError):
        broker.validate_launch_request({'sequence': 513, 'action': 'close'}, 513, origin, forbidden)
    with pytest.raises(ValueError):
        broker.validate_launch_request({'sequence': 512, 'action': 'launch', 'phase': 'inspect', 'session': SESSION},
                                       512, origin, lambda _: deepcopy(origin))


def test_child_uses_only_the_same_executable_and_fixed_arguments(monkeypatch):
    seen = []
    def start(*args, **kwargs):
        seen.append((args, kwargs));return SimpleNamespace(pid=123)
    monkeypatch.setattr(broker.subprocess, 'Popen', start)
    monkeypatch.setattr(sys, 'frozen', True, raising=False)
    assert broker.spawn_phase('prepare', SESSION).pid == 123
    args, options = seen[0]
    assert args == ([sys.executable, '--installer-phase', 'prepare', '--installer-session', SESSION],)
    assert options['shell'] is False and 'env' not in options
    assert options['creationflags'] & 0x08000000


def test_unfrozen_invocation_never_spawns(monkeypatch):
    monkeypatch.setattr(sys, 'frozen', False, raising=False)
    monkeypatch.setattr(broker.subprocess, 'Popen', lambda *_a, **_k: pytest.fail('unfrozen spawn'))
    with pytest.raises(ValueError): broker.spawn_phase('prepare', SESSION)


def test_owner_loss_after_receive_prevents_process_creation(origin, monkeypatch):
    alive = [True]
    class Owner:
        def assert_alive(self):
            if not alive[0]: raise ValueError('OWNER_AUTH_FAILED')
    class Transport:
        def send(self, _): pass
        def receive(self):
            alive[0] = False
            return {'sequence': 1, 'action': 'launch', 'phase': 'prepare', 'session': SESSION}
    monkeypatch.setattr(broker, 'spawn_phase', lambda *_: pytest.fail('lost owner spawned a child'))
    with pytest.raises(ValueError, match='OWNER_AUTH_FAILED'):
        broker.serve_launcher(origin, Owner(), Transport(), lambda _: deepcopy(origin))


def test_each_launch_returns_a_new_identity_and_close_waits_for_child(origin, monkeypatch):
    requests = iter([{'sequence': 1, 'action': 'launch', 'phase': 'prepare', 'session': SESSION},
                     {'sequence': 2, 'action': 'close'}])
    replies = []
    child = SimpleNamespace(pid=77, poll=lambda: 0)
    monkeypatch.setattr(broker, 'spawn_phase', lambda *_: child)
    class Identity:
        def __init__(self, pid):
            assert pid == 77
            self.value = {**origin['owner'], 'pid': pid, 'created': 99, 'hash': origin['helper_sha256']}
        def close(self): pass
    monkeypatch.setattr(broker, 'NativeIdentity', Identity)
    owner = SimpleNamespace(assert_alive=lambda: None)
    transport = SimpleNamespace(send=replies.append, receive=lambda: next(requests))
    assert broker.serve_launcher(origin, owner, transport, lambda _: deepcopy(origin)) == 0
    assert replies == [{'ready': True}, {'sequence': 1, 'pid': 77, 'created': 99},
                       {'sequence': 2, 'closed': True}]


def test_service_entry_routes_launcher_without_starting_a_service(monkeypatch):
    from pc_agent.platform.windows import service_launcher
    calls = []
    monkeypatch.setattr(broker, 'run_launch_broker', lambda *args: calls.append(args) or 0)
    assert service_launcher.main(['--installer-launcher', SESSION, '--installer-launch-nonce', 'a' * 32]) == 0
    assert calls == [(SESSION, 'a' * 32)]


def test_launcher_failure_is_bounded_without_windowed_traceback(monkeypatch):
    from pc_agent.platform.windows import service_launcher, installer_phase_diagnostics
    events = []
    def fail(*_): raise RuntimeError('not emitted into diagnostics')
    monkeypatch.setattr(broker, 'run_launch_broker', fail)
    monkeypatch.setattr(installer_phase_diagnostics, 'report_installer_phase_failure', lambda phase, error: events.append(phase))
    assert service_launcher.main(['--installer-launcher', SESSION, '--installer-launch-nonce', 'a' * 32]) == 1
    assert events == ['launcher']


@pytest.mark.skipif(os.name != 'nt', reason='Windows physical-pipe peer binding')
@pytest.mark.parametrize('defect', [None, 'server-creation', 'self-hash', 'self-sid', 'self-elevation'])
def test_launcher_pins_both_physical_peers_and_releases_handles(origin, monkeypatch, defect):
    import win32pipe
    closed = []
    monkeypatch.setattr(sys, 'frozen', True, raising=False)
    monkeypatch.setattr(broker, '_read_capability', lambda *_: deepcopy(origin))
    monkeypatch.setattr(win32pipe, 'GetNamedPipeServerProcessId', lambda _: origin['owner']['pid'])
    class Identity:
        def __init__(self, pid):
            self.pid = pid
            self.value = deepcopy(origin['owner'])
            if pid == os.getpid():
                self.value.update(pid=pid, hash=origin['helper_sha256'])
                if defect == 'self-hash': self.value['hash'] = '0' * 64
                if defect == 'self-sid': self.value['sid'] = 'S-1-5-32-545'
                if defect == 'self-elevation': self.value['elevated'] = False
            elif defect == 'server-creation': self.value['created'] += 1
        def close(self): closed.append(self.pid)
    class Transport:
        def __init__(self, name):
            assert name == 'EndpointInstaller-' + SESSION + '-' + 'a' * 32
            self.handle = 88
        def close(self): closed.append('transport')
    monkeypatch.setattr(broker, 'NativeIdentity', Identity)
    monkeypatch.setattr(broker, '_OwnerBoundTransport', Transport)
    if defect:
        with pytest.raises(ValueError, match='OWNER_AUTH_FAILED'):
            with broker._verified_launcher(None, SESSION, 'a' * 32): pytest.fail('forged peer admitted')
    else:
        with broker._verified_launcher(None, SESSION, 'a' * 32) as (value, owner, transport):
            assert value == origin and transport.owner is owner
    assert 'transport' in closed and origin['owner']['pid'] in closed


@pytest.mark.skipif(os.name != 'nt', reason='native protected extraction and file pins')
def test_worker_runtime_is_hardened_and_pinned_until_launcher_exit(native_protected_root, monkeypatch):
    from pc_agent.platform.windows import installer_fence as fence
    parent = native_protected_root / 'launcher'
    parent.mkdir();fence.protect_state(parent, secret=True)
    root = parent / '_MEI_runtime'
    root.mkdir();(root / 'nested').mkdir()
    library = root / 'nested' / 'runtime.dll'
    library.write_bytes(b'read-only extracted runtime fixture')
    checks = []
    owner = SimpleNamespace(assert_alive=lambda: checks.append(True))
    with monkeypatch.context() as scoped:
        scoped.chdir(parent)
        scoped.setattr(sys, 'frozen', True, raising=False)
        scoped.setattr(sys, '_MEIPASS', str(root), raising=False)
        with broker.protected_worker_runtime(owner) as verify:
            assert callable(verify)
            verify()
            for path in (root, root / 'nested', library): fence.assert_state_security(path, secret=True)
            for change in (lambda: library.write_bytes(b'changed'), library.unlink,
                           lambda: root.rename(parent / '_MEI_replaced')):
                with pytest.raises(OSError): change()
    library.write_bytes(b'handles released after launcher exit')
    assert checks


def test_owner_is_rechecked_after_runtime_validation(origin, monkeypatch):
    alive = [True]
    def owner_alive():
        if not alive[0]: raise ValueError('OWNER_AUTH_FAILED')
    def runtime_check(): alive[0] = False
    transport = SimpleNamespace(send=lambda _: None, receive=lambda: {
        'sequence': 1, 'action': 'launch', 'phase': 'inspect', 'session': SESSION})
    monkeypatch.setattr(broker, 'spawn_phase', lambda *_: pytest.fail('lost owner spawned after validation'))
    with pytest.raises(ValueError, match='OWNER_AUTH_FAILED'):
        broker.serve_launcher(origin, SimpleNamespace(assert_alive=owner_alive), transport,
                              lambda _: deepcopy(origin), before_spawn=runtime_check)


@pytest.mark.skipif(os.name != 'nt', reason='native protected extraction namespace')
def test_worker_runtime_refuses_foreign_root_before_acl_changes(native_protected_root, monkeypatch):
    from pc_agent.platform.windows import installer_fence as fence
    parent = native_protected_root / 'launcher'
    parent.mkdir();fence.protect_state(parent, secret=True)
    foreign = native_protected_root / '_MEI_foreign'
    foreign.mkdir();leaf = foreign / 'keep.txt';leaf.write_bytes(b'unchanged')
    with monkeypatch.context() as scoped:
        scoped.chdir(parent)
        scoped.setattr(sys, 'frozen', True, raising=False)
        scoped.setattr(sys, '_MEIPASS', str(foreign), raising=False)
        with pytest.raises(ValueError, match='OWNER_AUTH_FAILED'):
            with broker.protected_worker_runtime(SimpleNamespace(assert_alive=lambda: None)):
                pytest.fail('foreign extraction root admitted')
    assert leaf.read_bytes() == b'unchanged'


@pytest.mark.skipif(os.name != 'nt', reason='native extraction namespace and DACL revalidation')
@pytest.mark.parametrize('change', ['namespace', 'acl'])
def test_worker_runtime_revalidates_between_children(native_protected_root, monkeypatch, change):
    import win32security as security
    from pc_agent.platform.windows import installer_fence as fence
    parent = native_protected_root / 'launcher'
    parent.mkdir();fence.protect_state(parent, secret=True)
    root = parent / '_MEI_runtime';root.mkdir()
    leaf = root / 'runtime.dll';leaf.write_bytes(b'original')
    with monkeypatch.context() as scoped:
        scoped.chdir(parent)
        scoped.setattr(sys, 'frozen', True, raising=False)
        scoped.setattr(sys, '_MEIPASS', str(root), raising=False)
        with broker.protected_worker_runtime(SimpleNamespace(assert_alive=lambda: None)) as verify:
            if change == 'namespace':
                (root / 'unexpected.dll').write_bytes(b'unexpected')
            else:
                descriptor = security.ConvertStringSecurityDescriptorToSecurityDescriptor(
                    'D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;BU)', 1)
                security.SetNamedSecurityInfo(str(leaf), security.SE_FILE_OBJECT,
                    security.DACL_SECURITY_INFORMATION | security.PROTECTED_DACL_SECURITY_INFORMATION,
                    None, None, descriptor.GetSecurityDescriptorDacl(), None)
            with pytest.raises(ValueError): verify()


@pytest.mark.skipif(os.name != 'nt', reason='native handle ownership transfer')
def test_worker_runtime_closes_detached_handle_when_crt_adoption_fails(native_protected_root, monkeypatch):
    import msvcrt
    import pywintypes
    import win32api
    from pc_agent.platform.windows import installer_fence as fence
    parent = native_protected_root / 'launcher'
    parent.mkdir();fence.protect_state(parent, secret=True)
    root = parent / '_MEI_runtime'
    root.mkdir()
    detached = []
    def fail(raw, flags):
        detached.append(raw)
        raise OSError('simulated CRT adoption failure')
    try:
        with monkeypatch.context() as scoped:
            scoped.chdir(parent)
            scoped.setattr(sys, 'frozen', True, raising=False)
            scoped.setattr(sys, '_MEIPASS', str(root), raising=False)
            scoped.setattr(msvcrt, 'open_osfhandle', fail)
            with pytest.raises(OSError, match='simulated CRT'):
                with broker.protected_worker_runtime(SimpleNamespace(assert_alive=lambda: None)):
                    pytest.fail('failed handle adoption admitted')
            destination = parent / '_MEI_after_failure'
            assert root.resolve().parent == destination.resolve().parent == parent.resolve()
            root.rename(destination)  # Fails if the detached native handle leaked.
    finally:
        for raw in detached:
            try: win32api.CloseHandle(raw)
            except pywintypes.error: pass


@pytest.mark.skipif(os.name != 'nt', reason='real overlapped Windows pipe and owner handle')
@pytest.mark.parametrize('owner_loss', [False, True])
def test_launch_transport_reads_or_cancels_on_exact_owner_exit(owner_loss):
    import json
    import struct
    import subprocess
    import threading
    import uuid
    import win32api
    import win32file
    import win32pipe
    name = 'EndpointLaunchTest-' + uuid.uuid4().hex
    server = win32pipe.CreateNamedPipe('\\\\.\\pipe\\' + name, 3, 0, 1, 65536, 65536, 0, None)
    connected, release = threading.Event(), threading.Event()
    failures = []
    def serve():
        try:
            win32pipe.ConnectNamedPipe(server, None)
            connected.set()
            if owner_loss:
                release.wait(10)
            else:
                data = json.dumps({'ready': True}).encode('ascii')
                win32file.WriteFile(server, struct.pack('<I', len(data)) + data)
                release.wait(10)
        except BaseException as error:
            failures.append(type(error).__name__)
    worker = threading.Thread(target=serve, daemon=True)
    owner = subprocess.Popen([sys.executable, '-c', 'import time;time.sleep(1)']) if owner_loss else None
    process = win32api.OpenProcess(0x00101000, False, owner.pid if owner else os.getpid())
    transport = None
    worker.start()
    try:
        transport = broker._OwnerBoundTransport(name)
        transport.owner = SimpleNamespace(process=process, assert_alive=lambda: None)
        assert connected.wait(5)
        if owner_loss:
            with pytest.raises(ValueError, match='OWNER_AUTH_FAILED'):
                transport.receive()
        else:
            assert transport.receive() == {'ready': True}
    finally:
        release.set()
        worker.join(10)
        if transport: transport.close()
        server.Close();process.Close()
        if owner:
            if owner.poll() is None: owner.terminate()
            owner.wait(timeout=5)
    assert not worker.is_alive() and failures == []
