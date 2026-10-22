"""Launch fixed helper children from an initialized, verified onefile parent.

This process grants no installer phase or mutation. Every child establishes its
own ordinary owner-authorized conversation, with a new native process identity.
The launch-only pipe authenticates both peers through retained native handles.
"""
from contextlib import ExitStack, contextmanager
import os
import re
import subprocess
import sys
import stat
from pathlib import Path
from uuid import UUID

from .installer_transaction_bridge import PHASES, NativeIdentity, PipeTransport, _read_capability
from .update_paths import WindowsUpdatePaths
from endpoint_contracts.runtime_payload import reject_reparse_ancestors

OWNER_PHASES = PHASES - {'msi-preflight', 'msi-enter', 'msi-complete', 'recover-enter',
                        'foundation-config', 'uninstall-finalize-preflight',
                        'uninstall-finalize-enter', 'uninstall-finalize-complete'}


def _fail():
    raise ValueError('OWNER_AUTH_FAILED')


def _session(value):
    try:
        if not isinstance(value, str) or str(UUID(value)) != value: _fail()
    except (ValueError, TypeError, AttributeError):
        _fail()
    return value


def validate_launch_request(value, sequence, origin, read_capability):
    if (not isinstance(value, dict) or type(value.get('sequence')) is not int
            or value['sequence'] != sequence or not 1 <= sequence <= 512):
        _fail()
    if set(value) == {'sequence', 'action'} and value['action'] == 'close':
        return None
    if (set(value) != {'sequence', 'action', 'phase', 'session'}
            or sequence >= 512 or value['action'] != 'launch' or not isinstance(value['phase'], str)
            or value['phase'] not in OWNER_PHASES):
        _fail()
    session = _session(value['session'])
    target = read_capability(session)
    if any(target[key] != origin[key] for key in ('transaction_id', 'owner', 'helper_sha256')):
        _fail()
    return value['phase'], session


def spawn_phase(phase, session):
    if not getattr(sys, 'frozen', False) or phase not in OWNER_PHASES:
        _fail()
    _session(session)
    # PyInstaller's supported same-executable worker path inherits the verified
    # onefile parent. Never forge/reset its private environment variables.
    return subprocess.Popen([sys.executable, '--installer-phase', phase,
                             '--installer-session', session],
                            shell=False, close_fds=True, creationflags=0x08000000)


class _OwnerBoundTransport(PipeTransport):
    """An idle launch pipe waits for data OR its exact owner's retained handle.

    Ordinary native-phase transports retain their existing 30-second bounds.
    This launch-only connection may idle throughout a native MSI call without
    losing the live-owner requirement or abandoning an overlapped read.
    """
    owner = None

    def _io(self, data, *, writing):
        if writing:
            return super()._io(data, writing=True)
        import pywintypes
        import win32event
        import win32file
        if self.owner is None: _fail()
        operation = pywintypes.OVERLAPPED()
        operation.hEvent = win32event.CreateEvent(None, True, False, None)
        try:
            _, buffer = win32file.ReadFile(self.handle, data, operation)
            result = win32event.WaitForMultipleObjects(
                (operation.hEvent, self.owner.process), False, 4 * 60 * 60 * 1000)
            if result != win32event.WAIT_OBJECT_0:
                try:
                    win32file.CancelIo(self.handle)
                    win32file.GetOverlappedResult(self.handle, operation, True)
                except pywintypes.error:
                    pass
                _fail()
            self.owner.assert_alive()
            size = win32file.GetOverlappedResult(self.handle, operation, False)
            if size <= 0: _fail()
            return bytes(buffer[:size])
        finally:
            operation.hEvent.Close()


def serve_launcher(origin, owner, transport, read_capability, *, before_spawn=lambda: None):
    child = None
    try:
        owner.assert_alive()
        transport.send({'ready': True})
        for sequence in range(1, 513):
            owner.assert_alive()
            value = transport.receive()
            owner.assert_alive()
            command = validate_launch_request(value, sequence, origin, read_capability)
            if child is not None and child.poll() is None:
                _fail()
            if command is None:
                transport.send({'sequence': sequence, 'closed': True})
                return 0
            before_spawn()
            owner.assert_alive()
            child = spawn_phase(*command)
            identity = NativeIdentity(child.pid)
            try:
                owner.assert_alive()
                if (identity.value['hash'] != origin['helper_sha256']
                        or identity.value['sid'] != origin['owner']['sid']
                        or identity.value['elevated'] is not True):
                    _fail()
                transport.send({'sequence': sequence, 'pid': child.pid,
                                'created': identity.value['created']})
            finally:
                identity.close()
        _fail()
    finally:
        # Popen retains this exact child handle. Never terminate by a name or
        # a recycled wire PID. No native grant originates from this process.
        if child is not None and child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)


@contextmanager
def _verified_launcher(paths, session, nonce):
    if (os.name != 'nt' or not getattr(sys, 'frozen', False)
            or not isinstance(nonce, str) or not re.fullmatch('[0-9a-f]{32}', nonce)):
        _fail()
    import win32pipe
    origin = _read_capability(paths, _session(session))
    with ExitStack() as stack:
        transport = _OwnerBoundTransport('EndpointInstaller-' + session + '-' + nonce)
        stack.callback(transport.close)
        owner = NativeIdentity(win32pipe.GetNamedPipeServerProcessId(transport.handle))
        stack.callback(owner.close)
        if owner.value != origin['owner']: _fail()
        identity = NativeIdentity(os.getpid())
        stack.callback(identity.close)
        if (identity.value['hash'] != origin['helper_sha256']
                or identity.value['sid'] != owner.value['sid']
                or identity.value['elevated'] is not True):
            _fail()
        transport.owner = owner
        yield origin, owner, transport


def run_launch_broker(session, nonce):
    paths = WindowsUpdatePaths.production()
    with _verified_launcher(paths, session, nonce) as (origin, owner, transport):
        with protected_worker_runtime(owner) as verify:
            return serve_launcher(origin, owner, transport, lambda value: _read_capability(paths, value),
                                  before_spawn=verify)


@contextmanager
def protected_worker_runtime(owner):
    """Keep the shared bootstrap DLL tree administrator-only and deny mutation.

    PyInstaller applies a current-user DACL to its temporary directories. Before
    reusing that tree for other elevated phases, harden only this verified
    launcher's own extraction. Native handles pin every object against rename,
    deletion and content writes. No product directory or Native grant is used.
    """
    if os.name != 'nt' or not getattr(sys, 'frozen', False): _fail()
    import msvcrt
    import win32api
    import win32file
    import win32security as security
    from .installer_fence import assert_state_security
    parent = Path.cwd().absolute()
    root = Path(getattr(sys, '_MEIPASS', '')).absolute()
    if root.parent != parent or not root.name.startswith('_MEI'): _fail()
    assert_state_security(parent, secret=True)
    reject_reparse_ancestors(root)
    with ExitStack() as stack:
        todo = [root]
        count = 0
        pins = []
        while todo:
            path = todo.pop()
            count += 1
            if count > 10000: _fail()
            owner.assert_alive()
            reject_reparse_ancestors(path)
            before = path.lstat()
            directory = stat.S_ISDIR(before.st_mode)
            if not directory and (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1): _fail()
            handle = win32file.CreateFile(str(path), 0x800C0000, 1, None, 3, 0x02200000, None)
            try:
                details = win32file.GetFileInformationByHandle(handle)
                if details[0] & 0x400 or (not directory and details[7] != 1): _fail()
            except BaseException:
                handle.Close()
                raise
            raw_handle = handle.Detach()
            try:
                descriptor_fd = msvcrt.open_osfhandle(raw_handle, os.O_RDONLY | os.O_BINARY)
            except BaseException:
                win32api.CloseHandle(raw_handle)
                raise
            stack.callback(os.close, descriptor_fd)
            opened = os.fstat(descriptor_fd)
            if (before.st_dev, before.st_ino, stat.S_IFMT(before.st_mode)) != (
                    opened.st_dev, opened.st_ino, stat.S_IFMT(opened.st_mode)): _fail()
            inheritance = 'OICI' if directory else ''
            descriptor = security.ConvertStringSecurityDescriptorToSecurityDescriptor(
                'O:BAG:BAD:P(A;' + inheritance + ';FA;;;SY)(A;' + inheritance + ';FA;;;BA)', 1)
            # SetSecurityInfo uses the opened object, never a replaceable pathname.
            security.SetSecurityInfo(msvcrt.get_osfhandle(descriptor_fd), security.SE_FILE_OBJECT,
                security.OWNER_SECURITY_INFORMATION | security.DACL_SECURITY_INFORMATION
                | security.PROTECTED_DACL_SECURITY_INFORMATION,
                descriptor.GetSecurityDescriptorOwner(), None, descriptor.GetSecurityDescriptorDacl(), None)
            assert_state_security(path, secret=True)
            pins.append((path, descriptor_fd, os.fstat(descriptor_fd)))
            if directory:
                with os.scandir(path) as children:
                    todo.extend(Path(child.path) for child in children)
        expected = {path.relative_to(root).as_posix() for path, _, _ in pins}
        def verify():
            actual = {'.'}
            for directory, subdirs, files in os.walk(root, followlinks=False):
                for name in (*subdirs, *files):
                    actual.add((Path(directory) / name).relative_to(root).as_posix())
                    if len(actual) > 10000: _fail()
            if actual != expected: _fail()
            for path, descriptor_fd, before in pins:
                owner.assert_alive()
                assert_state_security(path, secret=True)
                after, named = os.fstat(descriptor_fd), path.lstat()
                if ((before.st_dev, before.st_ino, stat.S_IFMT(before.st_mode)) !=
                    (named.st_dev, named.st_ino, stat.S_IFMT(named.st_mode))): _fail()
                if stat.S_ISREG(before.st_mode) and (
                        (after.st_size, after.st_mtime_ns, after.st_nlink) !=
                        (before.st_size, before.st_mtime_ns, 1)):
                    _fail()
        verify()
        yield verify
