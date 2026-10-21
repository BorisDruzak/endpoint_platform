"""Small privileged service: two closed browser-policy operations for Core only."""
from __future__ import annotations

import os
from pathlib import Path
import re
import signal
import socket
import stat
import struct
import threading

from pc_agent.browser_policy_protocol import (
    BrowserPolicyRequestError, decode_policy_request, encode_policy_reply,
)
from .browser_policy import BrowserPolicyConflict, LinuxBrowserPolicy, _directory, _read
from .seqpacket import LocalIpcRejected, read_frame, write_frame

SOCKET_PATH = Path('/run/endpoint-agent-browser-policy/policy.sock')
EXTENSION_ID_PATH = Path('/usr/share/endpoint-agent/extension-id.txt')
_UCRED = struct.Struct('iII')


def handle_connection(connection, applicator, *, agent_uid: int) -> None:
    credentials = _UCRED.unpack(connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _UCRED.size))
    if credentials[1] != agent_uid:
        raise LocalIpcRejected('IDENTITY_MISMATCH')
    # Recheck the sender on the complete atomic record: handing an authenticated
    # connection to a different process does not delegate privileged access.
    payload = read_frame(connection, expected_peer=credentials)
    try:
        operation, family = decode_policy_request(payload)
        status = getattr(applicator, operation)(family)
    except BrowserPolicyRequestError:
        status = 'INVALID_REQUEST'
    except BrowserPolicyConflict:
        status = 'POLICY_CONFLICT'
    except Exception:
        # Do not disclose file contents or exception text across the boundary.
        status = 'HELPER_ERROR'
    write_frame(connection, encode_policy_reply(status))


def _extension_identity() -> str:
    raw = _read(EXTENSION_ID_PATH)
    value = '' if raw is None else raw.decode('ascii').strip()
    if re.fullmatch(r'[a-p]{32}', value) is None:
        raise ValueError('invalid root-owned extension identity')
    return value


def serve(stop: threading.Event) -> None:
    import fcntl
    import pwd

    if os.geteuid() != 0:
        raise PermissionError('root service required')
    account = pwd.getpwnam('endpoint-agent')
    if account.pw_uid <= 0 or account.pw_gid <= 0:
        raise ValueError('dedicated service account required')
    applicator = LinuxBrowserPolicy(extension_id=_extension_identity())
    _directory(SOCKET_PATH.parent)
    lock_path = SOCKET_PATH.parent / 'policy.lock'
    descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(descriptor, 'r+b') as lock:
        info = os.fstat(lock.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600):
            raise PermissionError('unsafe service lock')
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            stale = SOCKET_PATH.lstat()
        except FileNotFoundError:
            stale = None
        if stale is not None:
            if not stat.S_ISSOCK(stale.st_mode) or stale.st_uid != 0:
                raise PermissionError('unsafe service socket')
            SOCKET_PATH.unlink()
        with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            server.bind(str(SOCKET_PATH))
            identity = SOCKET_PATH.lstat()
            os.chown(SOCKET_PATH, 0, account.pw_gid, follow_symlinks=False)
            os.chmod(SOCKET_PATH, 0o660, follow_symlinks=False)
            server.listen(16)
            server.settimeout(0.25)
            try:
                while not stop.is_set():
                    try:
                        connection, _ = server.accept()
                    except TimeoutError:
                        continue
                    with connection:
                        connection.settimeout(1.0)
                        try:
                            handle_connection(connection, applicator, agent_uid=account.pw_uid)
                        except (LocalIpcRejected, OSError):
                            pass
            finally:
                try:
                    current = SOCKET_PATH.lstat()
                    if (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino):
                        SOCKET_PATH.unlink()
                except FileNotFoundError:
                    pass


def main(argv=None) -> int:
    import sys

    arguments = list(sys.argv[1:] if argv is None else argv)
    if os.geteuid() != 0 or arguments not in ([], ['--relinquish']):
        return 78
    try:
        if arguments:
            applicator = LinuxBrowserPolicy(extension_id=_extension_identity())
            for family in ('chrome', 'yandex'):
                applicator.relinquish(family)
        else:
            stop = threading.Event()
            for signum in (signal.SIGTERM, signal.SIGINT):
                signal.signal(signum, lambda *_args: stop.set())
            serve(stop)
    except (OSError, ValueError, BrowserPolicyConflict):
        return 78
    return 0
