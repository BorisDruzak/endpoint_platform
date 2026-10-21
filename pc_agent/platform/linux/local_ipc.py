"""Authenticated, atomic Linux sensor frames; no commands or device credentials."""
from __future__ import annotations

import array
from collections.abc import Callable, Sequence
import ctypes
from dataclasses import dataclass
import os
from pathlib import Path
import socket
import stat
import struct

from pc_agent.local_sensor_protocol import MAX_IPC_MESSAGE_BYTES
from .identity import resolve_login
from .sessions import LinuxSession, list_sessions

SOCKET_PATH = '/run/endpoint-agent/sensor.sock'
_UCRED = struct.Struct('iII')


class LocalIpcRejected(PermissionError):
    pass


@dataclass(frozen=True, slots=True)
class LinuxPeer:
    pid: int
    uid: int
    session: LinuxSession
    user_login: str | None

    @property
    def session_key(self) -> tuple[str, str, int]:
        return 'linux', self.session.session_id, self.uid


def pid_session_id(pid: int) -> str | None:
    library = ctypes.CDLL('libsystemd.so.0')
    libc = ctypes.CDLL(None)
    library.sd_pid_get_session.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_void_p)]
    library.sd_pid_get_session.restype = ctypes.c_int
    libc.free.argtypes = [ctypes.c_void_p]
    libc.free.restype = None
    pointer = ctypes.c_void_p()
    if library.sd_pid_get_session(pid, ctypes.byref(pointer)) < 0 or not pointer:
        return None
    try:
        return ctypes.string_at(pointer).decode('ascii')
    finally:
        libc.free(pointer)


def authorize_peer(
    pid: int, uid: int, *, sessions: Sequence[LinuxSession],
    pid_session: str | None,
    login_resolver: Callable[[int, str], str | None] = resolve_login,
) -> LinuxPeer:
    if type(pid) is not int or pid <= 0 or type(uid) is not int or not 0 < uid < 2**32:
        raise LocalIpcRejected('IDENTITY_MISMATCH')
    candidates = [session for session in sessions if session.uid == uid and session.state in {'active', 'online'}]
    if pid_session is not None:
        candidates = [session for session in candidates if session.session_id == pid_session]
    # Modern desktop applications can belong to user@UID.service rather than
    # a logind scope. A unique graphical session is then the only safe fallback.
    if len(candidates) != 1:
        raise LocalIpcRejected('IDENTITY_MISMATCH')
    session = candidates[0]
    return LinuxPeer(pid, uid, session, login_resolver(uid, session.user_login))


def authenticate_connection(connection: socket.socket) -> tuple[LinuxPeer, tuple[int, int, int]]:
    credentials = _UCRED.unpack(connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _UCRED.size))
    pid, uid, _gid = credentials
    peer = authorize_peer(pid, uid, sessions=list_sessions(), pid_session=pid_session_id(pid))
    return peer, credentials


def read_frame(connection: socket.socket, *, expected_peer: tuple[int, int, int]) -> bytes:
    """One SOCK_SEQPACKET record binds its entire frame to the actual sender.

    SO_PASSCRED is required at both endpoints before sending. SCM credentials
    also prevent handing an already-authenticated connection to another process.
    Descriptor passing is never accepted; any received FDs are closed first.
    """
    packet, controls, flags, _address = connection.recvmsg(
        MAX_IPC_MESSAGE_BYTES + 5,
        socket.CMSG_SPACE(_UCRED.size) + socket.CMSG_SPACE(64),
    )
    credentials = []
    rejected_control = False
    for level, kind, data in controls:
        if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
            descriptors = array.array('i')
            descriptors.frombytes(data[:len(data) - len(data) % descriptors.itemsize])
            for descriptor in descriptors:
                os.close(descriptor)
            rejected_control = True
        elif level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS and len(data) == _UCRED.size:
            credentials.append(_UCRED.unpack(data))
        else:
            rejected_control = True
    if rejected_control or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or credentials != [expected_peer]:
        raise LocalIpcRejected('IDENTITY_MISMATCH')
    if len(packet) < 5:
        raise LocalIpcRejected('INVALID_MESSAGE')
    size = struct.unpack_from('<I', packet)[0]
    if not 1 <= size <= MAX_IPC_MESSAGE_BYTES or len(packet) != size + 4:
        raise LocalIpcRejected('OVERSIZE')
    return packet[4:]


def write_frame(connection: socket.socket, payload: bytes) -> None:
    if not isinstance(payload, bytes) or not 1 <= len(payload) <= MAX_IPC_MESSAGE_BYTES:
        raise LocalIpcRejected('OVERSIZE')
    packet = struct.pack('<I', len(payload)) + payload
    if connection.send(packet) != len(packet):
        raise LocalIpcRejected('IPC_UNAVAILABLE')


def exchange(payload: bytes, *, socket_path: Path = Path(SOCKET_PATH)) -> bytes:
    """User-side transport authenticates the fixed service before disclosing data."""
    import pwd

    service_uid = pwd.getpwnam('endpoint-agent').pw_uid
    parent = socket_path.parent
    directory = parent.lstat()
    endpoint = socket_path.lstat()
    if (parent.resolve() != parent or not stat.S_ISDIR(directory.st_mode)
            or directory.st_uid not in {0, service_uid} or directory.st_mode & 0o022
            or not stat.S_ISSOCK(endpoint.st_mode) or endpoint.st_uid != service_uid):
        raise LocalIpcRejected('IDENTITY_MISMATCH')
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as connection:
        connection.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        connection.settimeout(3.0)
        connection.connect(str(socket_path))
        credentials = _UCRED.unpack(connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _UCRED.size))
        if credentials[1] != service_uid:
            raise LocalIpcRejected('IDENTITY_MISMATCH')
        write_frame(connection, payload)
        return read_frame(connection, expected_peer=credentials)
