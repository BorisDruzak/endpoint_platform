"""Bounded credential-bound Linux seqpacket frames shared by local services."""
from __future__ import annotations
import array
import os
import socket
import struct

MAX_IPC_MESSAGE_BYTES = 16 * 1024
_UCRED = struct.Struct('iII')


class LocalIpcRejected(PermissionError):
    pass


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
