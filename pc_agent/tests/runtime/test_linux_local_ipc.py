"""Kernel peer credentials and logind own the Linux sensor identity boundary."""
import os
import array
import socket
import struct

import pytest

from pc_agent.platform.linux.sessions import LinuxSession


def _session(sid="c1", uid=2000, active=True, locked=False):
    return LinuxSession(sid, uid, "worker", "wayland", active, locked, "active")


def test_peer_identity_comes_from_kernel_uid_and_logind_session():
    from pc_agent.platform.linux.local_ipc import authorize_peer

    peer = authorize_peer(100, 2000, sessions=[_session()], pid_session="c1", login_resolver=lambda uid, name: "worker@corp.example")
    assert peer.session_key == ("linux", "c1", 2000)
    assert peer.user_login == "worker@corp.example" and peer.pid == 100


@pytest.mark.parametrize("uid,sessions,pid_session", [
    (0, [_session()], "c1"),
    (3000, [_session()], "c1"),
    (2000, [_session()], "other"),
    (2000, [_session(), _session("c2")], None),
])
def test_cross_uid_cross_session_and_ambiguous_manager_peers_are_rejected(uid, sessions, pid_session):
    from pc_agent.platform.linux.local_ipc import authorize_peer, LocalIpcRejected

    with pytest.raises(LocalIpcRejected):
        authorize_peer(100, uid, sessions=sessions, pid_session=pid_session, login_resolver=lambda *a: "worker@corp.example")


def test_user_manager_process_falls_back_only_to_a_unique_os_session():
    from pc_agent.platform.linux.local_ipc import authorize_peer

    peer = authorize_peer(100, 2000, sessions=[_session()], pid_session=None, login_resolver=lambda *a: "worker@corp.example")
    assert peer.session.session_id == "c1"


@pytest.mark.skipif(os.name != "posix", reason="real Linux Unix socket credentials")
def test_socket_frame_checks_real_sender_and_rejects_oversize_before_body():
    from pc_agent.platform.linux.local_ipc import read_frame, LocalIpcRejected

    client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    try:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        client.send(struct.pack("<I", 2) + b"{}")
        assert read_frame(server, expected_peer=(os.getpid(), os.getuid(), os.getgid())) == b"{}"
        client.sendall(struct.pack("<I", 16385))
        with pytest.raises(LocalIpcRejected):
            read_frame(server, expected_peer=(os.getpid(), os.getuid(), os.getgid()))
    finally:
        client.close()
        server.close()


@pytest.mark.skipif(os.name != 'posix', reason='real Linux Unix socket credentials')
def test_frame_rejects_socket_handoff_credentials_and_closes_passed_descriptors():
    from pc_agent.platform.linux.local_ipc import read_frame, LocalIpcRejected

    client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    try:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        client.send(struct.pack('<I', 2) + b'{}')
        with pytest.raises(LocalIpcRejected):
            read_frame(server, expected_peer=(os.getpid() + 1, os.getuid(), os.getgid()))
        descriptor = os.open('/dev/null', os.O_RDONLY)
        before = len(os.listdir('/proc/self/fd'))
        try:
            client.sendmsg([struct.pack('<I', 2) + b'{}'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [descriptor]))])
            with pytest.raises(LocalIpcRejected):
                read_frame(server, expected_peer=(os.getpid(), os.getuid(), os.getgid()))
            assert len(os.listdir('/proc/self/fd')) == before
        finally:
            os.close(descriptor)
    finally:
        client.close()
        server.close()


@pytest.mark.skipif(os.name != 'posix', reason='real Linux mutual socket credentials')
def test_user_client_verifies_socket_owner_and_kernel_server_identity(tmp_path, monkeypatch):
    import pwd
    from types import SimpleNamespace
    from pc_agent.platform.linux.local_ipc import exchange, read_frame, write_frame
    from pc_agent.platform.linux.sensor_listener import LinuxSensorListener

    monkeypatch.setattr(pwd, 'getpwnam', lambda name: SimpleNamespace(pw_uid=os.getuid()))
    def reply(connection):
        assert read_frame(connection, expected_peer=(os.getpid(), os.getuid(), os.getgid())) == b'{"test":1}'
        write_frame(connection, b'{"accepted":true}')
    path = tmp_path / 'sensor.sock'
    listener = LinuxSensorListener(reply, socket_path=path)
    listener.start()
    try:
        assert exchange(b'{"test":1}', socket_path=path) == b'{"accepted":true}'
        monkeypatch.setattr(pwd, 'getpwnam', lambda name: SimpleNamespace(pw_uid=os.getuid() + 1))
        with pytest.raises(PermissionError):
            exchange(b'{"test":1}', socket_path=path)
    finally:
        listener.stop()
