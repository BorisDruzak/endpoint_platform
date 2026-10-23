"""One bounded Unix listener around the common sensor envelope and projection."""
from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
import os
import socket
import stat
import struct
from threading import Event, Thread, Lock

from pc_agent.activity_ingress import ActivityIngress, _ack
from pc_agent.local_sensor_protocol import (
    LocalUserSessionEnvelopeV1, UserSessionSampleV1,
    LocalSensorProtocolError, parse_local_sensor_payload, serialize_local_sensor_payload,
)
from .local_ipc import (
    SOCKET_PATH, LinuxPeer, LocalIpcRejected, authenticate_connection,
    read_frame, write_frame,
)


def project_payload(payload: bytes, *, peer: LinuxPeer, ingress: ActivityIngress,
                    policy_provider, on_observation, on_security_event=None,
                    received_at: datetime | None = None):
    """Bind identity to OS credentials; logind lock/inactive state wins."""
    try:
        envelope = parse_local_sensor_payload(payload)
        now = received_at or datetime.now(UTC)
        current_policy = policy_provider()
        forced = ('DISCONNECTED' if not peer.session.active else
                  'LOCKED' if peer.session.locked else None)
        if forced:
            os_sample = LocalUserSessionEnvelopeV1(
                schema_version='local_sensor_envelope_v1', source='user_session',
                sample=UserSessionSampleV1(schema_version='user_session_sample_v1', desktop_state=forced),
            )
            safe_payload = serialize_local_sensor_payload(os_sample)
            if isinstance(envelope, LocalUserSessionEnvelopeV1):
                payload = safe_payload
            else:
                # Invalidate any earlier unlocked sample before a browser event
                # can project it. Keep the same session and policy boundaries.
                ingress.ingest(safe_payload, session_key=peer.session_key,
                               user_login=peer.user_login, policy=current_policy, received_at=now)
        reply, observation = ingress.ingest(
            payload, session_key=peer.session_key, user_login=peer.user_login,
            policy=current_policy, received_at=now, on_security_event=on_security_event,
        )
        if reply.accepted and observation is not None:
            on_observation(observation)
        return reply
    except LocalSensorProtocolError as error:
        return _ack(error.code)
    except Exception:
        return _ack('IPC_UNAVAILABLE')


class LinuxSensorListener:
    """Single worker, finite backlog, one deadline-limited record per connection.

    The runtime directory is provisioned by systemd, never by an interactive
    user. An advisory lock prevents duplicate listeners from unlinking a live
    socket. Only a socket owned by this service may be removed after a crash.
    """

    def __init__(self, handler: Callable[[socket.socket], None], *,
                 socket_path: Path = Path(SOCKET_PATH)) -> None:
        self._handler = handler
        self._path = socket_path
        self._stop = Event()
        self._thread: Thread | None = None
        self._server: socket.socket | None = None
        self._current: socket.socket | None = None
        self._guard = Lock()
        self._lock_fd: int | None = None
        self._socket_inode: int | None = None

    @property
    def available(self) -> bool:
        return self._thread is not None and self._thread.is_alive() and not self._stop.is_set()

    def start(self) -> None:
        import fcntl

        if self._thread is not None:
            raise RuntimeError('sensor listener already started')
        parent = self._path.parent
        info = parent.lstat()
        if parent.resolve() != parent or not stat.S_ISDIR(info.st_mode) or info.st_uid not in {0, os.getuid()} or info.st_mode & 0o022:
            raise ValueError('unsafe sensor directory')
        lock_fd = os.open(str(self._path) + '.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            info = os.fstat(lock_fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_nlink != 1:
                raise ValueError('unsafe sensor lock')
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._lock_fd = lock_fd
            try:
                previous = self._path.lstat()
            except FileNotFoundError:
                previous = None
            if previous is not None:
                if not stat.S_ISSOCK(previous.st_mode) or previous.st_uid != os.getuid():
                    raise ValueError('unsafe sensor socket')
                self._path.unlink()
            server = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            self._server = server
            server.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            server.bind(str(self._path))
            self._socket_inode = self._path.lstat().st_ino
            self._path.chmod(0o666)  # Authentication is kernel UID/PID + logind.
            server.listen(16)
            server.settimeout(0.25)
            self._thread = Thread(target=self._run, name='EndpointLinuxSensor', daemon=True)
            self._thread.start()
        except Exception:
            if self._lock_fd is None:
                os.close(lock_fd)
            else:
                self._cleanup()
            raise

    def _run(self) -> None:
        try:
            while not self._stop.is_set():
                try:
                    connection, _address = self._server.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                with connection:
                    with self._guard:
                        self._current = connection
                    connection.settimeout(1.0)
                    try:
                        self._handler(connection)
                    except Exception:
                        pass  # Optional sensors must not terminate Core.
                    finally:
                        with self._guard:
                            self._current = None
        finally:
            self._cleanup()

    def stop(self) -> None:
        self._stop.set()
        if self._server is not None:
            self._server.close()
        with self._guard:
            if self._current is not None:
                try:
                    self._current.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
        if self._thread is not None:
            self._thread.join(timeout=10)
            if self._thread.is_alive():
                raise TimeoutError('sensor listener did not stop')
            self._thread = None

    def _cleanup(self) -> None:
        if self._server is not None:
            self._server.close()
            self._server = None
        if self._socket_inode is not None:
            try:
                info = self._path.lstat()
                if stat.S_ISSOCK(info.st_mode) and info.st_uid == os.getuid() and info.st_ino == self._socket_inode:
                    self._path.unlink()
            except FileNotFoundError:
                pass
            self._socket_inode = None
        if self._lock_fd is not None:
            os.close(self._lock_fd)
            self._lock_fd = None


def create_activity_listener(*, ingress, policy_provider, on_observation,
                             on_security_event=None, socket_path=Path(SOCKET_PATH)):
    def handler(connection):
        credentials = struct.unpack('iII', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        payload = read_frame(connection, expected_peer=credentials)
        # Resolve logind and directory facts after the bounded record arrived,
        # so a stalled client cannot retain an earlier unlocked session state.
        peer, current_credentials = authenticate_connection(connection)
        if current_credentials != credentials:
            raise LocalIpcRejected('IDENTITY_MISMATCH')
        reply = project_payload(payload, peer=peer, ingress=ingress,
                                policy_provider=policy_provider, on_observation=on_observation,
                                on_security_event=on_security_event)
        write_frame(connection, reply.model_dump_json().encode('utf-8'))
    return LinuxSensorListener(handler, socket_path=socket_path)
