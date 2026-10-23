"""Linux adapter preserves OS session boundaries and shared policy projection."""
from datetime import UTC, datetime
import os
import socket

import pytest

from pc_agent.activity_ingress import ActivityIngress
from pc_agent.local_sensor_protocol import LocalUserSessionEnvelopeV1, UserSessionSampleV1, serialize_local_sensor_payload
from pc_agent.platform.linux.local_ipc import LinuxPeer
from pc_agent.platform.linux.sessions import LinuxSession
from pc_agent.tests.windows.test_activity_api import policy


@pytest.mark.parametrize('active,locked,expected', [(True, True, 'LOCKED'), (False, False, 'DISCONNECTED'), (True, False, 'ACTIVE')])
def test_os_state_overrides_a_user_claiming_unlocked(active, locked, expected):
    from pc_agent.platform.linux.sensor_listener import project_payload

    peer = LinuxPeer(123, 2000, LinuxSession('c1', 2000, 'short', 'wayland', active, locked, 'active'), 'user@corp.example')
    payload = serialize_local_sensor_payload(LocalUserSessionEnvelopeV1(
        schema_version='local_sensor_envelope_v1', source='user_session',
        sample=UserSessionSampleV1(schema_version='user_session_sample_v1', desktop_state='UNLOCKED', idle_seconds=0),
    ))
    observations = []
    reply = project_payload(payload, peer=peer, ingress=ActivityIngress(expected_extension_id=None),
                            policy_provider=lambda: policy(browser_context=False), on_observation=observations.append,
                            received_at=datetime.now(UTC))
    assert reply.accepted and observations[0].session_state == expected
    assert observations[0].user_login == 'user@corp.example'


def test_queue_failure_is_not_acknowledged_as_accepted():
    from pc_agent.platform.linux.sensor_listener import project_payload

    peer = LinuxPeer(123, 2000, LinuxSession('c1', 2000, 'short', 'x11', True, False, 'active'), None)
    payload = serialize_local_sensor_payload(LocalUserSessionEnvelopeV1(
        schema_version='local_sensor_envelope_v1', source='user_session',
        sample=UserSessionSampleV1(schema_version='user_session_sample_v1', desktop_state='UNKNOWN'),
    ))
    def fail(_observation):
        raise RuntimeError('queue full')
    reply = project_payload(payload, peer=peer, ingress=ActivityIngress(expected_extension_id=None),
                            policy_provider=lambda: policy(browser_context=False), on_observation=fail)
    assert not reply.accepted and reply.error_code == 'IPC_UNAVAILABLE'


@pytest.mark.skipif(os.name != 'posix', reason='Linux kernel socket credentials')
def test_listener_has_bounded_stop_rejects_duplicate_and_cleans_only_own_socket(tmp_path):
    from pc_agent.platform.linux.sensor_listener import LinuxSensorListener

    listener = LinuxSensorListener(lambda connection: None, socket_path=tmp_path / 'sensor.sock')
    listener.start()
    assert listener.available
    second = LinuxSensorListener(lambda connection: None, socket_path=tmp_path / 'sensor.sock')
    with pytest.raises((OSError, ValueError)):
        second.start()
    client = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    try:
        client.connect(str(tmp_path / 'sensor.sock'))
        listener.stop()
        assert not listener.available and not (tmp_path / 'sensor.sock').exists()
    finally:
        client.close()


@pytest.mark.skipif(os.name != 'posix', reason='Linux filesystem socket safety')
def test_listener_does_not_replace_files_or_symlinks(tmp_path):
    from pc_agent.platform.linux.sensor_listener import LinuxSensorListener

    sentinel = tmp_path / 'sensor.sock'
    sentinel.write_text('preserve')
    with pytest.raises((OSError, ValueError)):
        LinuxSensorListener(lambda connection: None, socket_path=sentinel).start()
    assert sentinel.read_text() == 'preserve'
