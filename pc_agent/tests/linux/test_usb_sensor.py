"""Kernel USB metadata must not accept user-space injection or private fields."""
from datetime import UTC, datetime
import socket
import sys
import struct
from uuid import UUID

import pytest

from pc_agent.platform.linux.usb_sensor import UsbNotifications, decode_usb_event, project_usb_change
from tests.contracts.test_endpoint_policy_v1 import _policy
from endpoint_contracts.endpoint_policy import EndpointPolicyV1

BOOT = UUID('50cd6883-355e-435b-bc82-b7debd9c52de')


def packet(action='add', **changes):
    values = dict(ACTION=action, DEVPATH='/devices/pci0000:00/usb1/1-2',
                  SUBSYSTEM='usb', DEVTYPE='usb_device', PRODUCT='1234/abcd/100',
                  TYPE='8/0/0', SEQNUM='100') | changes
    return (f'{action}@{values["DEVPATH"]}\0'.encode() +
            b''.join(key.encode() + b'=' + value.encode() + b'\0' for key, value in values.items()))


def decode(data, **changes):
    return decode_usb_event(data, boot_id=BOOT, sender=(0, 1), credentials=(0, 0, 0), **changes)


def test_usb_change_uses_only_ids_class_and_a_stable_event_id():
    change = decode(packet(SERIAL='PRIVATE_SERIAL', DOCUMENT='PRIVATE_DOCUMENT'))
    assert change is not None and change.action == 'add'
    assert change.event_identifier == decode(packet()).event_identifier
    policy = EndpointPolicyV1.model_validate(_policy())
    event = project_usb_change(change, policy, occurred_at=datetime.now(UTC))
    assert event.event_type == 'USB_DEVICE_CONNECTED'
    assert event.safe_metadata.vendor == 'VID_1234'
    assert event.safe_metadata.product == 'PID_ABCD'
    assert event.safe_metadata.device_class == 'mass_storage'
    assert event.safe_metadata.serial_hash is None
    wire = event.model_dump_json()
    assert 'PRIVATE_' not in wire and '/devices/' not in wire
    removed = decode(packet('remove', SEQNUM='101'))
    assert removed.event_identifier != change.event_identifier
    assert project_usb_change(removed, policy, occurred_at=datetime.now(UTC)).event_type == 'USB_DEVICE_DISCONNECTED'


@pytest.mark.parametrize('sender,credentials', [((123, 1), (0, 0, 0)), ((0, 1), (123, 1000, 1000)), ((0, 1), None)])
def test_usb_rejects_non_kernel_senders(sender, credentials):
    with pytest.raises(PermissionError):
        decode_usb_event(packet(), boot_id=BOOT, sender=sender, credentials=credentials)


@pytest.mark.parametrize('data', [b'x' * 16385, packet()[:-1], packet() + b'SEQNUM=101\0',
    packet(PRODUCT='../../private'), packet(SEQNUM='-1')])
def test_usb_rejects_incomplete_duplicate_or_invalid_kernel_fields(data):
    with pytest.raises(ValueError):
        decode(data)


def test_usb_ignores_interfaces_other_subsystems_and_synthetic_events():
    assert decode(packet(DEVTYPE='usb_interface')) is None
    assert decode(packet(SUBSYSTEM='input')) is None
    assert decode(packet(SYNTH_UUID='0')) is None


def test_usb_truncation_and_disabled_policy_do_not_create_success():
    with pytest.raises(ValueError):
        decode(packet(), flags=socket.MSG_TRUNC)
    assert project_usb_change(decode(packet()), None, occurred_at=datetime.now(UTC)) is None
    document = _policy(); document['dlp']['usb_device_events'] = 'disabled'
    assert project_usb_change(decode(packet()), EndpointPolicyV1.model_validate(document), occurred_at=datetime.now(UTC)) is None


@pytest.mark.skipif(sys.platform != 'linux', reason='native Linux netlink subscription')
def test_kernel_subscription_is_ready_and_cancellable_without_privileges():
    source = UsbNotifications(lambda _change: None)
    source.start()
    try:
        assert source.available
    finally:
        source.stop()
    assert not source.available


@pytest.mark.skipif(sys.platform != 'linux', reason='native SCM_CREDENTIALS constants')
def test_usb_persistence_failure_stops_source_without_claiming_readiness():
    class Connection:
        def recvmsg(self, *_args):
            return packet(), [(socket.SOL_SOCKET, socket.SCM_CREDENTIALS, struct.pack('iII', 0, 0, 0))], 0, (0, 1)
    def refuse(_change):
        raise OSError('spool unavailable')
    source = UsbNotifications(refuse)
    source._socket, source._boot_id, source._healthy = Connection(), BOOT, True
    source._run()
    assert source.failed == 1 and not source._healthy and not source.available
