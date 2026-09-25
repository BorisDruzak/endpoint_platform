"""USB audit uses PnP interface changes without leaking symbolic links."""

from __future__ import annotations

import asyncio
import ctypes
import hashlib
import os
import threading
from datetime import UTC, datetime

import pytest

from endpoint_contracts.endpoint_policy import EndpointPolicyV1
from pc_agent.platform.windows.usb_sensor import (
    UsbInterfaceNotifications,
    _decode_usb_interface_path,
    project_usb_change,
)
from tests.contracts.test_endpoint_policy_v1 import _policy


NOW = datetime(2026, 9, 25, 12, tzinfo=UTC)
PATH = (
    r"\\?\USB#VID_1234&PID_ABCD#PrivateSerial42"
    r"#{a5dcbf10-6530-11d2-901f-00c04fb951ed}"
)


def _audit_policy() -> EndpointPolicyV1:
    value = _policy()
    value["dlp"] = {**value["dlp"], "usb_device_events": "audit"}
    return EndpointPolicyV1.model_validate(value)


def test_usb_arrival_and_removal_are_typed_and_hash_serial() -> None:
    policy = _audit_policy()
    expected_hash = hashlib.sha256(b"1234:abcd:privateserial42").hexdigest()
    connected = project_usb_change("arrived", PATH, policy, occurred_at=NOW)
    removed = project_usb_change("removed", PATH, policy, occurred_at=NOW)

    assert connected is not None
    assert removed is not None
    assert connected.event_type == "USB_DEVICE_CONNECTED"
    assert removed.event_type == "USB_DEVICE_DISCONNECTED"
    assert connected.safe_metadata.removable is True
    assert connected.safe_metadata.serial_hash == expected_hash
    assert connected.safe_metadata.vendor == "VID_1234"
    assert connected.safe_metadata.product == "PID_ABCD"
    assert connected.policy_id == policy.policy_id
    assert connected.policy_version == policy.policy_version
    assert connected.user_login is None
    assert "PrivateSerial42" not in connected.model_dump_json()
    assert PATH not in connected.model_dump_json()


def test_usb_audit_requires_applied_policy_and_usb_interface() -> None:
    value = _policy()
    value["dlp"] = {**value["dlp"], "usb_device_events": "disabled"}
    disabled = EndpointPolicyV1.model_validate(value)
    assert project_usb_change("arrived", PATH, disabled, occurred_at=NOW) is None
    assert project_usb_change("arrived", PATH, None, occurred_at=NOW) is None
    assert project_usb_change(
        "arrived", r"\\?\HID#VID_1234&PID_ABCD#PrivateSerial42",
        _audit_policy(), occurred_at=NOW,
    ) is None
    assert project_usb_change(
        "arrived", r"\\?\USB#BAD#PrivateSerial42",
        _audit_policy(), occurred_at=NOW,
    ) is None


def test_native_event_data_decoder_is_bounded_and_requires_usb_interface() -> None:
    raw = (0).to_bytes(4, "little") + bytes(20) + (PATH + "\x00").encode("utf-16-le")
    buffer = ctypes.create_string_buffer(raw)
    assert _decode_usb_interface_path(ctypes.addressof(buffer), len(raw)) == PATH
    assert _decode_usb_interface_path(ctypes.addressof(buffer), 23) is None
    assert _decode_usb_interface_path(ctypes.addressof(buffer), 24 + 2049) is None
    wrong_type = ctypes.create_string_buffer((1).to_bytes(4, "little") + raw[4:])
    assert _decode_usb_interface_path(ctypes.addressof(wrong_type), len(raw)) is None


def test_generated_usb_location_is_not_claimed_as_stable_serial() -> None:
    path = PATH.replace("PrivateSerial42", "6&ABCD1234&0&2")
    event = project_usb_change("arrived", path, _audit_policy(), occurred_at=NOW)
    assert event is not None
    assert event.safe_metadata.serial_hash is None


@pytest.mark.skipif(os.name != "nt", reason="CfgMgr32 notifications need Windows")
def test_native_usb_callback_dispatches_off_system_callback_thread() -> None:
    delivered = []
    ready = threading.Event()

    def receive(action: str, path: str) -> None:
        delivered.append((action, path, threading.get_ident()))
        ready.set()

    source = UsbInterfaceNotifications(receive)
    source.start()
    try:
        raw = (0).to_bytes(4, "little") + bytes(20) + (PATH + "\x00").encode("utf-16-le")
        buffer = ctypes.create_string_buffer(raw)
        caller = threading.get_ident()
        assert source._callback is not None
        assert source._callback(None, None, 0, ctypes.addressof(buffer), len(raw)) == 0
        assert ready.wait(2)
        assert len(delivered) == 1
        assert delivered[0][:2] == ("arrived", PATH)
        assert delivered[0][2] != caller
    finally:
        source.stop()
    assert not source.available
    assert source.dropped == 0


@pytest.mark.asyncio
@pytest.mark.skipif(os.name != "nt", reason="USB audit runtime needs Windows")
@pytest.mark.parametrize("source_ok", [True, False])
async def test_agent_accepts_usb_audit_only_with_live_source_and_spools_change(
    monkeypatch, tmp_path, source_ok: bool,
) -> None:
    from pc_agent.platform.windows import activity_api, browser_bridge_entry, usb_sensor
    from pc_agent.policy import windows_sensors
    from pc_agent.runtime import application
    from pc_agent.security.spool import SecurityEventSpool

    data_root = tmp_path / "data"
    data_root.mkdir()
    settings = application.RuntimeSettings(
        data_root=data_root, install_root=tmp_path / "install",
        ca_file=tmp_path / "ca.crt", endpoint_origin="https://endpoint.sosnadmin.local",
        transport_mode="gateway_wss",
    )
    monkeypatch.setattr(application, "AGENT_VERSION", "3.2.70")
    monkeypatch.setattr(browser_bridge_entry, "_extension_id", lambda: "a" * 32)
    monkeypatch.setattr(windows_sensors, "send_policy_request", lambda *_: "EXTERNALLY_MANAGED")

    class Listener:
        def start(self):
            pass

        def stop(self):
            pass

    monkeypatch.setattr(
        activity_api, "create_activity_pipe_listener", lambda **_: Listener(),
    )

    class Source:
        def __init__(self, on_change):
            self.on_change = on_change
            self.available = False

        def start(self):
            if not source_ok:
                raise OSError("no USB notification support")
            self.available = True

        def stop(self):
            self.available = False

    instances = []

    def create_source(on_change):
        instance = Source(on_change)
        instances.append(instance)
        return instance

    monkeypatch.setattr(usb_sensor, "UsbInterfaceNotifications", create_source)
    dependencies = application._default_dependencies(settings)
    local_sensor = dependencies.start_local_sensor(settings)
    assert local_sensor is not None
    await dependencies.restore_policy(settings)
    disabled = _policy()
    disabled["activity"] = {
        "enabled": False, "idle_threshold_seconds": 600,
        "foreground_application": False, "browser_context": False,
    }
    disabled["dlp"] = {
        **disabled["dlp"], "usb_device_events": "audit", "print_events": "disabled",
        "browser_upload_events": "disabled", "browser_paste_events": "disabled",
    }
    disabled["browser_sensor"] = {
        "required": False, "deployment_mode": "external_managed",
    }
    policy = EndpointPolicyV1.model_validate(disabled)
    from endpoint_contracts.endpoint_policy import policy_digest
    from endpoint_contracts.gateway_ws import EndpointPolicyDeliveryV1
    from uuid import uuid4

    delivery = EndpointPolicyDeliveryV1(
        schema_version="endpoint_policy_delivery_v1",
        policy_version_id=uuid4(), policy=policy,
        policy_digest=policy_digest(policy), issued_at=NOW,
    )
    assert dependencies.policy_handler is not None
    try:
        ack = await dependencies.policy_handler(delivery)
        assert ack.status == ("APPLIED" if source_ok else "ERROR")
        if source_ok:
            await asyncio.to_thread(instances[0].on_change, "arrived", PATH)
            spool = SecurityEventSpool(data_root)
            await spool.open()
            batch = await spool.next_batch(now=NOW)
            assert batch is not None
            assert batch.events[0].event_type == "USB_DEVICE_CONNECTED"
            assert batch.events[0].policy_version == policy.policy_version
        else:
            assert ack.error_code == "SENSOR_NOT_READY"
    finally:
        local_sensor.stop()
