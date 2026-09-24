"""Credential-free Chromium Native Messaging host for the Endpoint Browser Sensor.

The host has no network client. Its only output is a bounded framed ACK; the
service pipe authenticates the Agent before any validated observation is sent.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import BinaryIO
import re

from pc_agent.browser_protocol import (
    BrowserBridgeAckV1,
    BrowserProtocolError,
    BrowserProtocolSession,
    decode_native_message,
    encode_native_ack,
)

from .local_ipc import connect_client_pipe, read_pipe_frame, write_pipe_frame
from .local_sensor_protocol import (
    LocalBrowserEnvelopeV1, LocalSensorProtocolError, serialize_local_sensor_payload,
)


_PARENT_WINDOW = re.compile(r"--parent-window=[0-9]{1,20}\Z", re.ASCII)
ForwardMessage = Callable[[LocalBrowserEnvelopeV1], BrowserBridgeAckV1]


class BrowserBridgeInvocationError(ValueError):
    """Chromium did not launch this host for the pinned extension origin."""


def validate_native_invocation(arguments: Sequence[str], *, expected_extension_id: str) -> None:
    """Require the exact extension origin and only Chromium's window hint."""
    BrowserProtocolSession(expected_extension_id=expected_extension_id)
    origin = f"chrome-extension://{expected_extension_id}"
    if not 1 <= len(arguments) <= 2 or arguments[0] not in (origin, origin + "/"):
        raise BrowserBridgeInvocationError("unapproved native messaging origin")
    if len(arguments) == 2 and not _PARENT_WINDOW.fullmatch(arguments[1]):
        raise BrowserBridgeInvocationError("invalid native messaging launch arguments")


def forward_to_agent(envelope: LocalBrowserEnvelopeV1) -> BrowserBridgeAckV1:
    """Use a fresh, mutually checked local pipe for one typed observation."""
    import win32file

    handle = connect_client_pipe()
    try:
        write_pipe_frame(handle, serialize_local_sensor_payload(envelope))
        return BrowserBridgeAckV1.model_validate_json(read_pipe_frame(handle))
    finally:
        win32file.CloseHandle(handle)


def run_native_bridge(
    *,
    stdin: BinaryIO,
    stdout: BinaryIO,
    arguments: Sequence[str],
    expected_extension_id: str,
    forward: ForwardMessage = forward_to_agent,
) -> None:
    """Process one Chromium port stream without logging or echoing browser data."""
    validate_native_invocation(arguments, expected_extension_id=expected_extension_id)
    session = BrowserProtocolSession(expected_extension_id=expected_extension_id)
    while True:
        try:
            message = decode_native_message(stdin)
            if message is None:
                return
            checked = session.accept(message)
            envelope = LocalBrowserEnvelopeV1(
                schema_version="local_sensor_envelope_v1", source="browser",
                extension_id=expected_extension_id, message=checked,
            )
        except BrowserProtocolError as error:
            stdout.write(encode_native_ack(accepted=False, error_code=error.code))
            stdout.flush()
            return
        try:
            reply = forward(envelope)
            if not isinstance(reply, BrowserBridgeAckV1):
                raise TypeError("invalid local IPC acknowledgement")
        except LocalSensorProtocolError as error:
            reply = BrowserBridgeAckV1(
                schema_version="browser_bridge_ack_v1", accepted=False,
                error_code=error.code,
            )
        except Exception:
            reply = BrowserBridgeAckV1(
                schema_version="browser_bridge_ack_v1", accepted=False,
                error_code="IPC_UNAVAILABLE",
            )
        stdout.write(encode_native_ack(accepted=reply.accepted, error_code=reply.error_code))
        stdout.flush()
