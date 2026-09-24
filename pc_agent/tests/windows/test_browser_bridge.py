"""The native host validates browser origin and forwards only typed frames."""

from datetime import UTC, datetime
from io import BytesIO
import json
import struct
import sys
from types import SimpleNamespace

import pytest

from pc_agent.browser_protocol import BrowserBridgeAckV1, BrowserHelloV1
from pc_agent.platform.windows import browser_bridge
from pc_agent.platform.windows.browser_bridge import (
    BrowserBridgeInvocationError,
    forward_to_agent,
    run_native_bridge,
    validate_native_invocation,
)
from pc_agent.platform.windows.local_sensor_protocol import (
    LocalBrowserEnvelopeV1, LocalSensorProtocolError,
)


EXTENSION_ID = "a" * 32
ORIGIN = f"chrome-extension://{EXTENSION_ID}/"
NOW = datetime(2026, 9, 25, tzinfo=UTC).isoformat()


def frame(payload: dict[str, object]) -> bytes:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return struct.pack("<I", len(body)) + body


def hello() -> dict[str, object]:
    return {
        "schema_version": "browser_sensor_hello_v1", "protocol_version": 1,
        "extension_id": EXTENSION_ID, "extension_version": "0.1.0",
        "browser_family": "chrome", "observed_at": NOW,
    }


def heartbeat() -> dict[str, object]:
    return {
        "schema_version": "browser_sensor_heartbeat_v1", "protocol_version": 1,
        "extension_version": "0.1.0", "browser_family": "chrome", "observed_at": NOW,
    }


def read_acks(data: bytes) -> list[BrowserBridgeAckV1]:
    stream = BytesIO(data)
    result = []
    while length := stream.read(4):
        body = stream.read(struct.unpack("<I", length)[0])
        result.append(BrowserBridgeAckV1.model_validate_json(body))
    return result


@pytest.mark.parametrize("arguments", [
    [], ["chrome-extension://" + "b" * 32 + "/"],
    ["https://example.test/"], [ORIGIN, "--parent-window=12", "--unexpected"],
    [ORIGIN, "--parent-window=not-a-number"],
])
def test_native_invocation_rejects_unpinned_origin_or_extra_arguments(arguments) -> None:
    with pytest.raises(BrowserBridgeInvocationError):
        validate_native_invocation(arguments, expected_extension_id=EXTENSION_ID)


def test_valid_native_invocation_accepts_chromium_window_hint() -> None:
    validate_native_invocation([ORIGIN, "--parent-window=0"], expected_extension_id=EXTENSION_ID)
    validate_native_invocation([ORIGIN], expected_extension_id=EXTENSION_ID)


def test_hello_and_heartbeat_forward_as_typed_messages_only() -> None:
    sent: list[LocalBrowserEnvelopeV1] = []
    stdout = BytesIO()
    run_native_bridge(
        stdin=BytesIO(frame(hello()) + frame(heartbeat())), stdout=stdout,
        arguments=[ORIGIN, "--parent-window=0"], expected_extension_id=EXTENSION_ID,
        forward=lambda message: sent.append(message) or BrowserBridgeAckV1(
            schema_version="browser_bridge_ack_v1", accepted=True, error_code="OK",
        ),
    )
    assert [envelope.message.schema_version for envelope in sent] == [
        "browser_sensor_hello_v1", "browser_sensor_heartbeat_v1",
    ]
    assert all(envelope.extension_id == EXTENSION_ID for envelope in sent)
    assert [reply.accepted for reply in read_acks(stdout.getvalue())] == [True, True]


def test_unknown_fields_do_not_reach_ipc_and_ack_is_bounded() -> None:
    sent: list[LocalBrowserEnvelopeV1] = []
    stdout = BytesIO()
    run_native_bridge(
        stdin=BytesIO(frame({**hello(), "secret_content": "SECRET_MARKER_7348"})),
        stdout=stdout, arguments=[ORIGIN], expected_extension_id=EXTENSION_ID,
        forward=lambda message: sent.append(message),
    )
    assert sent == []
    assert read_acks(stdout.getvalue())[0].error_code == "INVALID_MESSAGE"
    assert b"SECRET_MARKER_7348" not in stdout.getvalue()


def test_ipc_failure_is_reported_without_claiming_delivery() -> None:
    def unavailable(_message: LocalBrowserEnvelopeV1) -> BrowserBridgeAckV1:
        raise OSError("secret-local-path")

    stdout = BytesIO()
    run_native_bridge(
        stdin=BytesIO(frame(hello())), stdout=stdout,
        arguments=[ORIGIN], expected_extension_id=EXTENSION_ID, forward=unavailable,
    )
    assert read_acks(stdout.getvalue())[0].error_code == "IPC_UNAVAILABLE"
    assert b"secret-local-path" not in stdout.getvalue()


def test_local_envelope_oversize_is_reported_as_oversize() -> None:
    stdout = BytesIO()
    def oversized(_message: LocalBrowserEnvelopeV1) -> BrowserBridgeAckV1:
        raise LocalSensorProtocolError("OVERSIZE")

    run_native_bridge(
        stdin=BytesIO(frame(hello())), stdout=stdout,
        arguments=[ORIGIN], expected_extension_id=EXTENSION_ID, forward=oversized,
    )
    assert read_acks(stdout.getvalue())[0].error_code == "OVERSIZE"


def test_oversized_header_stops_stream_before_reading_body() -> None:
    class HeaderOnly(BytesIO):
        def read(self, count: int = -1) -> bytes:
            assert count <= 4
            return super().read(count)

    stdout = BytesIO()
    run_native_bridge(
        stdin=HeaderOnly(struct.pack("<I", 16385)), stdout=stdout,
        arguments=[ORIGIN], expected_extension_id=EXTENSION_ID,
        forward=lambda _message: pytest.fail("oversized message reached IPC"),
    )
    assert read_acks(stdout.getvalue())[0].error_code == "OVERSIZE"


def test_forward_to_agent_sends_typed_json_and_requires_typed_ack(monkeypatch) -> None:
    handle = object()
    written: list[bytes] = []
    closed: list[object] = []
    monkeypatch.setitem(sys.modules, "win32file", SimpleNamespace(CloseHandle=closed.append))
    monkeypatch.setattr(browser_bridge, "connect_client_pipe", lambda: handle)
    monkeypatch.setattr(browser_bridge, "write_pipe_frame", lambda _handle, data: written.append(data))
    monkeypatch.setattr(browser_bridge, "read_pipe_frame", lambda _handle: b'{"schema_version":"browser_bridge_ack_v1","accepted":true,"error_code":"OK"}')
    message = LocalBrowserEnvelopeV1(
        schema_version="local_sensor_envelope_v1", source="browser",
        extension_id=EXTENSION_ID, message=BrowserHelloV1.model_validate(hello()),
    )

    assert forward_to_agent(message).accepted
    assert json.loads(written[0]) == message.model_dump(mode="json")
    assert closed == [handle]

    monkeypatch.setattr(browser_bridge, "read_pipe_frame", lambda _handle: b'{"schema_version":"browser_bridge_ack_v1","accepted":true,"error_code":"OK","extra":"secret"}')
    with pytest.raises(ValueError):
        forward_to_agent(message)
    assert closed == [handle, handle]
