"""Native Messaging accepts only bounded, content-free Browser Sensor frames."""

from datetime import UTC, datetime
from io import BytesIO
from struct import pack
from uuid import uuid4
import json

import pytest

from pc_agent.browser_protocol import (
    BrowserProtocolError,
    BrowserProtocolSession,
    BrowserUploadV1,
    decode_native_message,
    encode_native_ack,
)


EXTENSION_ID = "a" * 32
NOW = datetime(2026, 9, 25, tzinfo=UTC).isoformat()


def _frame(message: dict[str, object]) -> BytesIO:
    encoded = json.dumps(message).encode("utf-8")
    return BytesIO(pack("<I", len(encoded)) + encoded)


def _hello() -> dict[str, object]:
    return {
        "schema_version": "browser_sensor_hello_v1", "protocol_version": 1,
        "extension_id": EXTENSION_ID, "extension_version": "0.1.0",
        "browser_family": "yandex", "observed_at": NOW,
    }


def _upload() -> dict[str, object]:
    return {
        "schema_version": "browser_sensor_event_v1", "protocol_version": 1,
        "event_identifier": str(uuid4()), "browser_family": "yandex",
        "destination_origin": "https://example.test", "destination_domain": "example.test",
        "observed_at": NOW, "event_type": "BROWSER_UPLOAD",
        "file_count": 2, "total_bytes": 4096,
        "mime_categories": ["document", "spreadsheet"],
    }


def test_hello_and_upload_require_matching_extension_session() -> None:
    session = BrowserProtocolSession(expected_extension_id=EXTENSION_ID)
    with pytest.raises(BrowserProtocolError):
        session.accept(decode_native_message(_frame(_upload())))
    session.accept(decode_native_message(_frame(_hello())))
    assert isinstance(session.accept(decode_native_message(_frame(_upload()))), BrowserUploadV1)


@pytest.mark.parametrize("change", [
    {"protocol_version": 2}, {"window_title": "secret"},
    {"destination_origin": "https://example.test/private?token=secret"},
    {"destination_domain": "other.test"},
])
def test_bad_upload_is_rejected_before_forwarding(change: dict[str, object]) -> None:
    message = {**_upload(), **change}
    with pytest.raises(BrowserProtocolError):
        decode_native_message(_frame(message))


def test_hello_identity_and_family_cannot_change_mid_stream() -> None:
    session = BrowserProtocolSession(expected_extension_id=EXTENSION_ID)
    wrong = {**_hello(), "extension_id": "b" * 32}
    with pytest.raises(BrowserProtocolError):
        session.accept(decode_native_message(_frame(wrong)))
    session.accept(decode_native_message(_frame(_hello())))
    with pytest.raises(BrowserProtocolError):
        session.accept(decode_native_message(_frame({**_upload(), "browser_family": "chrome"})))


def test_oversized_length_rejected_without_reading_body() -> None:
    class HeaderOnly(BytesIO):
        def read(self, count: int = -1) -> bytes:
            assert count <= 4
            return super().read(count)

    with pytest.raises(BrowserProtocolError, match="too large"):
        decode_native_message(HeaderOnly(pack("<I", 16385)))


def test_partial_or_unknown_frame_is_rejected() -> None:
    with pytest.raises(BrowserProtocolError):
        decode_native_message(BytesIO(pack("<I", 8) + b"{}"))
    with pytest.raises(BrowserProtocolError):
        decode_native_message(_frame({"schema_version": "unknown_v1"}))


def test_wrong_version_and_duplicate_keys_fail_closed() -> None:
    with pytest.raises(BrowserProtocolError) as rejected:
        decode_native_message(_frame({**_hello(), "protocol_version": 2}))
    assert rejected.value.code == "UNSUPPORTED_VERSION"
    body = b'{"schema_version":"browser_sensor_hello_v1","schema_version":"browser_sensor_hello_v1"}'
    with pytest.raises(BrowserProtocolError) as duplicate:
        decode_native_message(BytesIO(pack("<I", len(body)) + body))
    assert duplicate.value.code == "INVALID_MESSAGE"


def test_bounded_ack_never_echoes_source_payload() -> None:
    encoded = encode_native_ack(accepted=False, error_code="INVALID_MESSAGE")
    length = int.from_bytes(encoded[:4], "little")
    assert length == len(encoded) - 4
    assert length < 1024
    assert b"SECRET_MARKER_7348" not in encoded


def test_heartbeat_accepts_only_bounded_self_install_type() -> None:
    heartbeat = {
        "schema_version": "browser_sensor_heartbeat_v1", "protocol_version": 1,
        "extension_version": "0.1.0", "browser_family": "chrome", "observed_at": NOW,
        "install_type": "admin",
    }
    accepted = decode_native_message(_frame(heartbeat))
    assert accepted.install_type == "admin"
    legacy_heartbeat = {key: value for key, value in heartbeat.items() if key != "install_type"}
    assert decode_native_message(_frame(legacy_heartbeat)).install_type == "unknown"
    with pytest.raises(BrowserProtocolError):
        decode_native_message(_frame({**heartbeat, "install_type": "policy-private-value"}))
