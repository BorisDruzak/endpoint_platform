"""The service accepts only typed and bounded sensor-to-Agent envelopes."""

from datetime import UTC, datetime
import json

import pytest

from pc_agent.browser_protocol import BrowserHelloV1
from pc_agent.platform.windows.local_sensor_protocol import (
    LocalBrowserEnvelopeV1,
    LocalSensorProtocolError,
    LocalUserSessionEnvelopeV1,
    parse_local_sensor_payload,
    serialize_local_sensor_payload,
)
from pc_agent.platform.windows.user_sensor import UserSessionSampleV1


EXTENSION_ID = "a" * 32


def browser_envelope() -> LocalBrowserEnvelopeV1:
    return LocalBrowserEnvelopeV1(
        schema_version="local_sensor_envelope_v1", source="browser",
        extension_id=EXTENSION_ID,
        message=BrowserHelloV1(
            schema_version="browser_sensor_hello_v1", protocol_version=1,
            extension_id=EXTENSION_ID, extension_version="0.1.0",
            browser_family="chrome", observed_at=datetime(2026, 9, 25, tzinfo=UTC),
        ),
    )


def test_browser_envelope_roundtrip_is_typed() -> None:
    encoded = serialize_local_sensor_payload(browser_envelope())
    parsed = parse_local_sensor_payload(encoded)
    assert isinstance(parsed, LocalBrowserEnvelopeV1)
    assert isinstance(parsed.message, BrowserHelloV1)


def test_user_session_envelope_roundtrip_is_typed() -> None:
    message = LocalUserSessionEnvelopeV1(
        schema_version="local_sensor_envelope_v1", source="user_session",
        sample=UserSessionSampleV1(
            schema_version="user_session_sample_v1", desktop_state="UNLOCKED",
            idle_seconds=7,
        ),
    )
    assert parse_local_sensor_payload(serialize_local_sensor_payload(message)) == message


@pytest.mark.parametrize("mutation", [
    {"executable_path": "C:/Secret/program.exe"},
    {"source": "shell"},
    {"extension_id": "*"},
])
def test_extra_or_unapproved_browser_envelope_fields_fail(mutation) -> None:
    body = {**browser_envelope().model_dump(mode="json"), **mutation}
    with pytest.raises(LocalSensorProtocolError):
        parse_local_sensor_payload(json.dumps(body).encode("utf-8"))


def test_duplicate_keys_and_oversized_body_fail_before_projection() -> None:
    with pytest.raises(LocalSensorProtocolError):
        parse_local_sensor_payload(b'{"source":"browser","source":"user_session"}')
    with pytest.raises(LocalSensorProtocolError):
        parse_local_sensor_payload(b"x" * 16385)
