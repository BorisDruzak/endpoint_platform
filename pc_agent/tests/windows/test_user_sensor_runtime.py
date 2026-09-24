"""The interactive sensor retries local delivery without device credentials."""

from __future__ import annotations

from pc_agent.platform.windows.local_sensor_protocol import (
    LocalUserSessionEnvelopeV1,
    parse_local_sensor_payload,
)
from pc_agent.platform.windows.user_sensor import UserSessionSampleV1
from pc_agent.platform.windows.user_sensor_runtime import run_user_sensor, send_user_sample


class Probe:
    def session_connected(self) -> bool:
        return True

    def input_desktop_name(self) -> str:
        return "Default"

    def tick_count_ms(self) -> int:
        return 100_000

    def last_input_ms(self) -> int:
        return 95_000

    def foreground_process_name(self) -> str:
        return "chrome.exe"


def test_sensor_retries_after_pipe_failure_without_losing_next_sample() -> None:
    sent: list[UserSessionSampleV1] = []
    intervals: list[float] = []

    def send(sample: UserSessionSampleV1) -> None:
        sent.append(sample)
        if len(sent) == 1:
            raise OSError("service unavailable")

    def wait(interval: float) -> bool:
        intervals.append(interval)
        return len(sent) == 2

    run_user_sensor(Probe(), send=send, wait=wait)

    assert len(sent) == 2
    assert all(sample.desktop_state == "UNLOCKED" for sample in sent)
    assert intervals == [15.0, 15.0]


def test_sensor_retries_win32_pipe_error() -> None:
    import pytest

    pywintypes = pytest.importorskip("pywintypes")

    attempts = 0

    def send(_sample: UserSessionSampleV1) -> None:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise pywintypes.error(2, "CreateFile", "pipe unavailable")

    run_user_sensor(Probe(), send=send, wait=lambda _interval: attempts == 2)

    assert attempts == 2


def test_user_sample_sends_one_typed_frame_and_validates_ack(monkeypatch) -> None:
    handle = object()
    events: list[str] = []
    payloads: list[bytes] = []
    monkeypatch.setitem(send_user_sample.__globals__, "connect_client_pipe", lambda: handle)
    monkeypatch.setitem(send_user_sample.__globals__, "write_pipe_frame", lambda h, p: payloads.append(p))
    monkeypatch.setitem(send_user_sample.__globals__, "read_pipe_frame", lambda h: (
        b'{"schema_version":"browser_bridge_ack_v1","accepted":true,"error_code":"OK"}'
    ))
    monkeypatch.setitem(send_user_sample.__globals__, "close_pipe", lambda h: events.append("closed"))

    reply = send_user_sample(UserSessionSampleV1(
        schema_version="user_session_sample_v1", desktop_state="UNLOCKED", idle_seconds=5,
    ))

    assert reply.accepted
    assert events == ["closed"]
    envelope = parse_local_sensor_payload(payloads[0])
    assert isinstance(envelope, LocalUserSessionEnvelopeV1)
    assert envelope.sample.idle_seconds == 5


def test_user_sample_closes_pipe_when_ack_is_invalid(monkeypatch) -> None:
    import pytest
    from pydantic import ValidationError

    events: list[str] = []
    monkeypatch.setitem(send_user_sample.__globals__, "connect_client_pipe", object)
    monkeypatch.setitem(send_user_sample.__globals__, "write_pipe_frame", lambda *_: None)
    monkeypatch.setitem(send_user_sample.__globals__, "read_pipe_frame", lambda *_: b'{"accepted":true}')
    monkeypatch.setitem(send_user_sample.__globals__, "close_pipe", lambda *_: events.append("closed"))

    with pytest.raises(ValidationError):
        send_user_sample(UserSessionSampleV1(
            schema_version="user_session_sample_v1", desktop_state="LOCKED",
        ))
    assert events == ["closed"]
