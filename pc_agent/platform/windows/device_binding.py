"""Ephemeral possession proof exchanged over the existing protected local IPC."""
from datetime import UTC, datetime, timedelta
import json
import time
from threading import Event

from pydantic import ValidationError
from endpoint_contracts.device_binding import DeviceBindingChallengeV1
from .local_ipc import authorize_pipe_client, connect_client_pipe, LocalIpcRejected

PIPE_NAME = r"\\.\pipe\EndpointPlatform.Agent.DeviceBinding.v1"
MAX_CHALLENGE_BYTES = 2048
DEFAULT_BINDING_ORIGIN = "https://helpdesk.sosnadmin.local"
BINDING_ORIGINS = (DEFAULT_BINDING_ORIGIN, "https://helpdesk-staging.sosnadmin.local")


class BindingUnavailable(RuntimeError):
    def __init__(self):
        super().__init__("Device binding unavailable")


def parse_challenge(payload: object) -> DeviceBindingChallengeV1:
    try:
        challenge = DeviceBindingChallengeV1.model_validate(payload)
    except (ValidationError, ValueError, TypeError):
        raise BindingUnavailable() from None
    now = datetime.now(UTC)
    if (challenge.display_code != challenge.code[:3]+"-"+challenge.code[3:]
        or not now < challenge.expires_at <= now+timedelta(seconds=605)):
        raise BindingUnavailable()
    return challenge


def helpdesk_link(challenge: DeviceBindingChallengeV1, *, origin: str = DEFAULT_BINDING_ORIGIN) -> str:
    if origin not in BINDING_ORIGINS or challenge.expires_at <= datetime.now(UTC):
        raise BindingUnavailable()
    return origin+"/app/requester/devices/link#code="+challenge.code


def tray_binding_origin() -> str:
    """An explicit operator flag enables staging acceptance without changing DNS."""
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--helpdesk-origin", dest="binding_origin", choices=BINDING_ORIGINS, default=DEFAULT_BINDING_ORIGIN)
    return parser.parse_args().binding_origin


class BindingPipeHandler:
    def __init__(self, issue, *, authorize=authorize_pipe_client):
        self._issue = issue
        self._authorize = authorize

    def handle(self, pipe, payload: bytes) -> bytes:
        self._authorize(pipe)  # OS-backed interactive identity before any device request.
        try:
            if len(payload) > 128 or json.loads(payload) != {"action":"create"}:
                raise BindingUnavailable()
            challenge = parse_challenge(self._issue())
            return challenge.model_dump_json().encode("utf-8")
        except Exception:
            # No exception contents, credentials, code or inventory are projected.
            return b'{"error":"binding_unavailable"}'


def request_challenge_from_service(*, stop: Event | None = None) -> DeviceBindingChallengeV1:
    from .sensor_pipe_listener import _read_frame, _write_frame
    import win32file
    stop = stop if stop is not None else Event()
    if stop.is_set():
        raise BindingUnavailable()
    handle = None
    try:
        handle = connect_client_pipe(pipe_name=PIPE_NAME, overlapped=True)
        deadline = time.monotonic()+5
        _write_frame(handle, b'{"action":"create"}', stop, deadline)
        response = _read_frame(handle, stop, deadline)
        if len(response) > MAX_CHALLENGE_BYTES:
            raise BindingUnavailable()
        return parse_challenge(json.loads(response))
    except (OSError, LocalIpcRejected, ValueError):
        raise BindingUnavailable() from None
    finally:
        if handle is not None:
            win32file.CloseHandle(handle)
