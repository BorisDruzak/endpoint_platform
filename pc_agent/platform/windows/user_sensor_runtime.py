"""Credential-free, per-session Windows sensor process.

Only the LocalService Agent receives user observations. The interactive process
has no Gateway transport, endpoint address or device credential.
"""

from __future__ import annotations

import ctypes
import os
from collections.abc import Callable
from ctypes import wintypes
from threading import Event

from pydantic import ValidationError

from pc_agent.browser_protocol import BrowserBridgeAckV1

from .local_ipc import (
    LocalIpcRejected, connect_client_pipe, read_pipe_frame, write_pipe_frame,
)
from .local_sensor_protocol import LocalUserSessionEnvelopeV1, serialize_local_sensor_payload
from .user_sensor import SessionProbe, UserSessionSampleV1, WindowsSessionProbe, sample_user_session


SAMPLE_INTERVAL_SECONDS = 15.0
_ERROR_ALREADY_EXISTS = 183
_SESSION_MUTEX = r"Local\EndpointUserSensor"


def close_pipe(handle: object) -> None:
    import win32file

    win32file.CloseHandle(handle)


def send_user_sample(sample: UserSessionSampleV1) -> BrowserBridgeAckV1:
    """Send one bounded frame through a mutually authenticated local pipe."""
    envelope = LocalUserSessionEnvelopeV1(
        schema_version="local_sensor_envelope_v1", source="user_session", sample=sample,
    )
    payload = serialize_local_sensor_payload(envelope)
    handle = connect_client_pipe()
    try:
        write_pipe_frame(handle, payload)
        return BrowserBridgeAckV1.model_validate_json(read_pipe_frame(handle))
    finally:
        close_pipe(handle)


def run_user_sensor(
    probe: SessionProbe,
    *,
    send: Callable[[UserSessionSampleV1], object] = send_user_sample,
    wait: Callable[[float], bool],
) -> None:
    """Keep sampling after transient pipe/service failures until logoff or stop."""
    try:
        import pywintypes

        win32_error = pywintypes.error
    except ImportError:
        win32_error = OSError
    while True:
        sample = sample_user_session(probe)
        try:
            send(sample)
        except (OSError, LocalIpcRejected, ValidationError, win32_error):
            pass
        if wait(SAMPLE_INTERVAL_SECONDS):
            return


def _acquire_session_mutex() -> tuple[object, Callable[[object], None]] | None:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create = kernel32.CreateMutexW
    create.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
    create.restype = wintypes.HANDLE
    close = kernel32.CloseHandle
    close.argtypes = [wintypes.HANDLE]
    close.restype = wintypes.BOOL
    handle = create(None, False, _SESSION_MUTEX)
    if not handle:
        raise OSError(ctypes.get_last_error(), "cannot acquire user sensor mutex")
    if ctypes.get_last_error() == _ERROR_ALREADY_EXISTS:
        close(handle)
        return None
    return handle, close


def main() -> int:
    if os.name != "nt":
        return 1
    mutex = _acquire_session_mutex()
    if mutex is None:
        return 0
    handle, close = mutex
    try:
        run_user_sensor(WindowsSessionProbe(), wait=Event().wait)
    except KeyboardInterrupt:
        return 0
    finally:
        close(handle)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
