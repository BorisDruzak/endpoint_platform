"""One cancellable, bounded Windows pipe listener for local sensor frames."""

from __future__ import annotations

import struct
import time
from collections.abc import Callable
from threading import Event, Thread

from .local_ipc import LocalIpcRejected, MAX_IPC_MESSAGE_BYTES, PIPE_NAME, create_server_pipe


_POLL_MS = 100


def _overlapped_result(
    handle: object, overlapped: object, *, pending: bool,
    stop: Event, deadline: float | None,
) -> int:
    import pywintypes
    import win32event
    import win32file

    if not pending:
        return win32file.GetOverlappedResult(handle, overlapped, False)
    while True:
        remaining = None if deadline is None else deadline - time.monotonic()
        if stop.is_set() or (remaining is not None and remaining <= 0):
            try:
                # The listener owns this I/O thread; CancelIo targets its own request.
                win32file.CancelIo(handle)
            except pywintypes.error:
                pass
            try:
                win32file.GetOverlappedResult(handle, overlapped, True)
            except pywintypes.error:
                pass
            raise LocalIpcRejected("local IPC operation stopped or timed out")
        wait_ms = _POLL_MS if remaining is None else max(1, min(_POLL_MS, int(remaining * 1000)))
        result = win32event.WaitForSingleObject(overlapped.hEvent, wait_ms)
        if result == win32event.WAIT_OBJECT_0:
            return win32file.GetOverlappedResult(handle, overlapped, False)
        if result != win32event.WAIT_TIMEOUT:
            raise LocalIpcRejected("local IPC event wait failed")


def _new_overlapped():
    import pywintypes
    import win32event

    overlapped = pywintypes.OVERLAPPED()
    overlapped.hEvent = win32event.CreateEvent(None, True, False, None)
    return overlapped


def _connect(handle: object, stop: Event) -> bool:
    import winerror
    import win32file
    import win32pipe

    overlapped = _new_overlapped()
    try:
        code = win32pipe.ConnectNamedPipe(handle, overlapped)
        if code == winerror.ERROR_PIPE_CONNECTED:
            return True
        if code not in (0, winerror.ERROR_IO_PENDING):
            raise LocalIpcRejected("local IPC connection failed")
        _overlapped_result(
            handle, overlapped, pending=code == winerror.ERROR_IO_PENDING,
            stop=stop, deadline=None,
        )
        return True
    except LocalIpcRejected:
        if stop.is_set():
            return False
        raise
    finally:
        win32file.CloseHandle(overlapped.hEvent)


def _read_exact(handle: object, count: int, stop: Event, deadline: float) -> bytes:
    import winerror
    import win32file

    received = bytearray()
    while len(received) < count:
        overlapped = _new_overlapped()
        try:
            code, buffer = win32file.ReadFile(handle, count - len(received), overlapped)
            if code not in (0, winerror.ERROR_IO_PENDING):
                raise LocalIpcRejected("local IPC read failed")
            size = _overlapped_result(
                handle, overlapped, pending=code == winerror.ERROR_IO_PENDING,
                stop=stop, deadline=deadline,
            )
            if size <= 0:
                raise LocalIpcRejected("incomplete local IPC frame")
            received.extend(bytes(buffer)[:size])
        finally:
            win32file.CloseHandle(overlapped.hEvent)
    return bytes(received)


def _read_frame(handle: object, stop: Event, deadline: float) -> bytes:
    size = struct.unpack("<I", _read_exact(handle, 4, stop, deadline))[0]
    if not 1 <= size <= MAX_IPC_MESSAGE_BYTES:
        raise LocalIpcRejected("invalid local IPC frame size")
    return _read_exact(handle, size, stop, deadline)


def _write_frame(handle: object, payload: bytes, stop: Event, deadline: float) -> None:
    import winerror
    import win32file

    if not isinstance(payload, bytes) or not 1 <= len(payload) <= MAX_IPC_MESSAGE_BYTES:
        raise LocalIpcRejected("invalid local IPC reply size")
    data = struct.pack("<I", len(payload)) + payload
    sent = 0
    while sent < len(data):
        overlapped = _new_overlapped()
        try:
            code, _count = win32file.WriteFile(handle, data[sent:], overlapped)
            if code not in (0, winerror.ERROR_IO_PENDING):
                raise LocalIpcRejected("local IPC write failed")
            size = _overlapped_result(
                handle, overlapped, pending=code == winerror.ERROR_IO_PENDING,
                stop=stop, deadline=deadline,
            )
            if size <= 0:
                raise LocalIpcRejected("incomplete local IPC write")
            sent += size
        finally:
            win32file.CloseHandle(overlapped.hEvent)


class LocalSensorPipeListener:
    """Serve one connection at a time; stop even when a client never writes."""

    def __init__(
        self,
        on_frame: Callable[[object, bytes], bytes | None],
        *,
        pipe_name: str = PIPE_NAME,
        frame_timeout_seconds: float = 5.0,
        server_factory: Callable[[], object] | None = None,
    ) -> None:
        if not 0.05 <= frame_timeout_seconds <= 30:
            raise ValueError("invalid local IPC frame timeout")
        self._on_frame = on_frame
        self._pipe_name = pipe_name
        self._server_factory = server_factory or (
            lambda: create_server_pipe(pipe_name=self._pipe_name, overlapped=True)
        )
        self._frame_timeout = frame_timeout_seconds
        self._stop = Event()
        self._thread: Thread | None = None

    def start(self) -> None:
        if self._thread is not None:
            raise RuntimeError("local IPC listener already started")
        pipe = self._server_factory()
        self._thread = Thread(target=self._run, args=(pipe,), name="EndpointSensorPipe", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        thread = self._thread
        if thread is None:
            return
        self._stop.set()
        thread.join(timeout=3)
        if thread.is_alive():
            raise TimeoutError("local IPC listener did not stop")
        self._thread = None

    def _run(self, pipe: object) -> None:
        import pywintypes
        import win32file
        import win32pipe

        try:
            while not self._stop.is_set():
                try:
                    if not _connect(pipe, self._stop):
                        break
                    deadline = time.monotonic() + self._frame_timeout
                    payload = _read_frame(pipe, self._stop, deadline)
                    reply = self._on_frame(pipe, payload)
                    if reply is not None:
                        _write_frame(
                            pipe, reply, self._stop,
                            time.monotonic() + self._frame_timeout,
                        )
                        # DisconnectNamedPipe discards unread reply bytes. Wait for
                        # client close (or a bounded timeout) before disconnecting.
                        _read_exact(
                            pipe, 1, self._stop,
                            time.monotonic() + self._frame_timeout,
                        )
                except (LocalIpcRejected, pywintypes.error):
                    pass  # A malformed, idle or disconnected client cannot stop the listener.
                finally:
                    try:
                        win32pipe.DisconnectNamedPipe(pipe)
                    except pywintypes.error:
                        pass
        finally:
            win32file.CloseHandle(pipe)
