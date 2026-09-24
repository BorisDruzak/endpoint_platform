"""A stalled interactive pipe client cannot pin the Agent listener at shutdown."""

import os
import threading
import time
from uuid import uuid4

import pytest

from pc_agent.platform.windows.local_ipc import (
    CLIENT_ACCESS_MASK, PIPE_NAME, read_pipe_frame, write_pipe_frame,
)


@pytest.mark.skipif(os.name != "nt", reason="Windows named pipe")
def test_listener_processes_frame_then_stops_with_stalled_client() -> None:
    from pc_agent.platform.windows.sensor_pipe_listener import LocalSensorPipeListener

    import win32con
    import win32file
    import win32pipe

    pipe_name = f"{PIPE_NAME}.test.{uuid4().hex}"
    received: list[bytes] = []
    listener = LocalSensorPipeListener(
        lambda _pipe, payload: received.append(payload) or b"accepted",
        pipe_name=pipe_name,
        frame_timeout_seconds=10,
    )
    listener.start()
    try:
        response: list[bytes] = []
        failures: list[BaseException] = []

        def exchange() -> None:
            try:
                win32pipe.WaitNamedPipe(pipe_name, 2000)
                handle = win32file.CreateFile(
                    pipe_name, CLIENT_ACCESS_MASK, 0, None, win32con.OPEN_EXISTING, 0, None,
                )
                try:
                    write_pipe_frame(handle, b"hello")
                    response.append(read_pipe_frame(handle))
                finally:
                    win32file.CloseHandle(handle)
            except BaseException as error:
                failures.append(error)

        client = threading.Thread(target=exchange, daemon=True)
        client.start()
        client.join(timeout=3)
        assert not client.is_alive()
        assert not failures
        assert response == [b"accepted"]
        assert received == [b"hello"]

        win32pipe.WaitNamedPipe(pipe_name, 2000)
        stalled = win32file.CreateFile(
            pipe_name, CLIENT_ACCESS_MASK, 0, None, win32con.OPEN_EXISTING, 0, None,
        )
        try:
            started = time.monotonic()
            listener.stop()
            assert time.monotonic() - started < 2
        finally:
            win32file.CloseHandle(stalled)
    finally:
        listener.stop()


@pytest.mark.skipif(os.name != "nt", reason="Windows named pipe")
def test_listener_rejects_idle_client_then_accepts_next_frame() -> None:
    from pc_agent.platform.windows.sensor_pipe_listener import LocalSensorPipeListener

    import win32con
    import win32file
    import win32pipe

    pipe_name = f"{PIPE_NAME}.test.{uuid4().hex}"
    received: list[bytes] = []
    listener = LocalSensorPipeListener(
        lambda _pipe, payload: received.append(payload) or b"ok",
        pipe_name=pipe_name,
        frame_timeout_seconds=0.15,
    )
    listener.start()
    try:
        win32pipe.WaitNamedPipe(pipe_name, 2000)
        stalled = win32file.CreateFile(
            pipe_name, CLIENT_ACCESS_MASK, 0, None, win32con.OPEN_EXISTING, 0, None,
        )
        try:
            time.sleep(0.3)
        finally:
            win32file.CloseHandle(stalled)

        response: list[bytes] = []
        failures: list[BaseException] = []

        def exchange() -> None:
            try:
                win32pipe.WaitNamedPipe(pipe_name, 2000)
                handle = win32file.CreateFile(
                    pipe_name, CLIENT_ACCESS_MASK, 0, None, win32con.OPEN_EXISTING, 0, None,
                )
                try:
                    write_pipe_frame(handle, b"next")
                    response.append(read_pipe_frame(handle))
                finally:
                    win32file.CloseHandle(handle)
            except BaseException as error:
                failures.append(error)

        client = threading.Thread(target=exchange, daemon=True)
        client.start()
        client.join(timeout=3)
        assert not client.is_alive()
        assert not failures
        assert response == [b"ok"]
        assert received == [b"next"]
    finally:
        listener.stop()
