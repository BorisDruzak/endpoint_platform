"""Per-user sampler with no server transport, device identity or credential access."""
from __future__ import annotations

import asyncio
from contextlib import suppress
import os
from pathlib import Path
import signal
import stat
import json
import sys

from pc_agent.version import AGENT_VERSION

from pc_agent.browser_protocol import BrowserBridgeAckV1
from pc_agent.local_sensor_protocol import LocalUserSessionEnvelopeV1, serialize_local_sensor_payload
from .local_ipc import authorize_peer, exchange, pid_session_id
from .sessions import list_sessions
from .user_sensor import sample_record

PROBE_PATH = Path('/usr/lib/endpoint-agent/endpoint-kde-probe')


def own_session():
    try:
        return authorize_peer(os.getpid(), os.getuid(), sessions=list_sessions(),
                              pid_session=pid_session_id(os.getpid()),
                              login_resolver=lambda *_args: None).session
    except (OSError, ValueError):
        return None


def send_user_sample(sample) -> BrowserBridgeAckV1:
    envelope = LocalUserSessionEnvelopeV1(schema_version='local_sensor_envelope_v1', source='user_session', sample=sample)
    return BrowserBridgeAckV1.model_validate_json(exchange(serialize_local_sensor_payload(envelope)))


async def _stop_probe(probe):
    if probe.stdin is not None:
        probe.stdin.close()  # Gracefully unload our ephemeral KWin script.
    try:
        await asyncio.wait_for(probe.wait(), 3)
    except TimeoutError:
        probe.kill()
        await probe.wait()


async def _next_record(probe, stop: asyncio.Event):
    reading = asyncio.create_task(asyncio.wait_for(probe.stdout.readline(), 8))
    stopping = asyncio.create_task(stop.wait())
    try:
        await asyncio.wait({reading, stopping}, return_when=asyncio.FIRST_COMPLETED)
        if stopping.done():
            return None
        return await reading
    finally:
        for task in (reading, stopping):
            task.cancel()
        await asyncio.gather(reading, stopping, return_exceptions=True)


async def run_user_sensor(*, stop: asyncio.Event, probe_path: Path = PROBE_PATH) -> None:
    """Keep Core loss and optional KDE helper failure isolated from the session."""
    from pc_agent.platform.worktime_user import UserCompanion
    from .worktime_notification import notify
    companion = UserCompanion(exchange, notify)
    while not stop.is_set():
        probe = None
        try:
            probe = await asyncio.create_subprocess_exec(
                str(probe_path), '--managed-stdin', stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL, limit=1025,
            )
            while not stop.is_set():
                record = await _next_record(probe, stop)
                if not record:
                    break
                session = await asyncio.to_thread(own_session)
                sample = await asyncio.to_thread(sample_record, record, session=session)
                with suppress(OSError, ValueError):
                    await asyncio.to_thread(send_user_sample, sample)
                    if sample.desktop_state == 'UNLOCKED':
                        companion.tick()
                # The helper samples every 5 seconds; send at that same fixed
                # rate without accumulating historical user observations.
        except (OSError, ValueError, TimeoutError):
            with suppress(OSError, ValueError):
                sample = sample_record(b'', session=await asyncio.to_thread(own_session))
                await asyncio.to_thread(send_user_sample, sample)
        finally:
            if probe is not None:
                await _stop_probe(probe)
        if not stop.is_set():
            with suppress(TimeoutError):
                await asyncio.wait_for(stop.wait(), 5)


async def _main() -> int:
    if os.getuid() == 0 or os.geteuid() != os.getuid():
        return 1
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(signum, stop.set)
    watcher = asyncio.create_task(_watch_selected_release(stop))
    try:
        await run_user_sensor(stop=stop)
    finally:
        stop.set()
        await watcher
    return 0


def _selected_version_changed() -> bool:
    if not getattr(sys, 'frozen', False):
        return False
    try:
        selector = Path('/opt/endpoint-agent/current.json')
        info = selector.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_size > 4096:
            return False
        from pc_agent.local_sensor_protocol import _unique_object
        data = json.loads(selector.read_bytes(), object_pairs_hook=_unique_object)
        return isinstance(data, dict) and isinstance(data.get('version'), str) and data['version'] != AGENT_VERSION
    except (OSError, ValueError):
        return False


async def _watch_selected_release(stop: asyncio.Event) -> None:
    while not stop.is_set():
        if await asyncio.to_thread(_selected_version_changed):
            # Restart=always invokes the protected selector wrapper again.
            # No user process applies updates or rewrites install state.
            stop.set()
            return
        with suppress(TimeoutError):
            await asyncio.wait_for(stop.wait(), 10)


def main() -> int:
    return asyncio.run(_main())


if __name__ == '__main__':
    raise SystemExit(main())
