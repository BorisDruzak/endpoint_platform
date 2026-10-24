"""systemd 258 structured journal recovery and public logind subscriptions.

No rendered MESSAGE is read. Existing systemd-journal membership supplies the
journal boundary; busctl wait subscribes with AddMatch, unlike monitor.
"""

from __future__ import annotations

import asyncio
import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

from endpoint_contracts.power_events import PowerSourceStatusV1
from pc_agent.power.native import NativePage, native_event, opaque_id

SLEEP_START = "6bbd95ee977941e497c48be27c254128"
SLEEP_STOP = "8811e6df2a8e40f58a94cea26f8ebf14"
SHUTDOWN = "98268866d1d54a499c4e98921d93bc40"
STARTUP_FINISHED = "b07a249cd024414a82dd00cd181378ff"
UNIT_STARTING = "7d4958e842da4a758f6c1cdc7b36dcc5"
UNIT_STARTED = "39f53479d3a045ac8e11786248231fbf"
_PROJECTION_VERSION = 2
_UNITS = {
    "systemd-suspend.service": "sleep",
    "systemd-hibernate.service": "hibernate",
    "systemd-hybrid-sleep.service": "hybrid",
    "systemd-suspend-then-hibernate.service": "unknown",
}
_FIELDS = (
    "__CURSOR,__REALTIME_TIMESTAMP,_BOOT_ID,_UID,_PID,_SYSTEMD_UNIT,MESSAGE_ID,UNIT"
)


async def bounded_command(args, *, timeout=5, max_bytes=512 * 1024):
    process = await asyncio.create_subprocess_exec(
        *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
    )
    try:
        async with asyncio.timeout(timeout):
            try:
                encoded = await process.stdout.readexactly(max_bytes + 1)
            except asyncio.IncompleteReadError as ended:
                encoded = ended.partial
            if len(encoded) > max_bytes:
                raise ValueError("native metadata exceeds bound")
            await process.wait()
        if process.returncode:
            raise OSError("native metadata reader unavailable")
        return encoded.decode("utf-8", errors="strict")
    finally:
        if process.returncode is None:
            process.kill()
            await process.wait()


def read_boot():
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    if not re.fullmatch(r"[a-f0-9-]{32,36}", boot):
        raise ValueError("invalid Linux boot identity")
    for row in Path("/proc/stat").read_text().splitlines():
        if row.startswith("btime "):
            return boot, datetime.fromtimestamp(int(row[6:]), UTC)
    raise ValueError("Linux boot time unavailable")


def project_journal_page(rows, checkpoint, *, now):
    if len(rows) > 128:
        raise ValueError("journal page exceeds bound")
    state = json.loads(checkpoint) if checkpoint else {}
    events, losses = [], 0
    for row in rows:
        cursor = row.get("__CURSOR")
        if not isinstance(cursor, str) or len(cursor) > 4096:
            raise ValueError("journal cursor unavailable")
        state["cursor"] = cursor
        message = row.get("MESSAGE_ID")
        if row.get("_UID") != "0":
            continue
        unit = row.get("_SYSTEMD_UNIT")
        kind, evidence, subtype = None, "transition", None
        if message in {SLEEP_START, SLEEP_STOP} and unit in _UNITS:
            kind = "OS_SLEEP_STARTED" if message == SLEEP_START else "OS_RESUMED"
            subtype = _UNITS[unit] if message == SLEEP_START else None
        elif message == SHUTDOWN and unit == "systemd-logind.service":
            kind, evidence = "OS_SHUTDOWN_STARTED", "request"
        elif (
            message in {UNIT_STARTING, UNIT_STARTED}
            and row.get("_PID") == "1"
            and unit == "init.scope"
            and row.get("UNIT") == "shutdown.target"
        ):
            kind = "OS_SHUTDOWN_STARTED"
        elif (
            message == STARTUP_FINISHED
            and row.get("_PID") == "1"
            and unit == "init.scope"
        ):
            kind = "OS_STARTED"
        if kind is None:
            continue
        try:
            occurred = datetime.fromtimestamp(
                int(row["__REALTIME_TIMESTAMP"]) / 1000000, UTC
            )
            if occurred > now + timedelta(minutes=5):
                raise ValueError("clock skew")
            events.append(
                native_event(
                    source="linux.journal",
                    boot_id=row["_BOOT_ID"],
                    native_record_id=opaque_id(cursor),
                    event_kind=kind,
                    occurred_at=occurred,
                    observed_at=now,
                    evidence=evidence,
                    sleep_subtype=subtype,
                )
            )
        except (ValueError, TypeError, KeyError, OverflowError):
            losses += 1
    state["coverage"] = min(
        [
            state.get("coverage", now.isoformat()),
            *[e.occurred_at.isoformat() for e in events],
        ]
    )
    status = PowerSourceStatusV1(
        schema_version="power_source_status_v1",
        source="linux.journal",
        availability="DEGRADED" if losses else "READY",
        reported_at=now,
        coverage_started_at=min(datetime.fromisoformat(state["coverage"]), now),
    )
    return NativePage(
        tuple(events),
        json.dumps(state, separators=(",", ":")),
        status,
        loss_count=losses,
    )


def project_logind_signal(member, entering, *, boot_id, now):
    # A false signal can be cancellation. Strong journal resume facts fill history.
    if entering is not True or member not in {"PrepareForShutdown", "PrepareForSleep"}:
        return None
    return native_event(
        source="linux.logind",
        boot_id=boot_id,
        native_record_id=opaque_id(f"{member}:{now.isoformat()}"),
        event_kind="OS_SHUTDOWN_STARTED"
        if member == "PrepareForShutdown"
        else "OS_SLEEP_STARTED",
        evidence="request",
        sleep_subtype="unknown" if member == "PrepareForSleep" else None,
        occurred_at=now,
        observed_at=now,
    )


class LinuxPowerSource:
    source = "linux.journal"

    def __init__(
        self,
        *,
        run=bounded_command,
        boot_reader=read_boot,
        persistent=lambda: Path("/var/log/journal").is_dir(),
    ):
        self._run, self._boot_reader, self._persistent = run, boot_reader, persistent
        self._subscriptions = set()

    def _args(self, lines):
        return [
            "journalctl",
            "--system",
            "--no-pager",
            "--output=json",
            f"--output-fields={_FIELDS}",
            f"--lines=+{lines}",
        ]

    async def read_page(self, checkpoint, *, now):
        state = json.loads(checkpoint) if checkpoint else {}
        reset = 0
        if state and state.get("projection_version") != _PROJECTION_VERSION:
            # Earlier filters missed retained UNIT_STARTED shutdown.target rows.
            # Replay once; current_boot remains a kernel identity, not a restart.
            state.pop("cursor", None)
            state.pop("coverage", None)
            reset = 1
        # The caller commits this marker and the recovered facts atomically.
        state["projection_version"] = _PROJECTION_VERSION
        cursor = state.get("cursor")
        if cursor:
            exact = await self._run([*self._args(1), f"--cursor={cursor}"])
            rows = [json.loads(line) for line in exact.splitlines() if line.strip()]
            if not rows or rows[0].get("__CURSOR") != cursor:
                state.pop("cursor", None)
                state.pop("coverage", None)
                cursor, reset = None, 1
        args = self._args(128)
        args.extend(
            [
                f"MESSAGE_ID={x}"
                for x in [
                    SLEEP_START,
                    SLEEP_STOP,
                    SHUTDOWN,
                    STARTUP_FINISHED,
                    UNIT_STARTING,
                    UNIT_STARTED,
                ]
            ]
        )
        args.append(
            f"--after-cursor={cursor}"
            if cursor
            else f"--since={int((now - timedelta(days=30)).timestamp())}"
        )
        # @unix seconds avoids locale-dependent parsing of relative timestamps.
        if not cursor:
            args[-1] = args[-1].replace("--since=", "--since=@")
        encoded = await self._run(args)
        rows = [json.loads(line) for line in encoded.splitlines() if line.strip()]
        page = project_journal_page(rows, json.dumps(state), now=now)
        state = json.loads(page.checkpoint)
        events = list(page.events)
        boot, started = self._boot_reader()
        # Boot identity/time come from the kernel, never this agent's process.
        if state.get("current_boot") != boot and len(events) < 128:
            if started > now + timedelta(minutes=5):
                raise ValueError("Linux boot time is in the future")
            events.append(
                native_event(
                    source="linux.boot",
                    boot_id=boot,
                    native_record_id="boot",
                    event_kind="OS_STARTED",
                    occurred_at=started,
                    observed_at=now,
                )
            )
            state["current_boot"] = boot
        degraded = (
            reset
            or page.loss_count
            or not self._persistent()
            or len(self._subscriptions) < 2
        )
        status = page.status.model_copy(
            update={"availability": "DEGRADED" if degraded else "READY"}
        )
        return NativePage(
            tuple(events),
            json.dumps(state, separators=(",", ":")),
            status,
            loss_count=page.loss_count,
            reset_count=reset,
        )

    async def notifications(self, record):
        async def subscribe(member):
            while True:
                process = None
                try:
                    process = await asyncio.create_subprocess_exec(
                        "busctl",
                        "--system",
                        "--json=short",
                        "wait",
                        "org.freedesktop.login1",
                        "/org/freedesktop/login1",
                        "org.freedesktop.login1.Manager",
                        member,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.DEVNULL,
                    )
                    # wait needs public AddMatch only; no BecomeMonitor privilege.
                    await asyncio.sleep(0.05)
                    if process.returncode is not None:
                        raise OSError("logind subscription unavailable")
                    self._subscriptions.add(member)
                    try:
                        encoded = await process.stdout.readexactly(4097)
                    except asyncio.IncompleteReadError as ended:
                        encoded = ended.partial
                    await process.wait()
                    if process.returncode or len(encoded) > 4096:
                        raise ValueError("invalid logind signal")
                    value = json.loads(encoded)
                    if (
                        value.get("type") != "b"
                        or len(value.get("data", [])) != 1
                        or type(value["data"][0]) is not bool
                    ):
                        raise ValueError("invalid logind signal payload")
                    event = project_logind_signal(
                        member,
                        value["data"][0],
                        boot_id=self._boot_reader()[0],
                        now=datetime.now(UTC),
                    )
                    if event:
                        await record(event)
                except (OSError, ValueError):
                    self._subscriptions.discard(member)
                    await asyncio.sleep(5)
                finally:
                    self._subscriptions.discard(member)
                    if process is not None and process.returncode is None:
                        process.kill()
                        await process.wait()

        tasks = [
            asyncio.create_task(subscribe(x))
            for x in ("PrepareForSleep", "PrepareForShutdown")
        ]
        try:
            await asyncio.gather(*tasks)
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
