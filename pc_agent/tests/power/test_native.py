"""Structured native metadata, source trust and forward recovery."""

import asyncio
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from pc_agent.platform.linux.power_events import (
    LinuxPowerSource,
    project_journal_page,
    project_logind_signal,
)
from pc_agent.platform.windows.power_events import (
    WindowsPowerSource,
    parse_event_xml,
    project_windows_page,
)

NOW = datetime(2026, 10, 24, 12, tzinfo=UTC)


def test_operator_captured_system_metadata_is_real_evidence_not_vm_acceptance():
    rows = json.loads(
        (Path(__file__).parent / "fixtures/windows-system-metadata.json").read_text()
    )
    page = project_windows_page(
        sorted(rows, key=lambda r: r["record_id"]), None, now=NOW
    )
    starts = [event for event in page.events if event.event_kind == "OS_STARTED"]
    assert len(starts) == 5
    boot_records = {str(row["record_id"]) for row in rows if row["event_id"] == 27}
    assert {event.native_record_id for event in starts} == boot_records
    assert len({event.event_identifier for event in starts}) == 5
    assert page.loss_count > 0  # older retained rows lack their native boot boundary


def win(identifier, number, data=None, provider="Microsoft-Windows-Kernel-General"):
    return {
        "event_id": identifier,
        "record_id": number,
        "timestamp": NOW.isoformat(),
        "provider": provider,
        "data": data or {},
    }


def test_windows_full_boot_fast_startup_hibernate_same_boot_restart():
    for boot_type, kind in [
        ("0", "OS_STARTED"),
        ("1", "OS_RESUMED"),
        ("2", "OS_RESUMED"),
    ]:
        start = win(
            12,
            1,
            {"StartTime": (NOW - timedelta(seconds=1)).isoformat(), "BootMode": "0"},
        )
        first = project_windows_page([start], None, now=NOW)
        assert not first.events  # 12 alone cannot distinguish Fast Startup
        second = project_windows_page(
            [win(27, 2, {"BootType": boot_type}, "Microsoft-Windows-Kernel-Boot")],
            first.checkpoint,
            now=NOW,
        )
        assert [e.event_kind for e in second.events] == [kind]
        assert not project_windows_page([], second.checkpoint, now=NOW).events
        replay = project_windows_page(
            [
                start,
                win(27, 2, {"BootType": boot_type}, "Microsoft-Windows-Kernel-Boot"),
            ],
            None,
            now=NOW + timedelta(hours=1),
        )
        assert replay.events[0].event_identifier == second.events[0].event_identifier
        assert replay.events[0].occurred_at == second.events[0].occurred_at


def test_windows_boot_order_and_missing_general12_keep_stable_native_facts():
    boot = win(27, 2, {"BootType": "0"}, "Microsoft-Windows-Kernel-Boot")
    first = project_windows_page(
        [win(12, 1, {"StartTime": (NOW - timedelta(seconds=1)).isoformat()}), boot],
        None,
        now=NOW,
    )
    recovered = project_windows_page([boot], None, now=NOW)
    assert first.events == recovered.events


async def test_windows_immediate_notifications_use_current_os_boot_and_ignore_duplicates():
    source = WindowsPowerSource()
    source._boot_id = "actual-current-boot"
    event = source.notification_event(4, now=NOW)
    assert (
        event.event_kind == "OS_SLEEP_STARTED"
        and event.boot_id == "actual-current-boot"
    )
    assert source.notification_event(18, now=NOW).event_kind == "OS_RESUMED"
    assert source.notification_event(7, now=NOW) is None


def test_windows_real_metadata_parser_and_provider_whitelist():
    xml = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Kernel-General"/><EventID>12</EventID><TimeCreated SystemTime="2026-10-22T21:09:00.9356833Z"/><EventRecordID>36161421</EventRecordID></System><EventData><Data Name="StartTime">2026-10-22T21:09:00.5000000Z</Data><Data Name="BootMode">0</Data><Data Name="secret">excluded</Data></EventData></Event>"""
    row = parse_event_xml(xml)
    assert row["data"] == {"StartTime": "2026-10-22T21:09:00.5000000Z", "BootMode": "0"}
    page = project_windows_page(
        [win(6005, 1, provider="EventLog"), win(12, 2, provider="Spoof")], None, now=NOW
    )
    assert not page.events


def test_windows_sleep_shutdown_request_unclean_and_clock_skew():
    checkpoint = json.dumps({"record_id": 1, "boot_id": "native-boot"})
    rows = [
        win(42, 2, {"EffectiveState": "5"}, "Microsoft-Windows-Kernel-Power"),
        win(107, 3, provider="Microsoft-Windows-Kernel-Power"),
        win(1074, 4, provider="User32"),
        win(13, 5, {"StopTime": NOW.isoformat()}),
        win(41, 6, provider="Microsoft-Windows-Kernel-Power"),
    ]
    page = project_windows_page(rows, checkpoint, now=NOW)
    assert [e.event_kind for e in page.events] == [
        "OS_SLEEP_STARTED",
        "OS_RESUMED",
        "OS_SHUTDOWN_STARTED",
        "OS_SHUTDOWN_STARTED",
        "OS_UNEXPECTED_SHUTDOWN_REPORTED",
    ]
    assert page.events[0].sleep_subtype == "hibernate"
    assert page.events[2].evidence == "request"
    assert page.events[4].evidence == "reported"
    assert (
        project_windows_page(
            [{**rows[0], "timestamp": (NOW + timedelta(hours=1)).isoformat()}],
            checkpoint,
            now=NOW,
        ).status.availability
        == "DEGRADED"
    )


def journal(i, message="6bbd95ee977941e497c48be27c254128", **kwargs):
    return {
        "__CURSOR": f"s=abc;i={i}",
        "__REALTIME_TIMESTAMP": str(int(NOW.timestamp() * 1000000)),
        "_BOOT_ID": "abcdef1234567890abcdef1234567890",
        "_UID": "0",
        "_PID": "12",
        "_SYSTEMD_UNIT": "systemd-suspend.service",
        "MESSAGE_ID": message,
        **kwargs,
    }


def test_linux_trusted_structured_metadata_requests_and_resume():
    rows = [
        journal(1),
        journal(2, "8811e6df2a8e40f58a94cea26f8ebf14"),
        journal(
            3,
            "98268866d1d54a499c4e98921d93bc40",
            _SYSTEMD_UNIT="systemd-logind.service",
        ),
        journal(4, _UID="1000"),
        journal(5, _SYSTEMD_UNIT="evil.service"),
    ]
    page = project_journal_page(rows, None, now=NOW)
    assert [e.event_kind for e in page.events] == [
        "OS_SLEEP_STARTED",
        "OS_RESUMED",
        "OS_SHUTDOWN_STARTED",
    ]
    assert page.events[2].evidence == "request"
    assert page.events[0].sleep_subtype == "sleep"
    assert "MESSAGE" not in page.events[0].model_dump_json()
    assert json.loads(page.checkpoint)["cursor"] == "s=abc;i=5"
    assert (
        project_logind_signal("PrepareForShutdown", False, boot_id="boot", now=NOW)
        is None
    )
    assert (
        project_logind_signal(
            "PrepareForShutdown", True, boot_id="boot", now=NOW
        ).evidence
        == "request"
    )
    assert (
        project_logind_signal("PrepareForSleep", False, boot_id="boot", now=NOW) is None
    )


def test_linux_pid1_shutdown_target_is_transition_and_user_target_is_not():
    row = journal(
        1,
        "7d4958e842da4a758f6c1cdc7b36dcc5",
        _PID="1",
        _SYSTEMD_UNIT="init.scope",
        UNIT="shutdown.target",
    )
    page = project_journal_page([row], None, now=NOW)
    assert page.events[0].event_kind == "OS_SHUTDOWN_STARTED"
    assert page.events[0].evidence == "transition"
    assert not project_journal_page([{**row, "_PID": "999"}], None, now=NOW).events


async def test_linux_forward_pages_over_128_and_rollover():
    calls = []
    rows = [journal(i) for i in range(300)]

    async def run(args):
        calls.append(args)
        if any(a.startswith("--cursor=") for a in args):
            cursor = next(a[9:] for a in args if a.startswith("--cursor="))
            return json.dumps(next(r for r in rows if r["__CURSOR"] == cursor)) + "\n"
        start = 0
        if any(a.startswith("--after-cursor=") for a in args):
            cursor = next(a[15:] for a in args if a.startswith("--after-cursor="))
            start = next(i for i, r in enumerate(rows) if r["__CURSOR"] == cursor) + 1
        return "\n".join(json.dumps(r) for r in rows[start : start + 128])

    source = LinuxPowerSource(
        run=run,
        boot_reader=lambda: ("currentboot", NOW - timedelta(days=1)),
        persistent=lambda: True,
    )
    state, found = None, []
    for _ in range(4):
        page = await source.read_page(state, now=NOW)
        state = page.checkpoint
        found.extend(e for e in page.events if e.source == "linux.journal")
    assert len(found) == len({e.event_identifier for e in found}) == 300
    assert all("--lines=+128" in c or "--lines=+1" in c for c in calls)

    async def rolled(args):
        return json.dumps(journal(500))

    page = await LinuxPowerSource(
        run=rolled, boot_reader=lambda: ("currentboot", NOW), persistent=lambda: True
    ).read_page(state, now=NOW)
    assert page.reset_count == 1 and page.status.availability == "DEGRADED"


async def test_native_cursor_never_advances_on_reader_failure():
    def fail(*args):
        raise PermissionError("denied")

    with pytest.raises(PermissionError):
        await WindowsPowerSource(reader=fail).read_page("{}", now=NOW)


async def test_windows_reader_pages_forward_over128_and_reports_rollover():
    rows = [win(27, 1, {"BootType": "0"}, "Microsoft-Windows-Kernel-Boot")]
    rows.extend(
        win(107, i, provider="Microsoft-Windows-Kernel-Power") for i in range(2, 301)
    )
    calls = []

    def read(checkpoint, now):
        state = json.loads(checkpoint) if checkpoint else {}
        calls.append(state.get("record_id", 0))
        return (
            [r for r in rows if r["record_id"] > state.get("record_id", 0)][:128],
            json.dumps(state),
            False,
            "actualboot",
        )

    source = WindowsPowerSource(reader=read)
    checkpoint, found = None, []
    for _ in range(3):
        page = await source.read_page(checkpoint, now=NOW)
        checkpoint = page.checkpoint
        found.extend(page.events)
    assert calls == [0, 128, 256]
    assert len(found) == len({e.event_identifier for e in found}) == 300

    def reset(checkpoint, now):
        return rows[:1], "{}", True, "actualboot"

    rolled = await WindowsPowerSource(reader=reset).read_page(checkpoint, now=NOW)
    assert rolled.reset_count == 1 and rolled.status.availability == "DEGRADED"


def test_linux_bad_native_timestamp_counts_loss_and_checkpoint_progresses():
    bad = journal(1, __REALTIME_TIMESTAMP="broken")
    good = journal(2)
    result = project_journal_page([bad, good], None, now=NOW)
    assert len(result.events) == 1 and result.loss_count == 1
    assert result.status.availability == "DEGRADED"
    assert json.loads(result.checkpoint)["cursor"] == good["__CURSOR"]


async def test_failed_logind_signal_is_not_reported_subscribed_during_backoff(
    monkeypatch,
):
    class Process:
        returncode = None

        def __init__(self):
            self.stdout = asyncio.StreamReader()
            self.stdout.feed_data(b'{"type":"s","data":["invalid"]}')
            self.stdout.feed_eof()

        async def wait(self):
            self.returncode = 0

    async def spawn(*args, **kwargs):
        assert "wait" in args and "monitor" not in args
        return Process()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", spawn)
    source = LinuxPowerSource(boot_reader=lambda: ("boot", NOW))

    async def record(event):
        raise AssertionError("invalid signal must not become power fact")

    task = asyncio.create_task(source.notifications(record))
    try:
        await asyncio.sleep(0.1)
        assert source._subscriptions == set()
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


async def test_missing_latest_windows_boot_cannot_report_full_source_readiness():
    source = WindowsPowerSource(reader=lambda *_: ([], "{}", False, None))
    source._notifications_ready = True
    page = await source.read_page(None, now=NOW)
    assert page.status.availability == "DEGRADED"


@pytest.mark.parametrize(
    "checkpoint",
    [
        None,
        '{"record_id":9999,"boot_id":"obsolete"}',
        '{"record_id":5,"boot_id":"obsolete"}',
    ],
)
@pytest.mark.parametrize("new_boot_present", [False, True])
async def test_windows_retained_old_boot_context_recovers_recent_multiple_boots(
    monkeypatch, checkpoint, new_boot_present
):
    """The 30-day fact window must not hide the boot of its earliest row."""
    import re
    import sys
    from types import SimpleNamespace

    from pc_agent.platform.windows import power_events as native

    old_boot = win(27, 10, {"BootType": "0"}, "Microsoft-Windows-Kernel-Boot")
    old_boot["timestamp"] = (NOW - timedelta(days=60)).isoformat()
    recent = win(42, 20, provider="Microsoft-Windows-Kernel-Power")
    recent["timestamp"] = (NOW - timedelta(days=20)).isoformat()
    new_boot = win(27, 200, {"BootType": "0"}, "Microsoft-Windows-Kernel-Boot")
    new_boot["timestamp"] = (NOW - timedelta(days=10)).isoformat()
    resumed = win(107, 210, provider="Microsoft-Windows-Kernel-Power")
    interval = [
        {
            **win(107, number, provider="Microsoft-Windows-Kernel-Power"),
            "timestamp": recent["timestamp"],
        }
        for number in range(21, 151)
    ]
    pre_cursor = {
        **win(6005, 5, provider="EventLog"),
        "timestamp": (NOW - timedelta(days=90)).isoformat(),
    }
    rows = [
        pre_cursor,
        old_boot,
        recent,
        *interval,
        *([new_boot, resumed] if new_boot_present else []),
    ]
    reads = []

    class Handle:
        def __init__(self, value):
            self.value = value

        def Close(self):
            pass

    def query(_channel, flags, expression):
        selected = rows[:]
        if (
            "Provider[@Name='Microsoft-Windows-Kernel-Boot'] and EventID=27"
            in expression
            and " or " not in expression
        ):
            selected = [row for row in selected if row["event_id"] == 27]
        for operator, value in re.findall(
            r"EventRecordID\s*(<=|>=|<|>|=)\s*(\d+)", expression
        ):
            selected = [
                row
                for row in selected
                if {
                    "<": row["record_id"] < int(value),
                    "<=": row["record_id"] <= int(value),
                    ">": row["record_id"] > int(value),
                    ">=": row["record_id"] >= int(value),
                    "=": row["record_id"] == int(value),
                }[operator]
            ]
        if "TimeCreated" in expression:
            selected = [
                row
                for row in selected
                if datetime.fromisoformat(row["timestamp"]) >= NOW - timedelta(days=30)
            ]
        return Handle(list(reversed(selected)) if flags & 2 else selected)

    def next_rows(handle, count, timeout):
        reads.append(count)
        return [Handle(row) for row in handle.value[:count]]

    monkeypatch.setitem(
        sys.modules,
        "win32evtlog",
        SimpleNamespace(
            EvtQueryChannelPath=4,
            EvtQueryForwardDirection=1,
            EvtQueryReverseDirection=2,
            EvtQuery=query,
            EvtNext=next_rows,
            EvtRenderEventXml=1,
            EvtRender=lambda handle, _mode: handle.value,
        ),
    )
    monkeypatch.setattr(native, "parse_event_xml", lambda row: row)
    source = WindowsPowerSource(reader=native._read_system)
    source._notifications_ready = True
    found = []
    for _ in range(2):
        page = await source.read_page(checkpoint, now=NOW)
        checkpoint = page.checkpoint
        found.extend(page.events)
        assert page.loss_count == 0
    expected = [str(number) for number in range(20, 151)]
    assert [event.native_record_id for event in found] == expected + (
        ["200", "210"] if new_boot_present else []
    )
    assert len({event.boot_id for event in found[:131]}) == 1
    assert found[0].boot_id != "obsolete"
    if new_boot_present:
        assert found[0].boot_id != found[-1].boot_id
        assert found[-2].boot_id == found[-1].boot_id
    assert json.loads(page.checkpoint)["boot_id"] == found[-1].boot_id
    assert max(reads) <= 128


async def test_windows_missing_historical_boot_stays_degraded_on_empty_page():
    source = WindowsPowerSource(
        reader=lambda checkpoint, _now: ([], checkpoint or "{}", False, "newest-boot")
    )
    source._notifications_ready = True
    page = await source.read_page(None, now=NOW)
    assert page.status.availability == "DEGRADED"
    page = await source.read_page(page.checkpoint, now=NOW)
    assert page.status.availability == "DEGRADED"


async def test_windows_worker_reads_complete_page_across_pipe_chunks(monkeypatch):
    import sys

    from pc_agent.platform.windows.power_events import read_system_page

    spawn = asyncio.create_subprocess_exec

    async def split_reply(*_command, **kwargs):
        return await spawn(
            sys.executable,
            "-c",
            """
import json, sys
sys.stdin.buffer.read()
rows = [{'provider':'Microsoft-Windows-Kernel-Power', 'event_id':42,
         'record_id':i, 'timestamp':'2026-10-24T12:00:00+00:00',
         'data':{'EffectiveState':'4', 'WakeTime':'x'*1024}} for i in range(128)]
sys.stdout.buffer.write(json.dumps([rows, '{}', False, 'boot']).encode())
""",
            **kwargs,
        )

    monkeypatch.setattr(asyncio, "create_subprocess_exec", split_reply)
    rows, _state, reset, boot = await read_system_page(None, NOW)
    assert len(rows) == 128 and rows[-1]["record_id"] == 127
    assert reset is False and boot == "boot"


def test_windows_private_worker_and_frozen_dispatch_reject_extra_inputs(monkeypatch):
    import io
    import sys
    from types import SimpleNamespace

    from pc_agent.platform.windows import power_events as native
    from pc_agent.runtime import main

    called = []

    def read(checkpoint, now):
        called.append((checkpoint, now))
        return [], "{}", False, "boot"

    monkeypatch.setattr(native, "_read_system", read)
    output = io.BytesIO()
    monkeypatch.setattr(sys, "stdout", SimpleNamespace(buffer=output))
    for request in [b'{"command":"whoami"}', b"x" * 32769]:
        monkeypatch.setattr(sys, "stdin", SimpleNamespace(buffer=io.BytesIO(request)))
        assert main.main(["--windows-power-read"]) == 1
    assert not called and not output.getvalue()
    request = json.dumps({"checkpoint": None, "now": NOW.isoformat()}).encode()
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(buffer=io.BytesIO(request)))
    assert main.main(["--windows-power-read"]) == 0
    assert json.loads(output.getvalue()) == [[], "{}", False, "boot"]
    assert called == [(None, NOW)]

@pytest.mark.parametrize("case", ["overlapping_generation", "legacy", "missing_anchor", "same_generation", "later_boot"])
async def test_windows_native_cursor_revalidates_record_identity(monkeypatch, tmp_path, case):
    """Modeled native API: reused record numbers alone cannot prove continuity."""
    import re
    import sys
    from types import SimpleNamespace
    from pc_agent.platform.windows import power_events as native
    from pc_agent.power.spool import PowerEventSpool

    boot = win(27, 10, {"BootType": "0"}, "Microsoft-Windows-Kernel-Boot")
    previous = win(107, 100, provider="Microsoft-Windows-Kernel-Power")
    old_rows = [{**r, "timestamp": (NOW - timedelta(days=2)).isoformat()} for r in (boot, previous)]
    saved = project_windows_page(old_rows, None, now=NOW)
    state = json.loads(saved.checkpoint)
    if case == "legacy":
        state.pop("record_anchor", None)
    checkpoint = json.dumps(state)
    reset_expected = case in {"overlapping_generation", "legacy", "missing_anchor"}
    retained = [
        win(6005, 1, provider="EventLog"), boot,
        win(42, 20, provider="Microsoft-Windows-Kernel-Power"),
        win(107, 30, provider="Microsoft-Windows-Kernel-Power"),
        previous, win(6005, 200, provider="EventLog"),
    ]
    if case != "overlapping_generation":
        retained[1], retained[4] = old_rows
    if case == "missing_anchor":
        retained = [r for r in retained if r["record_id"] != 100]
    if case == "later_boot":
        retained.insert(-1, win(27, 150, {"BootType": "0"}, "Microsoft-Windows-Kernel-Boot"))
    queries, handles = [], []

    class Handle:
        def __init__(self, value):
            self.value, self.closed = value, False
            handles.append(self)

        def Close(self):
            self.closed = True

    def query(channel, flags, expression):
        assert channel == "System"
        queries.append(expression)
        rows = retained[:]
        if "Provider[@Name='Microsoft-Windows-Kernel-Boot']" in expression and " or " not in expression:
            rows = [r for r in rows if r["event_id"] == 27]
        if " or " in expression:
            rows = [r for r in rows if r["provider"].startswith("Microsoft-Windows-Kernel-")]
        for operator, number in re.findall(r"EventRecordID\s*(<=|>|=)\s*(\d+)", expression):
            rows = [r for r in rows if {"<=": r["record_id"] <= int(number), ">": r["record_id"] > int(number), "=": r["record_id"] == int(number)}[operator]]
        return Handle(list(reversed(rows)) if flags & 2 else rows)

    def render(handle, mode):
        row = handle.value
        data = "".join(f'<Data Name="{key}">{value}</Data>' for key, value in row["data"].items())
        return f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="{row["provider"]}"/><EventID>{row["event_id"]}</EventID><EventRecordID>{row["record_id"]}</EventRecordID><TimeCreated SystemTime="{row["timestamp"]}"/></System><EventData>{data}<Data Name="private">never-persist</Data></EventData></Event>'

    def next_rows(handle, count, timeout):
        assert count <= 128 and timeout == 1000
        return [Handle(r) for r in handle.value[:count]]

    monkeypatch.setitem(sys.modules, "win32evtlog", SimpleNamespace(
        EvtQueryChannelPath=4, EvtQueryForwardDirection=1, EvtQueryReverseDirection=2,
        EvtQuery=query, EvtNext=next_rows, EvtRender=render, EvtRenderEventXml=1,
    ))
    source = WindowsPowerSource(reader=native._read_system)
    source._notifications_ready = True
    page = await source.read_page(checkpoint, now=NOW)
    assert page.reset_count == int(reset_expected)
    if reset_expected:
        assert [e.native_record_id for e in page.events][:3] == ["10", "20", "30"]
        assert page.status.availability == "DEGRADED"
        if case == "overlapping_generation":
            assert page.status.coverage_started_at == NOW
            assert page.events[0].boot_id != saved.events[0].boot_id
    else:
        assert [e.native_record_id for e in page.events] == (["150"] if case == "later_boot" else [])
        assert page.status.coverage_started_at == NOW - timedelta(days=2)
    persisted = json.loads(page.checkpoint)
    assert len(persisted["record_anchor"]) == 64
    assert len(page.checkpoint) <= 16384 and "never-persist" not in page.checkpoint
    spool = PowerEventSpool(tmp_path)
    await spool.open()
    await spool.commit_page(page, now=NOW)
    reopened = PowerEventSpool(tmp_path)
    await reopened.open()
    assert (await reopened.source_status()).reset_count == int(reset_expected)
    again = await source.read_page(await reopened.checkpoint(), now=NOW)
    assert not again.events and again.reset_count == 0
    assert all(handle.closed for handle in handles)
