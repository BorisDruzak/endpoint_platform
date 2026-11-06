"""Current power monitoring must survive loss of a retained boot record."""

import json
import re
import sys
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from pc_agent.platform.windows import power_events as native

NOW = datetime(2026, 11, 5, 6, tzinfo=UTC)
BOOT = datetime(2026, 10, 21, 7, 12, 18, 500000, tzinfo=UTC)


def row(identifier, number, *, when=NOW, provider="Microsoft-Windows-Kernel-Power", data=None):
    return {"provider": provider, "event_id": identifier, "record_id": number,
            "timestamp": when.isoformat(), "data": data or {}}


def install_eventlog(monkeypatch, records, before_query=None, reads=None):
    """Model only the native API; exercise the real reader and projector."""
    handles = []

    class Handle:
        def __init__(self, value):
            self.value = value
            self.closed = False
            handles.append(self)

        def Close(self):
            self.closed = True

    def query(channel, flags, expression):
        assert channel == "System"
        if before_query is not None:
            before_query(expression)
        selected = records[:]
        if "Provider[@Name='Microsoft-Windows-Kernel-Boot']" in expression and " or " not in expression:
            selected = [r for r in selected if r["provider"] == "Microsoft-Windows-Kernel-Boot" and r["event_id"] == 27]
        elif " or " in expression:
            power_pairs = {
                ("Microsoft-Windows-Kernel-General", 12),
                ("Microsoft-Windows-Kernel-General", 13),
                ("Microsoft-Windows-Kernel-Boot", 27),
                ("Microsoft-Windows-Kernel-Power", 41),
                ("Microsoft-Windows-Kernel-Power", 42),
                ("Microsoft-Windows-Kernel-Power", 107),
                ("Microsoft-Windows-Power-Troubleshooter", 1),
                ("User32", 1074),
            }
            selected = [r for r in selected if (r["provider"], r["event_id"]) in power_pairs]
        for operator, number in re.findall(r"EventRecordID\s*(<=|>|=)\s*(\d+)", expression):
            number = int(number)
            selected = [r for r in selected if {"<=": r["record_id"] <= number, ">": r["record_id"] > number, "=": r["record_id"] == number}[operator]]
        handle = Handle(list(reversed(selected)) if flags & 2 else selected)
        handle.expression = expression
        return handle

    def next_rows(handle, count, timeout):
        if reads is not None:
            reads.append((handle.expression, count))
        return [Handle(r) for r in handle.value[:count]]

    def render(handle, mode):
        r = handle.value
        data = "".join(f'<Data Name="{k}">{v}</Data>' for k, v in r["data"].items())
        return f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="{r["provider"]}"/><EventID>{r["event_id"]}</EventID><EventRecordID>{r["record_id"]}</EventRecordID><TimeCreated SystemTime="{r["timestamp"]}"/></System><EventData>{data}</EventData></Event>'

    monkeypatch.setitem(sys.modules, "win32evtlog", SimpleNamespace(
        EvtQueryChannelPath=4, EvtQueryForwardDirection=1, EvtQueryReverseDirection=2,
        EvtQuery=query, EvtNext=next_rows,
        EvtRender=render, EvtRenderEventXml=1,
    ))
    return handles


async def test_rollover_recovers_current_source_without_inventing_os_start(monkeypatch):
    install_eventlog(monkeypatch, [row(6005, 100, provider="EventLog")])
    monkeypatch.setattr(native, "_read_current_boot", lambda now: BOOT, raising=False)
    source = native.WindowsPowerSource(reader=native._read_system)
    source._notifications_ready = True
    previous = json.dumps({"record_id": 50, "boot_id": "old-native-boundary", "coverage": BOOT.isoformat()})
    first = await source.read_page(previous, now=NOW)
    assert first.reset_count == 1 and not first.events
    again = await source.read_page(first.checkpoint, now=NOW + timedelta(seconds=5))
    assert again.status.availability == "READY"
    assert again.reset_count == again.loss_count == 0 and not again.events
    assert again.status.coverage_started_at == NOW
    notification = source.notification_event(18, now=NOW + timedelta(seconds=6))
    assert notification and notification.event_kind == "OS_RESUMED"
    assert len(notification.boot_id) == 64


async def test_fallback_never_attributes_events_before_the_verified_current_boot(monkeypatch):
    install_eventlog(monkeypatch, [
        row(42, 100, when=BOOT - timedelta(hours=1)),
        row(107, 101, when=BOOT + timedelta(hours=1)),
    ])
    monkeypatch.setattr(native, "_read_current_boot", lambda now: BOOT, raising=False)
    source = native.WindowsPowerSource(reader=native._read_system)
    source._notifications_ready = True
    page = await source.read_page(None, now=NOW)
    assert page.loss_count == 1
    assert [(e.event_kind, e.occurred_at) for e in page.events] == [("OS_RESUMED", BOOT + timedelta(hours=1))]
    assert page.status.availability == "DEGRADED"
    following = await source.read_page(page.checkpoint, now=NOW + timedelta(seconds=5))
    assert following.status.availability == "READY" and not following.events


async def test_reused_record_numbers_with_different_native_facts_do_not_collide(monkeypatch):
    records = [row(42, 100, when=NOW - timedelta(minutes=10))]
    install_eventlog(monkeypatch, records)
    monkeypatch.setattr(native, "_read_current_boot", lambda now: BOOT, raising=False)
    source = native.WindowsPowerSource(reader=native._read_system)
    source._notifications_ready = True
    first = await source.read_page(None, now=NOW)
    assert len(first.events) == 1
    records[:] = [row(42, 100, when=NOW - timedelta(minutes=1))]
    next_page = await source.read_page(first.checkpoint, now=NOW + timedelta(seconds=5))
    assert next_page.reset_count == 1 and len(next_page.events) == 1
    assert first.events[0].event_identifier != next_page.events[0].event_identifier
    assert first.events[0].boot_id == next_page.events[0].boot_id


@pytest.mark.parametrize("boot", [None, NOW + timedelta(days=1)])
async def test_missing_or_future_current_boot_does_not_claim_ready(monkeypatch, boot):
    install_eventlog(monkeypatch, [row(6005, 100, provider="EventLog")])
    monkeypatch.setattr(native, "_read_current_boot", lambda now: boot, raising=False)
    source = native.WindowsPowerSource(reader=native._read_system)
    source._notifications_ready = True
    page = await source.read_page(None, now=NOW)
    assert page.status.availability == "DEGRADED" and not page.events
    assert source.notification_event(18, now=NOW) is None


async def test_retained_native_boot_keeps_existing_identity_and_classification(monkeypatch):
    install_eventlog(monkeypatch, [row(27, 100, provider="Microsoft-Windows-Kernel-Boot", data={"BootType": "1"})])
    def unexpected(now):
        raise AssertionError("Retained native boot must not depend on WMI")
    monkeypatch.setattr(native, "_read_current_boot", unexpected, raising=False)
    source = native.WindowsPowerSource(reader=native._read_system)
    source._notifications_ready = True
    page = await source.read_page(None, now=NOW)
    assert page.status.availability == "READY"
    assert [(e.event_kind, e.native_record_id) for e in page.events] == [("OS_RESUMED", "100")]


@pytest.mark.parametrize("values, expected", [
    (["20261021121218.500000+300"], BOOT),
    (["20261021021218.500000-300"], BOOT),
    (["20261021121218.******+300"], None),
    (["20261321121218.500000+300"], None),
    (["20261106121218.500000+300"], None),
    (["00010101000000.000000+060"], None),
    ([], None),
    (["20261021121218.500000+300"] * 2, None),
])
def test_wmi_current_boot_accepts_only_one_complete_nonfuture_utc_fact(monkeypatch, values, expected):
    class ComError(Exception):
        pass

    def query(statement, dialect, flags):
        assert statement == "SELECT LastBootUpTime FROM Win32_OperatingSystem"
        return [SimpleNamespace(LastBootUpTime=v) for v in values]

    client = SimpleNamespace(GetObject=lambda namespace: SimpleNamespace(ExecQuery=query))
    monkeypatch.setitem(sys.modules, "pywintypes", SimpleNamespace(com_error=ComError))
    monkeypatch.setitem(sys.modules, "win32com", SimpleNamespace(client=client))
    monkeypatch.setitem(sys.modules, "win32com.client", client)
    assert native._read_current_boot(NOW) == expected


def test_optional_wmi_permission_failure_returns_no_boot_evidence(monkeypatch):
    class ComError(Exception):
        pass

    def denied(namespace):
        raise ComError("Access denied")

    client = SimpleNamespace(GetObject=denied)
    monkeypatch.setitem(sys.modules, "pywintypes", SimpleNamespace(com_error=ComError))
    monkeypatch.setitem(sys.modules, "win32com", SimpleNamespace(client=client))
    monkeypatch.setitem(sys.modules, "win32com.client", client)
    assert native._read_current_boot(NOW) is None


async def test_native_boundary_does_not_change_identity_of_preceding_fallback_fact(monkeypatch):
    records = [row(6005, 100, provider="EventLog")]
    install_eventlog(monkeypatch, records)
    monkeypatch.setattr(native, "_read_current_boot", lambda now: BOOT)
    source = native.WindowsPowerSource(reader=native._read_system)
    source._notifications_ready = True
    initial = await source.read_page(None, now=NOW)
    records.append(row(107, 101, when=NOW + timedelta(seconds=1)))
    isolated = await source.read_page(initial.checkpoint, now=NOW + timedelta(seconds=3))
    records.append(row(27, 102, when=NOW + timedelta(seconds=2), provider="Microsoft-Windows-Kernel-Boot", data={"BootType": "0"}))
    combined = await source.read_page(initial.checkpoint, now=NOW + timedelta(seconds=3))
    assert combined.events[0] == isolated.events[0]
    assert combined.events[1].event_kind == "OS_STARTED"
    assert json.loads(combined.checkpoint)["boot_id"] == combined.events[1].boot_id
    split = await source.read_page(isolated.checkpoint, now=NOW + timedelta(seconds=3))
    assert split.events == (combined.events[1],)
    following = await source.read_page(combined.checkpoint, now=NOW + timedelta(seconds=5))
    assert not following.events and following.status.availability == "READY"


@pytest.mark.parametrize("identifier,provider,data", [
    (1, "Microsoft-Windows-Power-Troubleshooter", {"WakeTime": (BOOT + timedelta(minutes=10)).isoformat()}),
    (13, "Microsoft-Windows-Kernel-General", {"StopTime": (BOOT + timedelta(minutes=10)).isoformat()}),
])
async def test_old_native_header_cannot_be_attributed_using_newer_payload_time(monkeypatch, identifier, provider, data):
    install_eventlog(monkeypatch, [row(identifier, 100, when=BOOT - timedelta(minutes=5), provider=provider, data=data)])
    monkeypatch.setattr(native, "_read_current_boot", lambda now: BOOT)
    source = native.WindowsPowerSource(reader=native._read_system)
    source._notifications_ready = True
    page = await source.read_page(None, now=NOW)
    assert not page.events and page.loss_count == 1


async def test_native_boot_arriving_between_queries_is_not_overwritten_by_fallback(monkeypatch):
    records = [row(6005, 100, provider="EventLog")]
    def append_boot(expression):
        if " or " in expression and len(records) == 1:
            records.append(row(27, 101, provider="Microsoft-Windows-Kernel-Boot", data={"BootType": "0"}))
    install_eventlog(monkeypatch, records, before_query=append_boot)
    monkeypatch.setattr(native, "_read_current_boot", lambda now: BOOT)
    source = native.WindowsPowerSource(reader=native._read_system)
    source._notifications_ready = True
    page = await source.read_page(None, now=NOW)
    assert len(page.events) == 1 and page.events[0].event_kind == "OS_STARTED"
    assert json.loads(page.checkpoint)["boot_id"] == page.events[0].boot_id
    assert source.notification_event(18, now=NOW + timedelta(seconds=1)).boot_id == page.events[0].boot_id


async def test_failed_live_fallback_does_not_reuse_cached_current_boot(monkeypatch):
    records = [row(6005, 100, provider="EventLog")]
    install_eventlog(monkeypatch, records)
    monkeypatch.setattr(native, "_read_current_boot", lambda now: BOOT)
    source = native.WindowsPowerSource(reader=native._read_system)
    source._notifications_ready = True
    first = await source.read_page(None, now=NOW)
    monkeypatch.setattr(native, "_read_current_boot", lambda now: None)
    records.append(row(107, 101, when=NOW + timedelta(seconds=1)))
    failed = await source.read_page(first.checkpoint, now=NOW + timedelta(seconds=2))
    assert failed.status.availability == "DEGRADED" and failed.loss_count == 1
    assert not failed.events and source.notification_event(18, now=NOW + timedelta(seconds=3)) is None


@pytest.mark.parametrize("unrelated_event_id", [292, 41])
async def test_unrelated_duplicate_record_id_does_not_reset_power_checkpoint(monkeypatch, tmp_path, unrelated_event_id):
    """The native stream can retain an unrelated provider with the same ID."""
    from dataclasses import replace
    from pc_agent.power.spool import PowerEventSpool

    observed = datetime(2026, 11, 6, 8, 8, 17, tzinfo=UTC)
    boot = row(27, 256180, provider="Microsoft-Windows-Kernel-Boot", data={"BootType": "0"})
    boot["timestamp"] = "2026-11-06T06:10:35.9631750Z"
    power = row(41, 256200)
    power["timestamp"] = "2026-11-06T06:10:37.7190788Z"
    records = [boot, power]
    install_eventlog(monkeypatch, records)
    source = native.WindowsPowerSource(reader=native._read_system)
    source._notifications_ready = True
    initial = await source.read_page(None, now=observed)
    assert len(initial.events) == 2
    assert json.loads(initial.checkpoint)["record_anchor"] == (
        "a70931f4f02f48a831492c3e046d5aa44ab2217366f039503f2b8e904c95b017"
    )
    records.insert(0, row(unrelated_event_id, 256200, when=observed - timedelta(days=1), provider="CProCtrl"))
    spool = PowerEventSpool(tmp_path)
    await spool.open()
    await spool.commit_page(replace(initial, reset_count=7), now=observed)
    original_events = (await spool.next_batch(now=observed)).events
    for tick in range(3):
        page = await source.read_page(await spool.checkpoint(), now=observed + timedelta(seconds=5 * tick))
        assert page.reset_count == page.loss_count == 0 and not page.events
        assert page.status.availability == "READY"
        assert json.loads(page.checkpoint) == json.loads(initial.checkpoint)
        await spool.commit_page(page, now=observed)
    assert (await spool.source_status()).reset_count == 7
    assert (await spool.next_batch(now=observed)).events == original_events


@pytest.mark.parametrize("duplicates", [2, 3, 129])
async def test_conflicting_power_record_ids_degrade_without_reset_replay(monkeypatch, duplicates):
    boot = row(27, 10, provider="Microsoft-Windows-Kernel-Boot", data={"BootType": "0"})
    power = row(107, 100)
    records = [boot, power]
    reads = []
    handles = install_eventlog(monkeypatch, records, reads=reads)
    source = native.WindowsPowerSource(reader=native._read_system)
    source._notifications_ready = True
    initial = await source.read_page(None, now=NOW)
    records[1:1] = [row(42, 100, when=NOW - timedelta(minutes=i + 1)) for i in range(duplicates - 1)]
    # A later event must wait while the retained stream identity is ambiguous.
    records.append(row(107, 101, when=NOW + timedelta(seconds=1)))
    for tick in range(3):
        page = await source.read_page(initial.checkpoint, now=NOW + timedelta(seconds=5 * (tick + 1)))
        assert not page.events and page.reset_count == page.loss_count == 0
        assert page.status.availability == "DEGRADED"
        assert json.loads(page.checkpoint) == json.loads(initial.checkpoint)
        assert source.notification_event(18, now=NOW) is None
        assert all(handle.closed for handle in handles)
    anchor_reads = [count for expression, count in reads if "EventRecordID=100" in expression]
    assert anchor_reads and max(anchor_reads) <= 2
    # Removing ambiguity resumes without counter resets or missing the later fact.
    records[:] = [boot, power, records[-1]]
    recovered = await source.read_page(initial.checkpoint, now=NOW + timedelta(seconds=20))
    assert recovered.status.availability == "READY" and recovered.reset_count == 0
    assert [event.native_record_id for event in recovered.events] == ["101"]
    assert source.notification_event(18, now=NOW + timedelta(seconds=20)) is not None
    assert all(handle.closed for handle in handles)
