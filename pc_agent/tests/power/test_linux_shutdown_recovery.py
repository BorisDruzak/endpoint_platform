"""ALT systemd258 shutdown evidence and one-time retained checkpoint replay."""

import json
import sqlite3
from datetime import UTC, datetime, timedelta

import pytest

from pc_agent.platform.linux.power_events import LinuxPowerSource, project_journal_page
from pc_agent.power.native import NativePage
from pc_agent.power.spool import PowerEventSpool

NOW = datetime(2026, 10, 24, 17, tzinfo=UTC)
BOOT = "11111111222243338444555555555555"
STARTED = "39f53479d3a045ac8e11786248231fbf"


def shutdown_row(index=101, **changes):
    # Captured ALT K11.4/systemd258.9 shape/time; boot and cursor are synthetic.
    return {
        "__CURSOR": f"s=alt-fixture;i={index}",
        "__REALTIME_TIMESTAMP": "1792859996594029",
        "_BOOT_ID": BOOT,
        "_UID": "0",
        "_PID": "1",
        "_SYSTEMD_UNIT": "init.scope",
        "MESSAGE_ID": STARTED,
        "UNIT": "shutdown.target",
        **changes,
    }


def test_alt_reached_shutdown_target_is_native_transition_with_stable_identity():
    first = project_journal_page([shutdown_row()], None, now=NOW)
    assert len(first.events) == 1
    event = first.events[0]
    assert (event.event_kind, event.evidence) == ("OS_SHUTDOWN_STARTED", "transition")
    assert event.boot_id == BOOT
    assert event.occurred_at == datetime(2026, 10, 24, 16, 39, 56, 594029, tzinfo=UTC)
    assert str(event.event_identifier) == "69525118-be7a-5ffe-9f2c-da9626b5adb7"
    replay = project_journal_page([shutdown_row()], None, now=NOW + timedelta(hours=1))
    assert replay.events[0].event_identifier == event.event_identifier
    assert replay.events[0].occurred_at == event.occurred_at


@pytest.mark.parametrize(
    "changes",
    [
        {"UNIT": "reboot.target"},
        {"UNIT": "user-shutdown.target"},
        {"UNIT": None},
        {"_PID": "999"},
        {"_UID": "1000"},
        {"_SYSTEMD_UNIT": "user@1000.service"},
        {"_SYSTEMD_UNIT": "systemd-logind.service"},
        {"MESSAGE_ID": "be02cf6855d2428ba40df7e9d022f03d"},
    ],
)
def test_reached_target_requires_exact_system_manager_unit_and_success(changes):
    assert not project_journal_page([shutdown_row(**changes)], None, now=NOW).events


class RetainedJournal:
    """The external journal boundary honors native match, time and cursor arguments."""

    def __init__(self, rows):
        self.rows, self.calls = rows, []

    async def __call__(self, args):
        self.calls.append(args)
        assert "--system" in args
        fields = next(arg for arg in args if arg.startswith("--output-fields="))
        assert "MESSAGE" not in fields.removeprefix("--output-fields=").split(",")
        exact = next((arg[9:] for arg in args if arg.startswith("--cursor=")), None)
        if exact:
            return "\n".join(json.dumps(r) for r in self.rows if r["__CURSOR"] == exact)
        rows = self.rows
        after = next(
            (arg[15:] for arg in args if arg.startswith("--after-cursor=")), None
        )
        if after:
            offset = next(i for i, row in enumerate(rows) if row["__CURSOR"] == after)
            rows = rows[offset + 1 :]
        since = next((arg[9:] for arg in args if arg.startswith("--since=@")), None)
        if since:
            rows = [
                r
                for r in rows
                if int(r["__REALTIME_TIMESTAMP"]) >= int(since) * 1000000
            ]
        matches = {arg[11:] for arg in args if arg.startswith("MESSAGE_ID=")}
        rows = [r for r in rows if r["MESSAGE_ID"] in matches]
        return "\n".join(json.dumps(r) for r in rows[:128])


def source(journal):
    result = LinuxPowerSource(
        run=journal,
        boot_reader=lambda: ("current-kernel-boot", NOW - timedelta(minutes=5)),
        persistent=lambda: True,
    )
    result._subscriptions.update({"PrepareForSleep", "PrepareForShutdown"})
    return result


async def test_legacy_cursor_replays_retained_history_once_and_commits_atomically(
    tmp_path,
):
    request = shutdown_row(
        102,
        MESSAGE_ID="98268866d1d54a499c4e98921d93bc40",
        _PID="51",
        _SYSTEMD_UNIT="systemd-logind.service",
    )
    old_page = project_journal_page([request], None, now=NOW)
    legacy = json.dumps(
        {
            "cursor": request["__CURSOR"],
            "coverage": (NOW - timedelta(days=60)).isoformat(),
            "current_boot": "current-kernel-boot",
        }
    )
    spool = PowerEventSpool(tmp_path)
    await spool.open()
    await spool.commit_page(
        NativePage(old_page.events, legacy, old_page.status), now=NOW
    )
    journal = RetainedJournal([shutdown_row(), request])
    recovered = await source(journal).read_page(await spool.checkpoint(), now=NOW)
    assert [e.evidence for e in recovered.events] == ["transition", "request"]
    assert recovered.reset_count == 1
    assert recovered.status.availability == "DEGRADED"
    assert recovered.status.coverage_started_at == recovered.events[0].occurred_at
    assert any(
        arg == f"--since=@{int((NOW - timedelta(days=30)).timestamp())}"
        for arg in journal.calls[0]
    )
    with sqlite3.connect(spool.path) as db:
        db.execute(
            "CREATE TRIGGER reject_migration BEFORE UPDATE ON power_state "
            "BEGIN SELECT RAISE(ABORT,'test'); END"
        )
    with pytest.raises(sqlite3.Error):
        await spool.commit_page(recovered, now=NOW)
    assert await spool.checkpoint() == legacy
    assert (await spool.stats()).queued_events == 1
    with sqlite3.connect(spool.path) as db:
        db.execute("DROP TRIGGER reject_migration")
    retried = await source(journal).read_page(await spool.checkpoint(), now=NOW)
    assert [e.event_identifier for e in retried.events] == [
        e.event_identifier for e in recovered.events
    ]
    await spool.commit_page(retried, now=NOW)
    assert (await spool.stats()).queued_events == 2
    assert (await spool.source_status()).reset_count == 1
    assert json.loads(await spool.checkpoint())["current_boot"] == "current-kernel-boot"
    reopened = PowerEventSpool(tmp_path)
    await reopened.open()
    resumed = await source(journal).read_page(await reopened.checkpoint(), now=NOW)
    assert resumed.events == () and resumed.reset_count == 0
    assert resumed.status.availability == "READY"
    await reopened.commit_page(resumed, now=NOW)
    assert (await reopened.stats()).queued_events == 2
    assert (await reopened.source_status()).reset_count == 1
    assert not any(arg.startswith("--since=") for arg in journal.calls[-1])


async def test_projection_replay_pages_forward_without_reset_or_duplicate_boot():
    rows = [shutdown_row(i) for i in range(130)]
    legacy = json.dumps(
        {"cursor": rows[-1]["__CURSOR"], "current_boot": "current-kernel-boot"}
    )
    journal = RetainedJournal(rows)
    state, found, resets = legacy, [], []
    for _ in range(3):
        page = await source(journal).read_page(state, now=NOW)
        found.extend(page.events)
        resets.append(page.reset_count)
        state = page.checkpoint
    assert resets == [1, 0, 0]
    assert len(found) == len({e.event_identifier for e in found}) == 130
    assert all(e.source == "linux.journal" for e in found)
    assert (
        sum(any(arg.startswith("--since=") for arg in call) for call in journal.calls)
        == 1
    )


async def test_empty_legacy_replay_discards_obsolete_coverage_then_resumes():
    journal = RetainedJournal([])
    old = json.dumps(
        {
            "cursor": "expired",
            "coverage": (NOW - timedelta(days=60)).isoformat(),
            "current_boot": "current-kernel-boot",
        }
    )
    first = await source(journal).read_page(old, now=NOW)
    assert first.events == () and first.reset_count == 1
    assert first.status.coverage_started_at == NOW
    second = await source(journal).read_page(first.checkpoint, now=NOW)
    assert second.events == () and second.reset_count == 0
