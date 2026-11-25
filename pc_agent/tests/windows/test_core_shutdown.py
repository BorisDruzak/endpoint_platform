from contextlib import nullcontext
from dataclasses import asdict
from uuid import uuid4

import pytest

from pc_agent.platform.windows import core_shutdown as proof


@pytest.fixture
def proofs(tmp_path, monkeypatch):
    from pc_agent.platform.windows.update_paths import WindowsUpdatePaths
    paths = WindowsUpdatePaths(tmp_path, tmp_path / "updates" / "pending_update.json")
    state = {"boot": str(uuid4()), "event": 10, "owner": None, "flushes": []}
    monkeypatch.setattr(proof, "_native_boot_id", lambda: state["boot"])
    monkeypatch.setattr(proof, "_native_cold_boot_event", lambda: state["event"])
    monkeypatch.setattr(proof, "_event_watermark", lambda: state.get("watermark"))
    monkeypatch.setattr(proof, "_kernel_boot_counter", lambda: None, raising=False)
    monkeypatch.setattr(proof, "_read_owner", lambda _: state["owner"])
    monkeypatch.setattr(proof, "_write_owner", lambda _, owner: state.update(owner=owner))
    monkeypatch.setattr(proof, "core_shutdown_gate", lambda _: nullcontext())
    monkeypatch.setattr(proof, "flush_directory", state["flushes"].append)
    return paths, state


SELECTOR = b'{"version":"3.2.253"}'


def test_missing_legacy_authority_stays_pending_until_new_cold_boot(proofs):
    paths, state = proofs
    assert proof.capture_core_owner(paths, SELECTOR) is None
    first = proof.reserve_core_owner(paths, SELECTOR)
    proof.record_core_stopped(paths, first)
    assert proof.capture_core_owner(paths, SELECTOR) is None
    with pytest.raises(proof.CoreShutdownUnconfirmed):
        proof.require_core_stopped(paths, SELECTOR, first)
    state["boot"] = str(uuid4())
    assert proof.capture_core_owner(paths, SELECTOR) is None  # stale event can't corroborate changed GUID
    state["event"] += 1
    captured = proof.capture_core_owner(paths, SELECTOR)
    assert captured.run_id == first.run_id
    proof.require_core_stopped(paths, SELECTOR, captured)
    assert state["flushes"] == [paths.updates_root]


def test_uncertain_previous_run_survives_same_boot_successful_replacement(proofs):
    paths, state = proofs
    orphan = proof.reserve_core_owner(paths, SELECTOR)  # no stop receipt
    replacement = proof.reserve_core_owner(paths, SELECTOR)
    assert orphan.run_id != replacement.run_id and replacement.unresolved
    proof.record_core_stopped(paths, replacement)
    assert proof.capture_core_owner(paths, SELECTOR) is None
    state["event"] += 1
    assert proof.capture_core_owner(paths, SELECTOR) is None  # event alone is insufficient


def test_delayed_cold_boot_event_does_not_discard_original_debt_anchor(proofs):
    paths, state = proofs
    previous = proof.reserve_core_owner(paths, SELECTOR)
    state["boot"] = str(uuid4())
    replacement = proof.reserve_core_owner(paths, SELECTOR)
    assert replacement.unresolved and replacement.debt_boot_id == previous.boot_id
    assert replacement.debt_boot_event == previous.boot_event
    proof.record_core_stopped(paths, replacement)
    assert proof.capture_core_owner(paths, SELECTOR) is None
    state["event"] += 1
    captured = proof.capture_core_owner(paths, SELECTOR)
    proof.require_core_stopped(paths, SELECTOR, captured)


def test_expected_selector_bytes_and_run_must_match_at_consumption(proofs):
    paths, state = proofs
    proof.reserve_core_owner(paths, SELECTOR)
    state["boot"] = str(uuid4())
    state["event"] += 1
    first = proof.reserve_core_owner(paths, SELECTOR)
    assert not first.unresolved
    old = proof.capture_core_owner(paths, SELECTOR)
    assert old == first
    with pytest.raises(proof.CoreShutdownUnconfirmed):
        proof.require_core_stopped(paths, SELECTOR, old)
    proof.record_core_stopped(paths, first)
    assert proof.capture_core_owner(paths, SELECTOR + b"\n") is None
    proof.require_core_stopped(paths, SELECTOR, old)
    new = proof.reserve_core_owner(paths, SELECTOR)
    proof.record_core_stopped(paths, new)
    with pytest.raises(proof.CoreShutdownUnconfirmed):
        proof.require_core_stopped(paths, SELECTOR, old)


def test_evicted_old_boot_event_needs_new_cold_event_above_watermark(proofs):
    paths, state = proofs
    state.update(event=None, watermark=40)
    old = proof.reserve_core_owner(paths, SELECTOR)
    assert old.boot_event == 40
    state["boot"] = str(uuid4())
    state["event"] = 39
    assert proof.capture_core_owner(paths, SELECTOR) is None
    state["event"] = 41
    proof.require_core_stopped(paths, SELECTOR, old)


@pytest.mark.parametrize("boot_type, expected", [(0, 32), (1, None), (2, None)])
def test_only_explicit_cold_boot_system_event_can_corroborate_guid(monkeypatch, boot_type, expected):
    monkeypatch.setattr(proof, "_last_system_event", lambda _: {"record_id": 32, "data": {"BootType": boot_type}})
    assert proof._native_cold_boot_event() == expected

BOOT_SHA = "b" * 64


def set_boot_events(state, *, counter, records, previous, boot_type=0, anchor_ok=True):
    start, status, cold = records
    state.update(counter=counter, event=cold if boot_type == 0 else None, watermark=cold + 41,
                 records=(start, status, cold), previous=previous, boot_type=boot_type,
                 anchor_ok=anchor_ok)


@pytest.fixture
def stable_proofs(proofs, monkeypatch):
    paths, state = proofs
    set_boot_events(state, counter=6, records=(445, 447, 449), previous=5)
    monkeypatch.setattr(proof, "_kernel_boot_counter", lambda: state["counter"])

    def system_event(query):
        if "EventRecordID" in query:
            record = int(query.split("EventRecordID=")[1].split("]")[0])
            if state["anchor_ok"] or record == state["watermark"]:
                digest = BOOT_SHA if record == state["watermark"] else state.get("past_anchor", BOOT_SHA)
                return {"record_id": record, "event_sha256": digest}
            return None
        start, status, cold = state["records"]
        if "EventID=12" in query:
            return {"record_id": start, "data": {"BootMode": "0"}}
        if "EventID=20" in query:
            return {"record_id": status, "data": {"LastBootId": str(state["previous"])}}
        if "EventID=27" in query:
            return {"record_id": cold, "data": {"BootType": str(state["boot_type"])}}
        return {"record_id": state["watermark"], "event_sha256": BOOT_SHA}

    monkeypatch.setattr(proof, "_last_system_event", system_event)
    return paths, state


def test_stable_guid_ordinary_restart_releases_exact_prior_owner(stable_proofs):
    paths, state = stable_proofs
    first = proof.reserve_core_owner(paths, SELECTOR)
    assert first.unresolved
    assert proof.capture_core_owner(paths, SELECTOR) is None
    set_boot_events(state, counter=7, records=(500, 502, 504), previous=6)
    captured = proof.capture_core_owner(paths, SELECTOR)
    assert captured == first
    proof.require_core_stopped(paths, SELECTOR, captured)
    second = proof.reserve_core_owner(paths, SELECTOR)
    assert not second.unresolved
    with pytest.raises(proof.CoreShutdownUnconfirmed):
        proof.require_core_stopped(paths, SELECTOR, captured)
    proof.record_core_stopped(paths, second)
    proof.require_core_stopped(paths, SELECTOR, second)


@pytest.mark.parametrize(("counter", "records", "previous", "boot_type", "anchor_ok"), [
    (6, (500, 502, 504), 5, 0, True),  # Same generation.
    (7, (500, 502, 504), 5, 0, True),  # New counter with delayed journal.
    (7, (489, 502, 504), 6, 0, True),  # Cluster starts before prior watermark.
    (7, (500, 499, 504), 6, 0, True),  # Inconsistent order.
    (7, (500, 502, 504), 6, 1, True),  # Hybrid.
    (7, (500, 502, 504), 6, 2, True),  # Resume.
    (7, (500, 502, 504), 6, 0, False), # Prior watermark evicted/reset.
    (None, (500, 502, 504), 6, 0, True),
    (1, (500, 502, 504), 0, 0, True),  # Reset/wrap.
])
def test_stable_guid_rejects_unproven_generation(stable_proofs, counter, records, previous, boot_type, anchor_ok):
    paths, state = stable_proofs
    first = proof.reserve_core_owner(paths, SELECTOR)
    set_boot_events(state, counter=counter, records=records, previous=previous,
                    boot_type=boot_type, anchor_ok=anchor_ok)
    assert proof.capture_core_owner(paths, SELECTOR) is None
    with pytest.raises(proof.CoreShutdownUnconfirmed):
        proof.require_core_stopped(paths, SELECTOR, first)


def test_legacy_owner_acquires_baseline_without_releasing_current_debt(stable_proofs):
    paths, state = stable_proofs
    state["counter"] = None
    old = proof.reserve_core_owner(paths, SELECTOR)
    proof.record_core_stopped(paths, old)
    set_boot_events(state, counter=7, records=(500, 502, 504), previous=6)
    assert proof.capture_core_owner(paths, SELECTOR) is None
    baseline = proof.reserve_core_owner(paths, SELECTOR)
    assert baseline.unresolved
    proof.record_core_stopped(paths, baseline)
    assert proof.capture_core_owner(paths, SELECTOR) is None
    set_boot_events(state, counter=8, records=(600, 602, 604), previous=7)
    proof.require_core_stopped(paths, SELECTOR, baseline)


def test_stable_guid_cannot_release_owner_when_system_record_was_replaced(stable_proofs):
    paths, state = stable_proofs
    first = proof.reserve_core_owner(paths, SELECTOR)
    proof.record_core_stopped(paths, first)
    set_boot_events(state, counter=7, records=(500, 502, 504), previous=6)
    state["past_anchor"] = "c" * 64
    assert proof.capture_core_owner(paths, SELECTOR) is None


@pytest.mark.parametrize("replaced", [False, True])
def test_evicted_debt_can_rebaseline_only_at_reservation_then_requires_restart(stable_proofs, replaced):
    paths, state = stable_proofs
    first = proof.reserve_core_owner(paths, SELECTOR)
    proof.record_core_stopped(paths, first)
    set_boot_events(state, counter=7, records=(500, 502, 504), previous=6, anchor_ok=replaced)
    if replaced:
        state["past_anchor"] = "c" * 64
    baseline = proof.reserve_core_owner(paths, SELECTOR)
    assert baseline.unresolved
    proof.record_core_stopped(paths, baseline)
    assert proof.capture_core_owner(paths, SELECTOR) is None
    assert baseline.debt_boot_event == 545
    assert baseline.debt_boot_stamp == baseline.boot_stamp

    set_boot_events(state, counter=8, records=(561, 563, 565), previous=7)
    state.pop("past_anchor", None)
    proof.require_core_stopped(paths, SELECTOR, baseline)


@pytest.mark.parametrize("schema", [1, 2])
def test_read_owner_accepts_original_and_new_protected_schema(monkeypatch, tmp_path, schema):
    from pc_agent.platform.windows.update_paths import WindowsUpdatePaths

    path = WindowsUpdatePaths(tmp_path, tmp_path / "updates" / "pending_update.json")
    boot = str(uuid4())
    stamp = proof.BootStamp(7, BOOT_SHA) if schema == 2 else None
    owner = proof.CoreOwner(boot, str(uuid4()), BOOT_SHA, "running", True, 490, boot, 490, stamp, stamp)
    data = {"schema_version": schema, **asdict(owner)}
    if schema == 1:
        del data["boot_stamp"], data["debt_boot_stamp"]
    monkeypatch.setattr(proof, "_read_state", lambda *_: dict(data))
    assert proof._read_owner(path) == owner
    data["schema_version"] = True
    assert proof._read_owner(path) is None
