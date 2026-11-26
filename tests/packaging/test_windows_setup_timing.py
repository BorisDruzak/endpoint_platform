"""Timing diagnostics must bind Windows and provider receipts to identical bytes."""

from copy import deepcopy
from uuid import UUID

import pytest

from tools.release.windows_setup_timing import verify


ASSIGNMENT = UUID("3d8a83b3-cb3b-4b2d-b0ec-c632403041e2")
ATTEMPT = "9084840f-f2aa-45d7-bdc0-bc6e2d23a9b9"
DEVICE = "a0093b32-f33d-4d69-bb76-9733fccddf8d"
RELEASE = "b5435048-2352-477a-b947-b14772b76a78"
TARGET = {"version": "3.2.276", "source_revision": "4" * 40, "sha256": "a" * 64, "msi_sha256": "b" * 64}
SOURCE = {"version": "3.2.205", "source_revision": "5" * 40, "package_sha256": "c" * 64,
          "product_code": "bb088838-672a-4c0c-860f-f0a683f3215c"}


def timestamp(time):
    return f"2026-11-25T{time}Z"


def boundary(record, event_id, time, digest):
    return {"record_id": record, "event_id": event_id, "at": timestamp(time),
            "pid": 6828, "transaction_sha256": digest * 64}


def product(record, event_id, time, version):
    return {"record_id": record, "event_id": event_id, "at": timestamp(time),
            "pid": 6828, "version": version, "result": 0}


@pytest.fixture
def evidence():
    identity = {"schema_version": 1, "assignment_id": str(ASSIGNMENT), "attempt_id": ATTEMPT, "device_id": DEVICE}
    candidate = {"version": TARGET["version"], "build_revision": TARGET["source_revision"], "artifacts": {
        "setup": {"sha256": TARGET["sha256"]}, "msi": {"sha256": TARGET["msi_sha256"]},
    }}
    windows = {
        **identity, "phase": "applied", "release": {**TARGET, "id": None}, "edition": "EnterpriseSEval",
        "build": "26100.9457", "boot_at": timestamp("21:28:24.5000000"),
        "native": {"pid": 1160, "started": True, "exit_code": 0, "phase": "accepted",
                   "created_at": timestamp("21:34:00.5391800"), "ended_at": timestamp("21:41:09.4118102")},
        "source": {**SOURCE, "native_verified": True},
        "staged": {"schema": "endpoint_windows_staged_update_v1", "phase": "accepted",
                   "old": deepcopy(SOURCE), "new": {
                       "version": TARGET["version"], "source_revision": TARGET["source_revision"],
                       "package_sha256": TARGET["msi_sha256"], "product_code": "b691c994-3a6e-4734-92af-21be3194072c",
                   }, "operation_id": "a90bd749-03fe-4b0e-ae1d-af4e1eca538a", "previous_operation_id": None,
                   "owner_pid": 6152, "owner_created_at": timestamp("21:34:19.0117047"),
                   "last_write_at": timestamp("21:39:44.7525279")},
        "events": [
            {**product(1152, 1033, "21:34:15.6300611", TARGET["version"]), "pid": 6024},
            {**product(1154, 1033, "21:34:15.9001779", SOURCE["version"]), "pid": 6024},
            boundary(1166, 1040, "21:36:38.8961497", "d"),
            product(1177, 1034, "21:36:53.3253714", SOURCE["version"]),
            product(1186, 1033, "21:37:40.3624275", TARGET["version"]),
            boundary(1190, 1042, "21:38:01.7494718", "d"),
            boundary(1191, 1040, "21:38:02", "e"),
            boundary(1192, 1042, "21:38:03", "e"),
        ],
    }
    provider = {
        **identity, "status": "applied", "release": {**TARGET, "id": RELEASE},
        "source_foundation_version": SOURCE["version"], "assigned_at": timestamp("21:32:42.792059"),
        "finished_at": timestamp("21:44:34.140183"),
        "report": {"phase": "applied", "safe_code": "setup_post_restart_confirmed", "attempt_id": ATTEMPT,
                   "proof": {"exit_code": 0, "native_phase": "accepted", "native_verified": True,
                             "foundation_version": TARGET["version"], "core_version": TARGET["version"],
                             "source_revision": TARGET["source_revision"], "msi_sha256": TARGET["msi_sha256"],
                             "pending": False, "core_verified": True, "provenance_verified": True,
                             "services_verified": True, "companions_restored": True,
                             "soak": {"duration_seconds": 182.932, "sensor_count": 1, "samples": 6,
                                      "services_stable": True, "companions_stable": True, "connected": True}}},
    }
    return candidate, windows, provider


def test_separates_replacement_from_other_same_pid_transactions(evidence):
    result = verify(*evidence, ASSIGNMENT)
    assert result["windows_seconds"] == {
        "native_process": 428.873, "before_replacement": 158.357, "replacement_msi": 82.853,
        "replacement_end_to_journal_write": 103.003, "journal_write_to_native_exit": 84.659,
    }
    assert result["provider_seconds"] == {"assignment_to_applied": 711.348, "reported_soak": 182.932}
    assert result["replacement_event_ids"] == [1166, 1177, 1186, 1190]


@pytest.mark.parametrize(("receipt", "path", "value"), [
    (1, ("assignment_id",), DEVICE),
    (2, ("attempt_id",), DEVICE),
    (2, ("report", "attempt_id"), DEVICE),
    (2, ("device_id",), ATTEMPT),
    (1, ("release", "sha256"), "f" * 64),
    (2, ("release", "msi_sha256"), "f" * 64),
    (1, ("release", "source_revision"), "f" * 40),
    (2, ("report", "proof", "msi_sha256"), "f" * 64),
    (1, ("native", "exit_code"), False),
    (1, ("native", "exit_code"), 21),
    (1, ("native", "ended_at"), "2026-11-25T21:41:09"),
    (1, ("staged", "last_write_at"), timestamp("21:41:10")),
    (1, ("staged", "previous_operation_id"), "a90bd749-03fe-4b0e-ae1d-af4e1eca538a"),
    (1, ("staged", "old", "package_sha256"), "f" * 64),
    (2, ("report", "proof", "soak", "duration_seconds"), 90),
    (2, ("report", "phase"), "verifying"),
])
def test_refuses_unbound_or_unsettled_receipt(evidence, receipt, path, value):
    record = evidence[receipt]
    for name in path[:-1]:
        record = record[name]
    record[path[-1]] = value
    with pytest.raises(ValueError):
        verify(*evidence, ASSIGNMENT)


def test_refuses_ambiguous_or_unpaired_replacement_events(evidence):
    candidate, windows, provider = evidence
    events = windows["events"]
    events.insert(3, boundary(1167, 1040, "21:36:39", "d"))
    with pytest.raises(ValueError):
        verify(candidate, windows, provider, ASSIGNMENT)
    events.pop(3)
    events[5]["transaction_sha256"] = "e" * 64
    with pytest.raises(ValueError):
        verify(candidate, windows, provider, ASSIGNMENT)


def test_refuses_two_plausible_replacement_transactions(evidence):
    candidate, windows, provider = evidence
    windows["events"].extend([
        boundary(1193, 1040, "21:38:05", "f"),
        product(1194, 1034, "21:38:11", SOURCE["version"]),
        product(1195, 1033, "21:38:19", TARGET["version"]),
        boundary(1196, 1042, "21:38:21", "f"),
    ])
    with pytest.raises(ValueError, match="one exact"):
        verify(candidate, windows, provider, ASSIGNMENT)


def test_refuses_failed_windows_installer_product_event(evidence):
    candidate, windows, provider = evidence
    windows["events"][4]["result"] = 1603
    with pytest.raises(ValueError, match="failed product event"):
        verify(candidate, windows, provider, ASSIGNMENT)
