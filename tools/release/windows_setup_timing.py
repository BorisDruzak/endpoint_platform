"""Measure a completed Windows Full Setup upgrade from matching Lab receipts."""

from datetime import datetime, timedelta
from pathlib import Path
import re
from uuid import UUID

from endpoint_contracts.runtime_payload import read_json
from tools.release.agent_candidate_artifacts import verify_recorded_candidate
from tools.release.agent_reservations import reservation_status


MAX_RECEIPT_BYTES = 131072
MAX_EVENTS = 256
RELEASE_FIELDS = ("version", "source_revision", "sha256", "msi_sha256")
FOUNDATION_FIELDS = ("version", "source_revision", "package_sha256", "product_code")
PROOF_FLAGS = ("native_verified", "core_verified", "provenance_verified", "services_verified", "companions_restored")


def add_arguments(parser):
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--request-id", type=UUID, required=True)
    parser.add_argument("--assignment-id", type=UUID, required=True)
    parser.add_argument("--artifacts-dir", type=Path, required=True)
    parser.add_argument("--windows-receipt", type=Path, required=True)
    parser.add_argument("--provider-receipt", type=Path, required=True)


def _read_receipt(path):
    with path.open("rb") as stream:
        return read_json(stream.read(MAX_RECEIPT_BYTES + 1), MAX_RECEIPT_BYTES)


def report(args):
    candidate = verify_recorded_candidate(reservation_status(args), "windows", args.artifacts_dir)
    return verify(candidate, _read_receipt(args.windows_receipt), _read_receipt(args.provider_receipt),
                  args.assignment_id)


def _identifier(value: str) -> UUID:
    identifier = UUID(value)
    if not identifier.int:
        raise ValueError("Evidence identifier must not be empty")
    return identifier


def _timestamp(value: str) -> datetime:
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.utcoffset() is None:
        raise ValueError("Evidence timestamp requires an explicit UTC offset")
    return result


def _fields(record: dict, names: tuple) -> dict:
    return {name: record[name] for name in names}


def _native_zero(value) -> bool:
    return type(value) is int and value == 0


def _positive_int(value) -> bool:
    return type(value) is int and value > 0


def _matches(value, pattern) -> bool:
    return isinstance(value, str) and re.fullmatch(pattern, value) is not None


def _foundation(record: dict) -> dict:
    result = _fields(record, FOUNDATION_FIELDS)
    if not (_matches(result["version"], r"[0-9]+\.[0-9]+\.[0-9]+")
            and _matches(result["source_revision"], r"[a-f0-9]{40}")
            and _matches(result["package_sha256"], r"[a-f0-9]{64}")):
        raise ValueError("Invalid Foundation evidence")
    result["product_code"] = str(_identifier(result["product_code"]))
    return result


def _provider_times(provider: dict, target: dict, attempt_id: UUID, source: dict) -> dict:
    report = provider["report"]
    proof = report["proof"]
    if (provider["status"] != "applied" or report["phase"] != "applied"
            or report["safe_code"] != "setup_post_restart_confirmed"
            or _identifier(report["attempt_id"]) != attempt_id
            or provider["source_foundation_version"] != source["version"]
            or not _native_zero(proof["exit_code"]) or proof["native_phase"] != "accepted"
            or proof["pending"] is not False or any(proof[flag] is not True for flag in PROOF_FLAGS)
            or proof["foundation_version"] != target["version"] or proof["core_version"] != target["version"]
            or proof["source_revision"] != target["source_revision"] or proof["msi_sha256"] != target["msi_sha256"]):
        raise ValueError("Provider receipt requires an applied exact-target native operation")
    soak = proof["soak"]
    duration = soak["duration_seconds"]
    assigned = _timestamp(provider["assigned_at"])
    finished = _timestamp(provider["finished_at"])
    elapsed = (finished - assigned).total_seconds()
    if (type(duration) not in (float, int) or not 180 <= duration <= elapsed
            or not _positive_int(soak["samples"]) or not _positive_int(soak["sensor_count"])
            or any(soak[flag] is not True for flag in ("services_stable", "companions_stable", "connected"))):
        raise ValueError("Provider receipt requires stable service and active-user observation")
    return {"assignment_to_applied": round(elapsed, 3), "reported_soak": round(duration, 3)}


def _replacement(events, created, ended, owner_created, source_version, target_version):
    if not isinstance(events, list) or not 4 <= len(events) <= MAX_EVENTS:
        raise ValueError("Missing or oversized Windows Installer event window")
    pending = {}
    transactions = []
    products = []
    previous_id, previous_time = 0, created
    for event in events:
        at = _timestamp(event["at"])
        record_id, event_id, pid = event["record_id"], event["event_id"], event["pid"]
        if (not _positive_int(record_id) or record_id <= previous_id or not _positive_int(pid)
                or not previous_time <= at <= ended):
            raise ValueError("Windows Installer events are outside the ordered native process window")
        previous_id, previous_time = record_id, at
        if event_id in (1033, 1034):
            products.append(event)
            continue
        digest = event["transaction_sha256"]
        if event_id not in (1040, 1042) or not _matches(digest, r"[a-f0-9]{64}"):
            raise ValueError("Unrecognized Windows Installer transaction boundary")
        key = (pid, digest)
        if event_id == 1040 and key not in pending:
            pending[key] = (record_id, at)
        elif event_id == 1042 and key in pending:
            transactions.append((pending.pop(key), (record_id, at), pid))
        else:
            raise ValueError("Unpaired or duplicate Windows Installer transaction boundary")
    matches = []
    for start, end, pid in transactions:
        if start[1] < owner_created:
            continue
        bracketed = [event for event in products
                     if event["pid"] == pid and start[0] < event["record_id"] < end[0]]
        signature = [(event["event_id"], event["version"]) for event in bracketed]
        if signature == [(1034, source_version), (1033, target_version)]:
            if not all(_native_zero(event["result"]) for event in bracketed):
                raise ValueError("Windows Installer replacement reported a failed product event")
            matches.append((start, end, bracketed))
    if pending or len(matches) != 1:
        raise ValueError("Product events do not identify one exact Windows Installer replacement")
    start, end, bracketed = matches[0]
    return start[1], end[1], [start[0], bracketed[0]["record_id"], bracketed[1]["record_id"], end[0]]


def verify(candidate: dict, windows: dict, provider: dict, assignment_id: UUID) -> dict:
    for receipt in (windows, provider):
        if type(receipt["schema_version"]) is not int or receipt["schema_version"] != 1:
            raise ValueError("Unsupported Windows timing receipt schema")
        if _identifier(receipt["assignment_id"]) != assignment_id:
            raise ValueError("Timing receipt belongs to another assignment")
    attempt_id = _identifier(windows["attempt_id"])
    device_id = _identifier(windows["device_id"])
    if _identifier(provider["attempt_id"]) != attempt_id or _identifier(provider["device_id"]) != device_id:
        raise ValueError("Windows and provider timing receipts disagree on attempt or device")

    target = {"version": candidate["version"], "source_revision": candidate["build_revision"],
              "sha256": candidate["artifacts"]["setup"]["sha256"],
              "msi_sha256": candidate["artifacts"]["msi"]["sha256"]}
    if any(_fields(receipt["release"], RELEASE_FIELDS) != target for receipt in (windows, provider)):
        raise ValueError("Timing receipts differ from the recorded candidate")
    release_id = _identifier(provider["release"]["id"])
    if windows["release"]["id"] is not None and _identifier(windows["release"]["id"]) != release_id:
        raise ValueError("Windows receipt refers to another provider release")
    native, staged = windows["native"], windows["staged"]
    if (windows["phase"] != "applied" or native["phase"] != "accepted" or native["started"] is not True
            or not _native_zero(native["exit_code"]) or not _positive_int(native["pid"])
            or staged["schema"] != "endpoint_windows_staged_update_v1" or staged["phase"] != "accepted"
            or not _positive_int(staged["owner_pid"])):
        raise ValueError("Windows timing requires applied Setup and a known native exit 0")
    operation_id = _identifier(staged["operation_id"])
    if staged["previous_operation_id"] is not None and operation_id == _identifier(staged["previous_operation_id"]):
        raise ValueError("Staged journal predates this Setup job")
    source = _foundation(windows["source"])
    installed = _foundation(staged["new"])
    if (windows["source"]["native_verified"] is not True or _foundation(staged["old"]) != source
            or source["version"] == target["version"] or source["product_code"] == installed["product_code"]
            or installed["version"] != target["version"] or installed["source_revision"] != target["source_revision"]
            or installed["package_sha256"] != target["msi_sha256"]):
        raise ValueError("Staged journal does not bind the verified old and exact target Foundation")

    created, ended = _timestamp(native["created_at"]), _timestamp(native["ended_at"])
    boot, owner_created = _timestamp(windows["boot_at"]), _timestamp(staged["owner_created_at"])
    written = _timestamp(staged["last_write_at"])
    if not (boot <= created <= owner_created <= written <= ended and timedelta(0) < ended - created <= timedelta(days=1)):
        raise ValueError("Windows evidence does not fit one native process in the observed boot")
    if not (_matches(windows["edition"], r"[A-Za-z0-9]{1,40}") and _matches(windows["build"], r"[0-9]+\.[0-9]+")):
        raise ValueError("Invalid Windows edition or build")
    start, end, event_ids = _replacement(windows["events"], created, ended, owner_created,
                                         source["version"], target["version"])
    if not owner_created <= start < end <= written:
        raise ValueError("Replacement does not precede the accepted staged journal write")
    return {
        "schema_version": 1,
        "assignment_id": str(assignment_id), "attempt_id": str(attempt_id),
        "device_id": str(device_id), "operation_id": str(operation_id),
        "release": {"id": str(release_id), **target},
        "source_foundation": source,
        "windows": {"edition": windows["edition"], "build": windows["build"]},
        "replacement_event_ids": event_ids,
        "windows_seconds": {
            "native_process": round((ended - created).total_seconds(), 3),
            "before_replacement": round((start - created).total_seconds(), 3),
            "replacement_msi": round((end - start).total_seconds(), 3),
            "replacement_end_to_journal_write": round((written - end).total_seconds(), 3),
            "journal_write_to_native_exit": round((ended - written).total_seconds(), 3),
        },
        "provider_seconds": _provider_times(provider, target, attempt_id, source),
    }
