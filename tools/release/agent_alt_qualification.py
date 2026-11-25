"""Keep exact first-enrollment acceptance in the protected release ledger."""

from argparse import Namespace
from datetime import datetime, timedelta, timezone
from uuid import UUID

from tools.release import agent_reservations as ledger
from tools.release.agent_candidate_artifacts import get_recorded_candidate


_FIELD = "alt_enrollment_qualifications"
_EVIDENCE_IDS = ("device_id", "enrollment_request_id", "native_release_id",
                 "native_event_id", "session_id", "baseline_snapshot_id")
_FIELDS = ("schema_version", "platform", "scope", "state", "request_id", "version", "build_revision",
           "kit_sha256", "enrollment_status", "native_sequence", "checked_at", "activity_collected_at", *_EVIDENCE_IDS)
_RETRY_IDENTITY = ("qualification_id", "valid_until", "request_id", "build_revision", "kit_sha256", *_EVIDENCE_IDS)
_MAX_VALIDITY = timedelta(days=30)


def _timestamp(value):
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError("ALT qualification timestamps must include a UTC offset")
    return parsed.astimezone(timezone.utc)


def _validated(record, candidate):
    if (record["request_id"], record["version"], record["build_revision"], record["kit_sha256"]) != (
        candidate["request_id"], candidate["version"], candidate["build_revision"],
        candidate["artifacts"]["archive"]["sha256"],
    ):
        raise ValueError("ALT qualification belongs to a different candidate")
    if (type(record["schema_version"]) is not int or record["schema_version"] != 1
            or record["platform"] != "alt" or record["scope"] != "first_enrollment" or record["state"] != "accepted"
            or record["enrollment_status"] not in ("device_registered", "waiting_wss", "completed")
            or type(record["native_sequence"]) is not int or record["native_sequence"] != 1):
        raise ValueError("An accepted first-enrollment observation is required")
    if any(str(UUID(record[key])) != record[key] for key in ("qualification_id", *_EVIDENCE_IDS)):
        raise ValueError("ALT qualification requires canonical evidence IDs")
    checked, expires = _timestamp(record["checked_at"]), _timestamp(record["valid_until"])
    activity = _timestamp(record["activity_collected_at"])
    if not checked - timedelta(seconds=150) <= activity <= checked or not checked < expires <= checked + _MAX_VALIDITY:
        raise ValueError("ALT qualification timestamps exceed the allowed observation or validity window")
    return checked, expires


def record(args: Namespace, receipt: dict, *, now=None) -> dict:
    """Append only evidence returned by the live verifier on the publisher."""
    root = args.repo_root
    qualification_id = str(args.qualification_id)
    result = {key: receipt[key] for key in _FIELDS}
    result.update(qualification_id=qualification_id, valid_until=_timestamp(args.valid_until).isoformat())
    for _ in range(8):
        head = ledger._remote_head(root)
        entries = ledger._ledger(root, head)
        reserved = ledger._find_request(entries, str(args.request_id))
        candidate = get_recorded_candidate(reserved, "alt")
        checked, expires = _validated(result, candidate)
        current = now or datetime.now(timezone.utc)
        if not current - timedelta(seconds=90) <= checked <= current < expires:
            raise ValueError("Live ALT qualification must still be fresh at recording")
        records = reserved.get(_FIELD, {})
        if existing := records.get(qualification_id):
            _validated(existing, candidate)
            if any(existing[key] != result[key] for key in _RETRY_IDENTITY):
                raise ValueError("ALT qualification ID already bound to different evidence or validity")
            return existing
        updated = {**reserved, _FIELD: {**records, qualification_id: result}}
        if ledger._append(root, head, [updated if entry is reserved else entry for entry in entries],
                          "record ALT first-enrollment qualification"):
            return result
        if ledger._remote_head(root) == head:
            raise ValueError("Git rejected the qualification; retry with the same qualification ID")
    raise ValueError("Reservation ledger is busy; retry with the same qualification ID")


def require(args: Namespace, *, now=None) -> tuple[dict, dict]:
    reserved = ledger.reservation_status(args)
    candidate = get_recorded_candidate(reserved, "alt")
    qualification_id = str(args.qualification_id)
    qualification = reserved.get(_FIELD, {}).get(qualification_id)
    if qualification is None or qualification["qualification_id"] != qualification_id:
        raise ValueError("Recorded ALT first-enrollment qualification is required")
    checked, expires = _validated(qualification, candidate)
    if not checked <= (now or datetime.now(timezone.utc)) < expires:
        raise ValueError("ALT first-enrollment qualification is expired or not yet valid")
    return candidate, qualification
