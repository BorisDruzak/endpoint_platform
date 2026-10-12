"""Distinct continuation identity, independently pinned local issuer and clocks."""
import time
import threading
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from .codec import canonical, digest, hex256, instant, integer, parse_json, require, uuid
from .history import ORIGINAL_FILES, BASELINE_SHA, SNAPSHOT_SHA

REVIEW_SCOPE = ["creator-authority", "historical-prefix", "exact-source-closure",
                "deadlines", "replay-rollback", "atomic-publication", "no-old-gate-bypass"]
BUDGETS = {"authorization_seconds": 1200, "workload_seconds": 120,
           "settlement_seconds": 10, "ssh_observation_seconds": 145, "persistence_reserve_seconds": 2}
IDENTITY_KEYS = {"host_id", "boot_id", "pid", "birth", "token_sid", "elevated"}
CAPSULE_KEYS = {"schema", "version", "continuation_id", "allowed_seq", "allowed_step",
                "original", "controller", "created_utc", "expires_utc", "created_mono_ns",
                "deadline_mono_ns", "authority_sha256", "review_sha256", "source_closure", "budgets"}
AUTHORITY_KEYS = {"schema", "original", "allowed_seq", "allowed_step", "controller",
                  "source_closure_sha256", "bootstrap_sha256", "request_sha256", "request_reference"}
REVIEW_KEYS = {"schema", "status", "reviewer", "source_closure_sha256", "scope"}
ATTESTATION_KEYS = {"schema", "capsule_sha256", "authority_sha256", "controller"}
TRUST_KEYS = {"authority_sha256", "review_sha256", "attestation_sha256", "bootstrap_sha256",
              "source_closure_sha256", "request_sha256"}


def _identity(identity):
    require(type(identity) is dict and set(identity) == IDENTITY_KEYS, "controller identity schema")
    hex256(identity["host_id"])
    uuid(identity["boot_id"])
    integer(identity["pid"], 1, 2**32 - 1)
    integer(identity["birth"], 1)
    require(type(identity["token_sid"]) is str and identity["token_sid"].startswith("S-1-")
            and identity["elevated"] is True, "elevated creator required")


def create_capsule(prefix, closure, authority, review, identity):
    """Pure factory. Actual trusted bootstrap/store/identity checks precede use."""
    _identity(identity)
    require(authority["original"] == prefix.binding and authority["controller"] == identity,
            "creator original/controller binding")
    require(authority["source_closure_sha256"] == review["source_closure_sha256"] == digest(closure),
            "reviewed source closure required")
    utc, mono = datetime.now(timezone.utc), time.monotonic_ns()
    return {"schema": "task13_continuation_v1", "version": 1,
            "continuation_id": closure.get("continuation_id", str(uuid4())),
            "allowed_seq": 4, "allowed_step": "compare-after-start", "original": prefix.binding,
            "controller": parse_json(canonical(identity)), "created_utc": utc.isoformat(),
            "expires_utc": (utc + timedelta(seconds=1200)).isoformat(), "created_mono_ns": mono,
            "deadline_mono_ns": mono + 1200 * 10**9, "authority_sha256": digest(authority),
            "review_sha256": digest(review), "source_closure": parse_json(canonical(closure)),
            "budgets": dict(BUDGETS)}


def validate_authorization(capsule, authority, attestation, review, trust, identity):
    """Trust is provided by the reviewed bootstrap, never derived from capsule."""
    for value, keys in [(capsule, CAPSULE_KEYS), (authority, AUTHORITY_KEYS),
                        (attestation, ATTESTATION_KEYS), (review, REVIEW_KEYS), (trust, TRUST_KEYS)]:
        require(type(value) is dict and set(value) == keys, "exact authorization schema")
    _identity(identity)
    require(capsule["schema"] == "task13_continuation_v1" and type(capsule["version"]) is int
            and capsule["version"] == 1 and type(capsule["allowed_seq"]) is int
            and capsule["allowed_seq"] == 4 and capsule["allowed_step"] == "compare-after-start",
            "only seq04 is authorized")
    uuid(capsule["continuation_id"])
    original = capsule["original"]
    require(type(original) is dict and set(original) == {"original_run_id","original_plan_sha256",
            "original_run_seal_sha256","original_tip","baseline_sha256","snapshot_identity_sha256",
            "verified_receipt_count","historical_guest_brackets","source_entries","source_prerequisites",
            "original_files","raw_output_retained","historical_evidence_sha256"}, "historical binding schema")
    uuid(original["original_run_id"])
    hex256(original["historical_evidence_sha256"])
    require(capsule["continuation_id"] != original["original_run_id"]
            and original["original_plan_sha256"] == ORIGINAL_FILES["plan.json"]
            and original["original_run_seal_sha256"] == ORIGINAL_FILES["run-seal.json"]
            and original["raw_output_retained"] is False
            and all(type(original[k]) is int and original[k] == v for k,v in {
                "verified_receipt_count":4,"historical_guest_brackets":2,"source_entries":61,"source_prerequisites":305}.items()),
            "distinct continuation and verified historical prefix required")
    require(original["original_files"] == ORIGINAL_FILES
            and original["original_tip"] == ORIGINAL_FILES["receipt-03-start-after-snapshot.json"]
            and original["baseline_sha256"] == BASELINE_SHA
            and original["snapshot_identity_sha256"] == SNAPSHOT_SHA, "immutable historical authorization")
    require(authority["schema"] == "task13_operator_authority_v1"
            and authority["original"] == original and type(authority["allowed_seq"]) is int
            and authority["allowed_seq"] == 4 and authority["allowed_step"] == "compare-after-start"
            and type(authority["request_reference"]) is str and authority["request_reference"],
            "operator permission required")
    require(attestation["schema"] == "task13_creator_attestation_v1"
            and attestation["capsule_sha256"] == digest(capsule)
            and attestation["authority_sha256"] == digest(authority), "capsule creator attestation")
    require(review["schema"] == "task13_source_review_v1" and review["status"] == "PASS"
            and review["scope"] == REVIEW_SCOPE and type(review["reviewer"]) is str and review["reviewer"],
            "independent source review PASS required")
    for value in trust.values():
        hex256(value)
    require(digest(authority) == trust["authority_sha256"] == capsule["authority_sha256"]
            and digest(review) == trust["review_sha256"] == capsule["review_sha256"]
            and digest(attestation) == trust["attestation_sha256"], "independent authority/review pins")
    require(authority["bootstrap_sha256"] == trust["bootstrap_sha256"]
            and authority["request_sha256"] == trust["request_sha256"], "bootstrap/request permission")
    require(digest(capsule["source_closure"]) == authority["source_closure_sha256"]
            == review["source_closure_sha256"] == trust["source_closure_sha256"], "exact reviewed source closure")
    require(identity == capsule["controller"] == authority["controller"] == attestation["controller"],
            "observed controller boot/process/token mismatch")
    require(capsule["budgets"] == BUDGETS and all(type(v) is int for v in capsule["budgets"].values()),
            "sealed execution budgets")
    start, end = instant(capsule["created_utc"]), instant(capsule["expires_utc"])
    created = integer(capsule["created_mono_ns"])
    deadline = integer(capsule["deadline_mono_ns"])
    now, mono = datetime.now(timezone.utc), time.monotonic_ns()
    require(end - start == timedelta(seconds=1200) and deadline - created == 1200 * 10**9,
            "fresh bounded continuation duration")
    require(start <= now < end and created <= mono < deadline - 2 * 10**9, "continuation expired")
    require(abs((now - start).total_seconds() - (mono - created) / 10**9) <= 5,
            "UTC/monotonic divergence")


class LiveAuthorization:
    def __init__(self, capsule, authority, attestation, review, trust, identity):
        self._inputs = tuple(canonical(v) for v in (capsule, authority, attestation, review, trust, identity))
        validate_authorization(*(parse_json(v) for v in self._inputs))
        self._start_utc, self._end_utc = instant(capsule["created_utc"]), instant(capsule["expires_utc"])
        self._start_ns, self._end_ns = capsule["created_mono_ns"], capsule["deadline_mono_ns"]
        self.last_utc = instant(capsule["created_utc"])
        self.last_mono = capsule["created_mono_ns"]
        self._lock = threading.RLock()

    @property
    def capsule(self):
        return parse_json(self._inputs[0])

    def check(self):
        with self._lock:
            self._check()

    def _check(self):
        from .windows import observe_controller
        require(observe_controller() == parse_json(self._inputs[-1]), "live controller identity changed")
        # Canonical immutable byte inputs were validated once. Frequent watchdog
        # polling rechecks kernel identity and both clocks, not megabytes of sealed
        # dependency hashes; source handles remain held by the bootstrap.
        now, mono = datetime.now(timezone.utc), time.monotonic_ns()
        require(self._start_utc <= now < self._end_utc and self._start_ns <= mono < self._end_ns-2*10**9,
                "continuation expired")
        require(abs((now-self._start_utc).total_seconds()-(mono-self._start_ns)/10**9)<=5,
                "UTC/monotonic divergence")
        require(now >= self.last_utc and mono >= self.last_mono, "continuation clock rollback")
        self.last_utc, self.last_mono = now, mono
