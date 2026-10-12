"""Fixed historical task inputs are opt-in local evidence, never live authority."""
import hashlib
import json
import os
from pathlib import Path

import pytest

from tools.canary.task13_continuation.codec import canonical, digest, parse_json
from tools.canary.task13_continuation.history import (
    ORIGINAL_FILES, validate_original_blobs, verify_historical_prefix,
)
from tools.canary.task13_continuation import history

pytestmark = pytest.mark.no_db


@pytest.mark.parametrize("raw", [
    b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}',
    b'{"x":-Infinity}', b'[]', b'null', b'\xff', b'{',
])
def test_untrusted_json_refuses_ambiguous_or_nonobject_input(raw):
    with pytest.raises(ValueError):
        parse_json(raw)


def test_json_bounds_and_canonical_digest():
    with pytest.raises(ValueError):
        parse_json(b'{"x":1}', limit=2)
    with pytest.raises(ValueError):
        canonical({"x": float("nan")})
    assert canonical({"b": 2, "a": 1}) == b'{"a":1,"b":2}'
    assert digest({"a": 1}) == hashlib.sha256(b'{"a":1}').hexdigest()


def test_absent_prefix_refused():
    with pytest.raises(ValueError):
        validate_original_blobs({})


@pytest.mark.parametrize("name", ORIGINAL_FILES)
def test_fixed_anchor_tampering_refused_without_import_or_dispatch(name):
    blobs = {key: b'{}' for key in ORIGINAL_FILES}
    blobs[name] = b'{"changed":true}'
    with pytest.raises(ValueError):
        validate_original_blobs(blobs)


@pytest.fixture
def historical_root():
    raw = os.environ.get("TASK13_HISTORICAL_ROOT")
    if not raw:
        pytest.skip("private retained inputs require explicit local configuration")
    return Path(raw)


@pytest.mark.parametrize("name", ORIGINAL_FILES)
def test_actual_retained_object_tampering_refused(historical_root, name):
    records = historical_root / "zero-owner-recovery-records"
    blobs = {key: (records / key).read_bytes() for key in ORIGINAL_FILES}
    blobs[name] += b" "
    with pytest.raises(ValueError):
        validate_original_blobs(blobs)


def test_actual_prefix_verifies_without_mutating_or_reviving_history(historical_root):
    records = historical_root / "zero-owner-recovery-records"
    before = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in records.glob("*.json")}
    prefix = verify_historical_prefix(historical_root)
    assert prefix.binding["original_tip"] == ORIGINAL_FILES["receipt-03-start-after-snapshot.json"]
    assert prefix.binding["verified_receipt_count"] == 4
    assert prefix.binding["historical_guest_brackets"] == 2
    assert prefix.binding["source_entries"] == 61
    assert prefix.binding["source_prerequisites"] == 305
    assert prefix.binding["raw_output_retained"] is False
    assert before == {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in records.glob("*.json")}
    # No current= injection, clock patch or modified original function.
    controller = prefix.controller
    for call in [lambda: controller.live_plan(prefix.plan),
                 lambda: controller.verify_chain(prefix.seal, prefix.receipts),
                 lambda: controller.next_step(prefix.seal, prefix.receipts, "compare-after-start", prefix.snapshot)]:
        with pytest.raises(ValueError, match="run expired or duration changed"):
            call()


def test_source_manifest_substitution_refused_before_module_load(tmp_path):
    (tmp_path / "source-closure-manifest.json").write_bytes(b'{}')
    with pytest.raises(ValueError):
        verify_historical_prefix(tmp_path)


@pytest.mark.parametrize("filename,field", [
    ("guest-capture-006-accepted-observation.json", "transport"),
    ("guest-capture-006-result.json", "candidate_status"),
    ("ownership-before-capture.json", "observation"),
])
def test_actual_retained_evidence_substitution_refused(historical_root, monkeypatch, filename, field):
    read_original = history.read_file

    def tampered_read(path, limit=64 * 1024 * 1024):
        raw = read_original(path, limit)
        if path.parent == historical_root / "zero-owner-recovery-records" and path.name == filename:
            value = json.loads(raw)
            if field == "transport":
                value[field]["exit_code"] = 123
            elif field == "observation":
                value[field]["device_owners"] = ["synthetic-owner"]
            else:
                value[field] = "UNKNOWN"
            return canonical(value)
        return raw

    monkeypatch.setattr(history, "read_file", tampered_read)
    with pytest.raises(ValueError):
        verify_historical_prefix(historical_root)
