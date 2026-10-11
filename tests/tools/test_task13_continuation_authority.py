"""Synthetic authority predicates and owned local Windows storage; no VM calls."""
import copy
import os
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from uuid import uuid4

import pytest

from tools.canary.task13_continuation import authority
from tools.canary.task13_continuation.codec import digest, canonical
from tools.canary.task13_continuation.history import ORIGINAL_FILES, BASELINE_SHA, SNAPSHOT_SHA
from tools.canary.task13_continuation.storage import ProtectedStore
from tools.canary.task13_continuation.windows import observe_controller

pytestmark = pytest.mark.no_db


@pytest.fixture
def auth_inputs():
    identity = {"host_id": "a" * 64, "boot_id": str(uuid4()), "pid": 1234,
                "birth": 123456789, "token_sid": "S-1-5-18", "elevated": True}
    original = {"original_files": ORIGINAL_FILES, "original_tip": ORIGINAL_FILES["receipt-03-start-after-snapshot.json"],
                "baseline_sha256": BASELINE_SHA, "snapshot_identity_sha256": SNAPSHOT_SHA}
    prefix = SimpleNamespace(binding=original)
    closure = {"entries": {"synthetic.py": {"bytes": 1, "sha256": "c" * 64}}}
    review = {"schema": "task13_source_review_v1", "status": "PASS", "reviewer": "unit-test",
              "source_closure_sha256": digest(closure), "scope": authority.REVIEW_SCOPE}
    intent = {"schema": "task13_operator_authority_v1", "original": original,
              "allowed_seq": 4, "allowed_step": "compare-after-start", "controller": identity,
              "source_closure_sha256": digest(closure), "bootstrap_sha256": "d" * 64,
              "request_sha256": "e" * 64, "request_reference": "synthetic-test-only"}
    capsule = authority.create_capsule(prefix, closure, intent, review, identity)
    attestation = {"schema": "task13_creator_attestation_v1", "capsule_sha256": digest(capsule),
                   "authority_sha256": digest(intent), "controller": identity}
    trust = {"authority_sha256": digest(intent), "review_sha256": digest(review),
             "attestation_sha256": digest(attestation), "bootstrap_sha256": "d" * 64,
             "source_closure_sha256": digest(closure), "request_sha256": "e" * 64}
    return capsule, intent, attestation, review, trust, identity


def test_capsule_identity_and_original_facts_are_separate(auth_inputs):
    c, a, att, r, t, i = auth_inputs
    authority.validate_authorization(c, a, att, r, t, i)
    assert c["continuation_id"] != c["original"]["original_tip"]
    assert c["allowed_seq"] == 4


@pytest.mark.parametrize("field", ["boot_id", "pid", "birth", "host_id", "token_sid", "elevated"])
def test_wrong_observed_controller_refused(auth_inputs, field):
    c, a, att, r, t, i = auth_inputs
    bad = {**i, field: False if field == "elevated" else "wrong"}
    with pytest.raises(ValueError):
        authority.validate_authorization(c, a, att, r, t, bad)


@pytest.mark.parametrize("which", [0, 1, 2, 3])
def test_unsealed_capsule_authority_attestation_or_review_refused(auth_inputs, which):
    args = list(copy.deepcopy(auth_inputs))
    args[which]["injected"] = True
    with pytest.raises(ValueError):
        authority.validate_authorization(*args)


def test_expired_and_utc_rollback_refuse_without_time_adjustment(auth_inputs, monkeypatch):
    c, a, att, r, t, i = auth_inputs
    with monkeypatch.context() as patch:
        patch.setattr(authority.time, "monotonic_ns", lambda: c["deadline_mono_ns"])
        with pytest.raises(ValueError):
            authority.validate_authorization(c, a, att, r, t, i)
    live = authority.LiveAuthorization(*auth_inputs)
    monkeypatch.setattr("tools.canary.task13_continuation.windows.observe_controller", lambda: i)
    live.check()
    live.last_utc = authority.instant(c["expires_utc"])
    with pytest.raises(ValueError):
        live.check()


@pytest.mark.skipif(os.name != "nt", reason="native Windows security and storage")
def test_real_controller_and_protected_store_no_replace(tmp_path):
    observed = observe_controller()
    assert observed["pid"] == os.getpid() and observed["birth"] > 0
    store = ProtectedStore.create_root(tmp_path / "protected")
    store.create("original.json", b'{"original":true}')
    store.publish("receipt.json", b'{"complete":true}')
    with pytest.raises((ValueError, FileExistsError)):
        store.publish("receipt.json", b'{"overwritten":true}')
    assert store.read("receipt.json") == b'{"complete":true}'
    assert store.read("original.json") == b'{"original":true}'
    with pytest.raises(ValueError):
        store.read("../outside.json")
    os.link(store.root / "original.json", store.root / "alias.json")
    with pytest.raises(ValueError):
        store.read("original.json")


@pytest.mark.skipif(os.name != "nt", reason="native exclusive dispatch claims")
def test_concurrent_cross_continuation_replay_refused(tmp_path):
    store = ProtectedStore.create_root(tmp_path / "claims")
    binding = {"original_run_seal_sha256": ORIGINAL_FILES["run-seal.json"],
               "original_tip": ORIGINAL_FILES["receipt-03-start-after-snapshot.json"]}
    prefix = SimpleNamespace(binding=binding)

    def attempt(_):
        try:
            return store.claim(prefix, str(uuid4()))
        except (ValueError, FileExistsError):
            return None

    with ThreadPoolExecutor(max_workers=4) as pool:
        winners = [result for result in pool.map(attempt, range(8)) if result is not None]
    assert len(winners) == 1
    restarted = ProtectedStore(store.root)
    with pytest.raises((ValueError, FileExistsError)):
        restarted.claim(prefix, str(uuid4()))


@pytest.mark.skipif(os.name != "nt", reason="native publication crash boundaries")
@pytest.mark.parametrize("boundary", ["write_handle", "rename_handle", "flush_volume"])
def test_publication_fault_never_replaces_history(tmp_path, monkeypatch, boundary):
    from tools.canary.task13_continuation import windows
    store = ProtectedStore.create_root(tmp_path / "fault")
    store.create("original.json", b"history")
    def fault(*args):
        raise OSError("injected publication boundary")
    with monkeypatch.context() as patch:
        patch.setattr(windows, boundary, fault)
        with pytest.raises(OSError):
            store.publish("receipt.json", b"complete")
    assert store.read("original.json") == b"history"
    if (store.root / "receipt.json").exists():
        assert store.read("receipt.json") == b"complete"
        with pytest.raises(OSError):
            store.publish("receipt.json", b"replacement")


def test_live_authorization_reobserves_kernel_identity(auth_inputs, monkeypatch):
    monkeypatch.setattr("tools.canary.task13_continuation.windows.observe_controller", lambda: {})
    with pytest.raises(ValueError, match="live controller"):
        authority.LiveAuthorization(*auth_inputs).check()
