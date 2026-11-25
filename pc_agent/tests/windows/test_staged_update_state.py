"""A staged installer must exclude mutation without stopping the old runtime."""
from dataclasses import replace
import json
import os
from uuid import uuid4

import pytest

from pc_agent.platform.windows import durable_state, installer_fence
from pc_agent.platform.windows.update_paths import WindowsUpdatePaths
from pc_agent.platform.windows.update_transaction import UpdateInProgress
from pc_agent.tests.windows.test_installer_fence import native_protected_root


def release(version, digit):
    return {"schema_version": "endpoint_windows_release_v1", "version": version,
            "source_revision": digit * 40, "package_sha256": digit * 64,
            "product_code": "{" + str(uuid4()).upper() + "}",
            "initial_runtime_tree_sha256": digit * 64}


@pytest.fixture
def staged(request, tmp_path):
    from pc_agent.platform.windows import staged_update_state as state
    root = request.getfixturevalue("native_protected_root") if os.name == "nt" else tmp_path
    paths = WindowsUpdatePaths(root / "Agent", root / "data/updates/pending_update.json")
    paths.install_root.mkdir()
    paths.updates_root.mkdir(parents=True)
    directory = installer_fence.state_root(paths)
    directory.mkdir()
    installer_fence.protect_state(directory)
    selected = json.dumps({"schema_version": 1, "version": "3.2.121", "source_revision": "c" * 40}).encode()
    paths.current_path.write_bytes(selected)
    installer_fence.protect_state(paths.current_path)
    binding = state.StagedUpdateBinding(
        operation_id=str(uuid4()), old_release=release("3.2.120", "a"),
        new_release=release("3.2.122", "b"), selected_before=selected, previous_before=None,
        selected_tree_sha256_before="c" * 64, previous_tree_sha256_before=None,
        candidate_version="3.2.122", candidate_source_revision="b" * 40,
        candidate_tree_sha256="b" * 64)
    owner = {"pid": os.getpid(), "created": 123, "hash": "d" * 64,
             "sid": "S-1-5-18", "elevated": True}
    return state, paths, binding, owner


def begin(staged):
    state, paths, binding, owner = staged
    with durable_state.installer_mutation_checkpoints(lambda: None):
        state.begin_staged_update(paths, binding, owner)


def move(staged, before, after, **kwargs):
    state, paths, binding, _ = staged
    with durable_state.installer_mutation_checkpoints(lambda: None):
        return state.advance_staged_update(paths, binding.operation_id, before, after, **kwargs)


def test_preparing_allows_old_launch_only(staged):
    state, paths, binding, _ = staged
    begin(staged)
    state.assert_staged_update_allowed(paths, purpose="launch", runtime_tree_sha256="c" * 64)
    for purpose in ("ota", "setup", "cleanup"):
        with pytest.raises(UpdateInProgress):
            state.assert_staged_update_allowed(paths, purpose=purpose)
    assert paths.current_path.read_bytes() == binding.selected_before
    assert installer_fence.read_fence(paths) is None
    assert state.read_staged_update(paths).phase == "preparing"


def test_trial_allows_exact_candidate_only(staged):
    state, paths, binding, _ = staged
    begin(staged)
    for before, after in (("preparing", "prepared"), ("prepared", "switching"),
                          ("switching", "native-settled")):
        move(staged, before, after)
    with pytest.raises(UpdateInProgress):
        state.assert_staged_update_allowed(paths, purpose="launch", runtime_tree_sha256="c" * 64)
    attempt = str(uuid4())
    move(staged, "native-settled", "trial", attempt_id=attempt)
    paths.current_path.write_text(json.dumps({"schema_version": 1, "version": "3.2.122",
                                             "source_revision": "b" * 40}), encoding="utf-8")
    state.assert_staged_update_allowed(paths, purpose="launch", runtime_tree_sha256="b" * 64)
    with pytest.raises(UpdateInProgress):
        state.assert_staged_update_allowed(paths, purpose="launch", runtime_tree_sha256="c" * 64)
    with pytest.raises(UpdateInProgress):
        state.assert_staged_update_allowed(paths, purpose="ota")
    paths.current_path.write_bytes(binding.selected_before)
    with pytest.raises(UpdateInProgress):
        state.assert_staged_update_allowed(paths, purpose="launch", runtime_tree_sha256="b" * 64)
    assert state.read_staged_update(paths).attempt_id == attempt


def test_journal_rejects_wrong_binding_owner_schema_and_sequence(staged):
    state, paths, binding, owner = staged
    begin(staged)
    journal = installer_fence.state_root(paths) / "staged-update.json"
    original = journal.read_bytes()
    for operation, before, after in ((str(uuid4()), "preparing", "prepared"),
                                    (binding.operation_id, "prepared", "switching"),
                                    (binding.operation_id, "preparing", "accepted")):
        with durable_state.installer_mutation_checkpoints(lambda: None), pytest.raises(ValueError):
            state.advance_staged_update(paths, operation, before, after)
        assert journal.read_bytes() == original
    with durable_state.installer_mutation_checkpoints(lambda: None), pytest.raises(ValueError):
        state.begin_staged_update(paths, replace(binding, candidate_version="3.2.999"), owner)
    assert journal.read_bytes() == original
    for key, value in (("schema_version", "unknown"), ("sequence", True)):
        payload = json.loads(original)
        payload[key] = value
        journal.write_text(json.dumps(payload), encoding="utf-8")
        with pytest.raises(ValueError):
            state.read_staged_update(paths)
    journal.write_bytes(original)
    with durable_state.installer_mutation_checkpoints(lambda: None), pytest.raises(ValueError):
        state.begin_staged_update(paths, binding, {**owner, "elevated": False})
    assert journal.read_bytes() == original


def test_unknown_or_corrupt_journal_blocks_mutation(staged):
    state, paths, _, _ = staged
    assert state.read_staged_update(paths) is None
    begin(staged)
    journal = installer_fence.state_root(paths) / "staged-update.json"
    for raw in (b"{", b"{}", b'{"schema_version":1,"schema_version":1}'):
        journal.write_bytes(raw)
        with pytest.raises(ValueError):
            state.assert_staged_update_allowed(paths, purpose="ota")
        assert journal.read_bytes() == raw


def test_missing_or_lost_owner_grant_cannot_change_journal(staged):
    state, paths, binding, owner = staged
    with pytest.raises(ValueError):
        state.begin_staged_update(paths, binding, owner)
    begin(staged)
    journal = installer_fence.state_root(paths) / "staged-update.json"
    original = journal.read_bytes()
    def denied():
        raise ValueError("OWNER_AUTH_FAILED")
    with durable_state.installer_mutation_checkpoints(denied), pytest.raises(ValueError, match="OWNER_AUTH_FAILED"):
        state.advance_staged_update(paths, binding.operation_id, "preparing", "prepared")
    assert journal.read_bytes() == original


def test_an_accepted_operation_does_not_block_ota(staged):
    state, paths, _, _ = staged
    begin(staged)
    for before, after in (("preparing", "prepared"), ("prepared", "switching"),
                          ("switching", "native-settled"), ("native-settled", "trial"),
                          ("trial", "accepted")):
        move(staged, before, after, **({"attempt_id": str(uuid4())} if after == "trial" else {}))
    state.assert_staged_update_allowed(paths, purpose="ota")


def test_normal_transaction_honors_preparation_reservation(staged):
    from pc_agent.platform.windows.update_transaction import update_transaction
    _, paths, _, _ = staged
    begin(staged)
    with pytest.raises(UpdateInProgress):
        with update_transaction(paths, timeout_ms=0):
            pytest.fail("OTA admitted while staged installer owns preparation")


@pytest.mark.parametrize('defect', ['torn', 'wrong-operation', 'readable-invalid', 'unsafe-primary', 'busy'])
def test_watchdog_restores_only_the_exact_protected_stage_copy(staged, monkeypatch, defect):
    from contextlib import contextmanager
    from pc_agent.platform.windows import staged_recovery, update_transaction

    state, paths, binding, owner = staged
    begin(staged)
    move(staged, "preparing", "prepared")
    move(staged, "prepared", "switching")
    move(staged, "switching", "native-settled")
    expected = move(staged, "native-settled", "trial", attempt_id=str(uuid4()))
    journal = state._path(paths)
    primary = journal.read_bytes()
    mirror = journal.with_name("staged-update-recovery.json")
    assert mirror.read_bytes() == primary
    installer_fence.assert_state_security(mirror)
    damaged = b"INDX" + b"\0" * 64
    if defect == "readable-invalid":
        damaged = b"{}"
    journal.write_bytes(damaged)
    if defect == "unsafe-primary":
        original = installer_fence.assert_state_security
        def check(path, **kwargs):
            if path == journal:
                raise ValueError("UPDATE_STATE_INVALID")
            return original(path, **kwargs)
        monkeypatch.setattr(installer_fence, "assert_state_security", check)

    calls = []
    @contextmanager
    def mutex(timeout_ms):
        assert timeout_ms == 0
        if defect == "busy":
            raise UpdateInProgress("UPDATE_IN_PROGRESS")
        calls.append("locked")
        yield
    monkeypatch.setattr(update_transaction, "_windows_transaction", mutex)
    monkeypatch.setattr(staged_recovery, "_require_system_recovery", lambda: calls.append("system"))
    def owner_dead(actual):
        assert actual == owner
        calls.append("original-owner-dead")
    monkeypatch.setattr(staged_recovery, "_assert_owner_dead", owner_dead)
    monkeypatch.setattr(staged_recovery, "_validate_recovery_inputs", lambda p, r: calls.append("inputs"))
    root = staged_recovery._root(paths, binding.operation_id, create=True)

    with pytest.raises(ValueError):
        state.assert_staged_update_allowed(paths, purpose="ota")
    if defect in ("torn", "busy"):
        record, raw = staged_recovery.read_recoverable_stage(paths, binding.operation_id)
        assert record == expected and raw == damaged
        if defect == "busy":
            with pytest.raises(UpdateInProgress):
                staged_recovery.restore_damaged_stage(paths, record, raw)
            assert journal.read_bytes() == damaged
            assert not list(root.glob("damaged-stage-*"))
        else:
            staged_recovery.restore_damaged_stage(paths, record, raw)
            assert calls.index("system") < calls.index("locked") < calls.index("inputs")
            assert journal.read_bytes() == primary and mirror.read_bytes() == primary
            assert state.read_staged_update(paths) == expected
            archive, = root.glob("damaged-stage-*")
            assert archive.read_bytes() == damaged
            installer_fence.assert_state_security(archive, secret=True)
    else:
        operation = str(uuid4()) if defect == "wrong-operation" else binding.operation_id
        with pytest.raises(ValueError):
            staged_recovery.read_recoverable_stage(paths, operation)
        assert journal.read_bytes() == damaged
