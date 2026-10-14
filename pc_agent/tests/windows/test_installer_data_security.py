"""Fresh native creation needs exact pre-MSI owner evidence, never an empty-root guess."""
import pytest

from pc_agent.platform.windows import installer_data_security as data


@pytest.fixture
def operation(tmp_path, monkeypatch):
    from pc_agent.platform.windows.update_paths import WindowsUpdatePaths
    paths = WindowsUpdatePaths(tmp_path / "install" / "Agent", tmp_path / "data" / "updates" / "pending_update.json")
    root = tmp_path / "authority"
    root.mkdir()
    root.chmod(0o700)
    monkeypatch.setattr(data, "_transaction_root", lambda *_args: root)
    monkeypatch.setattr(data, "_prepare_transaction_root", lambda *_args: root)
    # Unit tests isolate the phase protocol; separate native tests exercise DACLs.
    monkeypatch.setattr(data, "protect_state", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(data, "assert_state_security", lambda path, **_kwargs: None)
    monkeypatch.setattr(data, "_snapshot", lambda *_args: {"root": None, "leaves": {}})
    request = {"transaction_id": "14c403b1-5de6-4fe9-b60a-8dad22349924",
               "session_id": "405d7d76-a86b-45db-bcaa-57a6574f61b5", "release": {"package_sha256": "a" * 64}}
    return paths, request


def test_absence_proof_survives_native_createfolder_without_rebaselining(operation, monkeypatch):
    paths, request = operation
    data.prepare(paths, request)
    data.before_native(paths, request)
    data.enter_native(paths, request)
    # The genuine native script creates the folder after its checked enter phase.
    monkeypatch.setattr(data, "_snapshot", lambda *_args: pytest.fail("fresh root treated as enrolled root"))
    calls = []
    monkeypatch.setattr(data, "_initialize_fresh_root", lambda *_args: calls.append("native fresh root"))
    data.configure(paths, request)
    assert calls == ["native fresh root"]


def test_root_appearing_before_native_enter_is_rejected(operation, monkeypatch):
    paths, request = operation
    data.prepare(paths, request)
    monkeypatch.setattr(data, "_snapshot", lambda *_args: {"root": "changed", "leaves": {}})
    with pytest.raises(ValueError, match="PROVENANCE_CONFLICT"):
        data.before_native(paths, request)


def test_existing_snapshot_and_leaves_are_preserved(operation, monkeypatch):
    paths, request = operation
    original = {"root": {"identity": [1, 1], "descriptor": "aa"},
                "leaves": dict.fromkeys(data._LEAVES)}
    original["leaves"]["enrollment-identity.json"] = {"identity": [1, 2], "descriptor": "bb"}
    monkeypatch.setattr(data, "_snapshot", lambda *_args: original)
    monkeypatch.setattr(data, "_initialize_fresh_root", lambda *_args: pytest.fail("existing root normalized"))
    data.prepare(paths, request)
    data.before_native(paths, request)
    data.enter_native(paths, request)
    data.configure(paths, request)
    data.verify_preserved(paths, request)
    changed = {"root": original["root"], "leaves": {**original["leaves"], "enrollment-identity.json": {"identity": [1, 3], "descriptor": "bb"}}}
    monkeypatch.setattr(data, "_snapshot", lambda *_args: changed)
    with pytest.raises(ValueError, match="PROVENANCE_CONFLICT"):
        data.verify_preserved(paths, request)


def test_other_package_cannot_reuse_fresh_creation_evidence(operation):
    paths, request = operation
    data.prepare(paths, request)
    different = {**request, "release": {"package_sha256": "b" * 64}}
    with pytest.raises(ValueError, match="PROVENANCE_CONFLICT"):
        data.configure(paths, different)


def test_repeat_prepare_cannot_replace_original_baseline(operation, monkeypatch):
    paths, request = operation
    data.prepare(paths, request)
    monkeypatch.setattr(data, "_snapshot", lambda *_args: {"root": "new", "leaves": {}})
    with pytest.raises(ValueError, match="PROVENANCE_CONFLICT"):
        data.prepare(paths, request)


def test_other_session_cannot_use_normal_fresh_creation_evidence(operation):
    paths, request = operation
    data.prepare(paths, request)
    other = {**request, "session_id": "ecf28bea-3d44-4455-af9f-57c95b27913c"}
    with pytest.raises(ValueError, match="PROVENANCE_CONFLICT"):
        data.before_native(paths, other)


def test_configure_before_checked_native_enter_is_rejected(operation, monkeypatch):
    paths, request = operation
    data.prepare(paths, request)
    monkeypatch.setattr(data, "_initialize_fresh_root", lambda *_args: pytest.fail("early ACL mutation"))
    with pytest.raises(ValueError, match="PROVENANCE_CONFLICT"):
        data.configure(paths, request)


def test_configure_replay_is_rejected(operation, monkeypatch):
    paths, request = operation
    data.prepare(paths, request)
    data.enter_native(paths, request)
    calls = []
    monkeypatch.setattr(data, "_initialize_fresh_root", lambda *_args: calls.append(True))
    data.configure(paths, request)
    with pytest.raises(ValueError, match="PROVENANCE_CONFLICT"):
        data.configure(paths, request)
    assert calls == [True]


def test_recovery_after_prepare_rejects_root_created_before_native_entry(operation, monkeypatch):
    paths, request = operation
    data.prepare(paths, request)
    root = data._root(paths)
    root.mkdir(parents=True)
    monkeypatch.setattr(data, "_assert_fresh_native_root", lambda *_args: None)
    monkeypatch.setattr(data, "_initialize_fresh_root", lambda *_args: pytest.fail("unaccounted root normalized"))
    recovered = {**request, "recovery": True, "session_id": "ecf28bea-3d44-4455-af9f-57c95b27913c"}
    with pytest.raises(ValueError, match="PROVENANCE_CONFLICT"):
        data.enter_native(paths, recovered)
    assert data._read(paths, recovered)["phase"] == "prepared"


@pytest.mark.parametrize("phase", ["prepared", "native-entered"])
def test_final_preservation_requires_completed_configuration(operation, phase):
    paths, request = operation
    data.prepare(paths, request)
    if phase == "native-entered":
        data.enter_native(paths, request)
    with pytest.raises(ValueError, match="PROVENANCE_CONFLICT"):
        data.verify_preserved(paths, request)


def test_recovery_rechecks_namespace_authority_even_when_fresh_root_is_still_absent(operation,monkeypatch):
    paths,request=operation;data.prepare(paths,request)
    recovered={**request,'recovery':True,'session_id':'ecf28bea-3d44-4455-af9f-57c95b27913c'}
    def unsafe_parent(*_args):raise ValueError('PROVENANCE_CONFLICT')
    monkeypatch.setattr(data,'_snapshot',unsafe_parent)
    with pytest.raises(ValueError,match='PROVENANCE_CONFLICT'):data.before_native(paths,recovered)
