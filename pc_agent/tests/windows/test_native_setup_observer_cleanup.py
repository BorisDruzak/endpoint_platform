from contextlib import nullcontext
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from types import SimpleNamespace
import uuid

import pytest

from pc_agent.platform.windows import native_setup_observer as observer
from pc_agent.platform.windows import installer_transaction_bridge as bridge


@pytest.mark.parametrize(
    ("case", "expected", "deleted"),
    [
        ("absent", "removed", False),
        ("absent_busy_mutex", "removed", False),
        ("busy_mutex", "incomplete", False),
        ("owned", "removed", True),
        ("disabled_owned", "removed", True),
        ("foreign", "incomplete", False),
        ("busy", "incomplete", False),
        ("changed", "incomplete", False),
        ("still_present", "incomplete", True),
    ],
)
def test_retire_only_a_still_idle_unchanged_owned_observer(monkeypatch, case, expected, deleted):
    task = SimpleNamespace(Xml="registered", State=1 if case == "disabled_owned" else 3, Path=r"\EndpointSetupUpdater",
                           GetSecurityDescriptor=lambda _: "owned",
                           GetInstances=lambda _: SimpleNamespace(Count=int(case == "busy")))
    replacement = SimpleNamespace(**vars(task))
    replacement.Xml = "changed"
    remaining = [None if case.startswith("absent") else task]
    calls = []
    folder = SimpleNamespace()

    def lookup(*_):
        calls.append("read")
        if case == "changed" and calls.count("read") >= 3:
            return replacement
        return remaining[0]

    def delete(name, flags):
        assert (name, flags) == ("EndpointSetupUpdater", 0)
        calls.append("delete")
        if case != "still_present":
            remaining[0] = None

    def verify(paths, item):
        assert item is task
        if case == "foreign":
            raise ValueError("foreign task")
        return nullcontext()

    folder.DeleteTask = delete

    def lock():
        if case.endswith("busy_mutex"):
            raise OSError("mutex busy")
        return nullcontext()

    monkeypatch.setattr(observer, "_scheduler_folder", lambda: folder)
    monkeypatch.setattr(observer, "find_task", lookup)
    monkeypatch.setattr(observer, "_observer_mutex", lock)
    monkeypatch.setattr(observer, "_pinned_observer_action", verify)
    monkeypatch.setattr(observer.durable_state, "installer_mutation_checkpoint", lambda **_: None)
    assert observer.retire_packaged_observer(object()) == expected
    assert ("delete" in calls) is deleted


@pytest.mark.parametrize("marker", [None, "compound", "repair", "reverse", "staged_rollback",
                                    "recovery_parent", "restoration_transaction_id", "recovery",
                                    "uninstall_finalization"])
def test_observer_cleanup_requires_standalone_operator_uninstall(marker):
    capability = {"operation": "uninstall"}
    if marker is not None:
        capability[marker] = True
    assert bridge._is_final_observer_uninstall(capability) is (marker is None)
    assert not bridge._is_final_observer_uninstall({"operation": "install"})


@pytest.mark.parametrize("condition", ["owned", "powershell_digest", "bad_digest", "bad_publisher", "bad_action"])
def test_cleanup_binds_pinned_receipt_actual_bytes_publisher_and_task(monkeypatch, tmp_path, condition):
    program_files = tmp_path / "Program Files"
    program_data = tmp_path / "ProgramData"
    paths = SimpleNamespace(install_root=program_files / "Endpoint Platform" / "Agent",
                            updates_root=program_data / "Endpoint Platform" / "Agent" / "updates")
    target = program_files / "EndpointPlatformSetupUpdater" / "1.0.13" / "EndpointSetupUpdater.ps1"
    receipt = program_data / "EndpointPlatformSetupUpdates" / "client.json"
    target.parent.mkdir(parents=True)
    receipt.parent.mkdir(parents=True)
    raw = b"$script:ClientVersion='1.0.13'\r\n"
    target.write_bytes(raw)
    digest = hashlib.sha256(raw).hexdigest()
    if condition == "powershell_digest":
        digest = digest.upper()
    if condition == "bad_digest":
        digest = "0" * 64
    receipt.write_text(json.dumps({"client_version": "1.0.13", "installed_at": "test",
                                   "script_sha256": digest}), encoding="utf-8")
    task = object()
    powershell = tmp_path / "powershell.exe"
    pinned = []
    trust = []
    verified = []

    def pin(path):
        pinned.append(path)
        return nullcontext()

    def verify_signature(path, publisher, *, cache_only):
        trust.append((path, publisher, cache_only))
        return condition != "bad_publisher"

    def verify_task(*args, allow_disabled):
        verified.append((args, allow_disabled))
        if condition == "bad_action":
            raise ValueError("task action changed")

    monkeypatch.setattr(observer, "_assert_administrative_file", lambda _: None)
    monkeypatch.setattr(observer.durable_state, "_pinned_copy_source", pin)
    monkeypatch.setattr(observer, "has_verified_timestamp", verify_signature)
    monkeypatch.setattr(observer, "_verify_task", verify_task)
    monkeypatch.setattr(observer, "system_powershell", lambda: powershell)
    valid = condition in {"owned", "powershell_digest"}
    result = nullcontext() if valid else pytest.raises(ValueError)
    with result, observer._pinned_observer_action(paths, task):
        assert valid
    assert pinned == [receipt, target]
    assert trust == ([] if condition == "bad_digest" else [(target, observer._PUBLISHER, True)])
    assert verified == ([((task, target, powershell), True)] if valid or condition == "bad_action" else [])


@pytest.mark.skipif(os.name != "nt", reason="Windows kernel mutex security")
def test_observer_mutex_roundtrips_its_exact_dacl(monkeypatch):
    import win32security

    administrators = win32security.ConvertStringSidToSid("S-1-5-32-544")
    system = win32security.ConvertStringSidToSid("S-1-5-18")
    if not any(win32security.CheckTokenMembership(None, sid) for sid in (administrators, system)):
        pytest.skip("Observer mutex requires an elevated installer token")

    monkeypatch.setattr(observer, "_MUTEX_NAME", r"Local\EndpointObserverAclTest-" + uuid.uuid4().hex)

    def try_concurrent_owner():
        with pytest.raises(ValueError, match="RECOVERY_REQUIRED"), observer._observer_mutex():
            pytest.fail("Concurrent Observer owner unexpectedly acquired the mutex")

    with observer._observer_mutex():
        with ThreadPoolExecutor(max_workers=1) as pool:
            pool.submit(try_concurrent_owner).result(timeout=2)
    with observer._observer_mutex():
        pass


def test_observer_signature_validation_can_require_offline_trust(monkeypatch, tmp_path):
    from pc_agent.platform.windows import authenticode_timestamp as timestamp

    captured = []

    def verify(_window, _action, request):
        captured.append(request._obj.flags)
        return 1

    def unused(*_):
        pytest.fail("A rejected trust result must not query certificate state")

    trust = SimpleNamespace(WinVerifyTrust=verify, WTHelperProvDataFromStateData=unused,
                            WTHelperGetProvSignerFromChain=unused, WTHelperGetProvCertFromChain=unused)
    crypto = SimpleNamespace(CertGetCertificateContextProperty=unused)
    monkeypatch.setattr(timestamp.ctypes, "WinDLL", lambda name, **_: trust if name == "wintrust.dll" else crypto)

    assert not timestamp.has_verified_timestamp(tmp_path / "example.ps1", observer._PUBLISHER, cache_only=True)
    assert not timestamp.has_verified_timestamp(tmp_path / "example.ps1", observer._PUBLISHER)
    assert captured == [0x1000, 0]


@pytest.mark.parametrize(
    ("modifiers", "cleanup", "support"),
    [
        ({}, "removed", "complete"),
        ({}, "incomplete", "incomplete"),
        ({"compound": {}}, None, None),
        ({"staged_rollback": {}}, None, None),
        ({"recovery": True, "uninstall_finalization": True}, None, "complete"),
    ],
)
def test_authenticated_finish_preserves_native_completion_with_independent_cleanup(
    monkeypatch, tmp_path, modifiers, cleanup, support,
):
    from pc_agent.platform.windows import compound_upgrade_plan, installation_lifecycle, installer_fence, msi_inventory

    transaction_id = "7538b31d-d7ac-474c-974c-17b1fa717607"
    package_hash = "b" * 64
    cap = {"operation": "uninstall", "transaction_id": transaction_id, "package": {},
           "recovery": False, "uninstall_finalization": False, **modifiers}
    client = SimpleNamespace(phase="finish", capability=cap, checkpoint=lambda: None)
    paths = SimpleNamespace(install_root=tmp_path)
    expected = SimpleNamespace(package=SimpleNamespace(sha256=package_hash))
    calls = []
    writes = {}

    def write(path, value, **_):
        writes[path.name] = value.copy()

    def retire(_):
        assert cleanup is not None
        calls.append("observer")
        return cleanup

    monkeypatch.setattr(bridge, "_request_data", lambda *_: {"package_path": tmp_path / "agent.msi"})
    monkeypatch.setattr(bridge, "_verify_normal_support_uninstall", lambda *_: support)
    monkeypatch.setattr(bridge, "_advance_fence", lambda *_: {"phase": "complete"})
    monkeypatch.setattr(bridge, "completion_root", lambda *_, **__: tmp_path)
    monkeypatch.setattr(msi_inventory, "read_expected_package", lambda *_: expected)
    monkeypatch.setattr(msi_inventory, "verify_uninstalled", lambda *_: calls.append("absence"))
    monkeypatch.setattr(installer_fence, "publish_fence", lambda *_: None)
    monkeypatch.setattr(installer_fence, "fence_path", lambda _: tmp_path / "fence.json")
    monkeypatch.setattr(observer, "retire_packaged_observer", retire)
    monkeypatch.setattr(observer.durable_state, "write_json_atomic", write)
    monkeypatch.setattr(observer.durable_state, "durable_unlink", lambda *_, **__: calls.append("fence"))
    monkeypatch.setattr(installation_lifecycle, "record_native_finish", lambda *_, **__: calls.append("event"))
    monkeypatch.setattr(compound_upgrade_plan, "record_standalone_completion", lambda *_: None)

    result = bridge._execute_authorized_phase(client, paths, complete=False)
    assert result.get("observer_cleanup") == cleanup
    assert result.get("support_cleanup") == support
    assert writes["completed.json"] == {"phase": "complete", "startup_restored": True}
    if cleanup is not None:
        assert writes["observer-cleanup.json"] == {
            "schema_version": 1, "transaction_id": transaction_id, "package_sha256": package_hash,
            "native_result": 0, "native_uninstalled": True, "observer_cleanup": cleanup,
        }
        assert calls == ["absence", "event", "observer", "fence"]
    else:
        assert "observer-cleanup.json" not in writes
        assert calls == ["absence", "event", "fence"]
