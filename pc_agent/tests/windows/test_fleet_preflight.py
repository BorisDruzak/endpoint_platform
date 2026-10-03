"""Eligibility is a read-only local snapshot, never authentication or READY."""

from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace

import pytest

from pc_agent.platform.windows import (
    installation_provenance,
    installer_fence,
    msi_inventory,
)
from pc_agent.platform.windows.update_paths import WindowsUpdatePaths
from pc_agent.platform.windows.fleet_preflight import _disk as _PRODUCTION_DISK
from pc_agent.tests.windows.test_installation_provenance import (
    handoff_input as _task7_handoff,
)

handoff_input = _task7_handoff

_VERIFY_INSTALLED = msi_inventory.verify_installed
_VERIFY_FOUNDATION = msi_inventory.verify_foundation


def snapshot(root):
    return {
        str(p.relative_to(root)): (
            p.read_bytes() if p.is_file() else "directory",
            p.stat().st_mtime_ns,
        )
        for p in root.rglob("*")
    }


@pytest.fixture
def machine(tmp_path, monkeypatch):
    from pc_agent.platform.windows import fleet_preflight as module
    from pc_agent.platform.windows import update_transaction

    paths = WindowsUpdatePaths(
        tmp_path / "Agent", tmp_path / "data/updates/pending_update.json"
    )
    paths.updates_root.mkdir(parents=True)
    monkeypatch.setattr(installation_provenance, "_assert_security", lambda *_: None)
    monkeypatch.setattr(installer_fence, "assert_state_security", lambda *_: None)
    monkeypatch.setattr(update_transaction, "_assert_state_security", lambda *_: None)
    from pc_agent.platform.windows.acl import PyWin32AclAdapter

    monkeypatch.setattr(PyWin32AclAdapter, "assert_protected_file", lambda *_: None)
    package = SimpleNamespace(
        version="3.2.81",
        sha256="b" * 64,
        product_code="{11111111-1111-4111-8111-111111111111}",
    )
    release = {
        "version": "3.2.81",
        "source_revision": "a" * 40,
        "package_sha256": "b" * 64,
    }
    state = installer_fence.state_root(paths)
    state.mkdir(parents=True)
    (state / "foundation.json").write_text(
        json.dumps({"schema_version": 1, "release": release})
    )
    monkeypatch.setattr(
        msi_inventory,
        "read_expected_package",
        lambda *_: SimpleNamespace(package=package),
    )
    monkeypatch.setattr(
        msi_inventory, "verify_foundation", lambda *_a, **_kw: "complete"
    )
    services = {
        name: {
            "present": True,
            "state": "running" if name == "EndpointAgent" else "stopped",
            "start_mode": "automatic" if name == "EndpointAgent" else "manual",
            "identity_valid": True,
        }
        for name in ("EndpointAgent", "EndpointAgentUpdater")
    }
    monkeypatch.setattr(module, "_services", lambda *_: services)
    monkeypatch.setattr(
        module, "_ca_parseable", lambda raw: raw == b"public CA fixture"
    )
    monkeypatch.setattr(
        module,
        "_disk",
        lambda *_: {
            "sufficient": True,
            "scope": "setup_allocation_unknown",
            "free_bytes": 10**10,
        },
    )
    (paths.updates_root.parent / "device-credential").write_bytes(b"S" * 43)
    (paths.updates_root.parent / "enrollment-identity.json").write_text(
        json.dumps(
            {
                "schema_version": "endpoint_enrollment_identity_v1",
                "device_id": "11111111-1111-4111-8111-111111111111",
            }
        )
    )
    (paths.updates_root.parent / "endpoint-ca.crt").write_bytes(b"public CA fixture")
    write_zip(paths)
    return module, paths, package, release, services


def write_zip(paths, version="3.2.81", minimum="3.2.81"):
    root = paths.versions_root / version
    root.mkdir(parents=True, exist_ok=True)
    (root / "pc_agent.exe").write_bytes(b"compiled core fixture")
    (root / "endpoint-runtime-contract.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "version": version,
                "source_revision": "a" * 40,
                "minimum_launcher_version": minimum,
            }
        )
    )
    manifest = {
        "schema_version": 1,
        "version": version,
        "source_revision": "a" * 40,
        "files": [
            {
                "path": p.name,
                "size": p.stat().st_size,
                "sha256": hashlib.sha256(p.read_bytes()).hexdigest(),
            }
            for p in sorted(root.iterdir())
            if p.name in ("pc_agent.exe", "endpoint-runtime-contract.json")
        ],
    }
    (root / "endpoint-update-manifest.json").write_text(json.dumps(manifest))
    (root / ".endpoint-update.json").write_text(
        json.dumps({"version": version, "sha256": "c" * 64, "size": 1234})
    )
    paths.current_path.write_text(
        json.dumps(
            {"schema_version": 1, "version": version, "source_revision": "a" * 40}
        )
    )
    return root


def test_upgrade_snapshot_is_bounded_redacted_and_does_not_mutate(machine, tmp_path):
    module, paths, *_ = machine
    (paths.updates_root.parent / "challenge").write_bytes(b"challenge-never-read")
    before = snapshot(tmp_path)
    result = module.collect_fleet_preflight(paths, "3.2.82")
    assert result["eligibility"] == "READY_FOR_SETUP_UPGRADE"
    assert result["core"]["origin"] == "zip"
    assert result["foundation"]["version"] == "3.2.81"
    assert result["credential"]["shape_valid"] is True
    assert result["credential"]["authenticated"] is None
    assert result["ca"]["strict_live_tls"] is None
    assert result["wss"]["live_connected"] is None
    assert result["update_lane"]["migration_http_pull_fallback"] is False
    encoded = json.dumps(result)
    assert len(encoded.encode()) < 16384
    assert "S" * 43 not in encoded and "challenge-never-read" not in encoded
    assert snapshot(tmp_path) == before


@pytest.mark.parametrize(
    "defect,want",
    [
        ("current", "ALREADY_CURRENT"),
        ("pending", "UPDATE_IN_PROGRESS"),
        ("payload", "PROVENANCE_CONFLICT"),
        ("foundation", "FOUNDATION_UNKNOWN"),
        ("disk", "DISK_INSUFFICIENT"),
        ("service", "SERVICE_INVALID"),
        ("credential", "CREDENTIAL_REPAIR_REQUIRED"),
        ("ca", "TLS_REPAIR_REQUIRED"),
    ],
)
def test_each_eligibility_state(machine, tmp_path, monkeypatch, defect, want):
    module, paths, package, release, services = machine
    if defect == "current":
        package.version = release["version"] = "3.2.83"
        (installer_fence.state_root(paths) / "foundation.json").write_text(
            json.dumps({"schema_version": 1, "release": release})
        )
        write_zip(paths, "3.2.83", "3.2.82")
    elif defect == "pending":
        paths.pending_path.write_text(
            json.dumps(
                {
                    "operation_id": "11111111-1111-4111-8111-111111111111",
                    "version": "3.2.82",
                }
            )
        )
    elif defect == "payload":
        (paths.versions_root / "3.2.81" / "pc_agent.exe").write_bytes(b"tampered")
    elif defect == "foundation":
        (installer_fence.state_root(paths) / "foundation.json").unlink()
    elif defect == "disk":
        monkeypatch.setattr(
            module,
            "_disk",
            lambda *_: {
                "sufficient": False,
                "scope": "setup_allocation_unknown",
                "free_bytes": 0,
            },
        )
    elif defect == "service":
        services["EndpointAgent"]["identity_valid"] = False
    elif defect == "credential":
        (paths.updates_root.parent / "device-credential").write_bytes(b"invalid-secret")
    elif defect == "ca":
        (paths.updates_root.parent / "endpoint-ca.crt").unlink()
    before = snapshot(tmp_path)
    assert module.collect_fleet_preflight(paths, "3.2.82")["eligibility"] == want
    assert snapshot(tmp_path) == before


def test_current_core_stale_foundation_and_equal_feature_absent_need_setup(machine):
    module, paths, package, release, _ = machine
    write_zip(paths, "3.2.82", "3.2.81")
    assert (
        module.collect_fleet_preflight(paths, "3.2.82")["eligibility"]
        == "READY_FOR_SETUP_UPGRADE"
    )
    package.version = release["version"] = "3.2.82"
    (installer_fence.state_root(paths) / "foundation.json").write_text(
        json.dumps({"schema_version": 1, "release": release})
    )
    from unittest.mock import patch

    with patch.object(
        msi_inventory, "verify_foundation", return_value="foundation_only"
    ):
        assert (
            module.collect_fleet_preflight(paths, "3.2.82")["eligibility"]
            == "READY_FOR_SETUP_UPGRADE"
        )


def test_newer_zip_under_equal_foundation_needs_package_candidate_proof(machine):
    module, paths, package, release, _ = machine
    write_zip(paths, "3.2.83", "3.2.82")
    package.version = release["version"] = "3.2.82"
    (installer_fence.state_root(paths) / "foundation.json").write_text(
        json.dumps({"schema_version": 1, "release": release})
    )
    result = module.collect_fleet_preflight(paths, "3.2.82")
    assert result["eligibility"] == "READY_FOR_SETUP_UPGRADE"
    assert result["core"]["version"] == "3.2.83"


@pytest.mark.parametrize("state", ["pending", "transition", "invalid_fence", "fence"])
def test_recovery_dominates_payload_and_disabled_service(machine, monkeypatch, state):
    module, paths, _, _, services = machine
    (paths.versions_root / "3.2.81" / "pc_agent.exe").write_bytes(b"tampered")
    services["EndpointAgent"].update(start_mode="disabled", identity_valid=False)
    if state == "pending":
        paths.pending_path.write_text('{"version":"3.2.82","operation_id":"op"}')
    elif state == "transition":
        paths.transition_path.write_text("null")
    elif state == "invalid_fence":
        (installer_fence.state_root(paths) / "transaction.json").write_text("null")
    else:
        monkeypatch.setattr(
            installer_fence, "read_fence", lambda _: {"phase": "msi-executing"}
        )
    result = module.collect_fleet_preflight(paths, "3.2.82")
    assert result["eligibility"] == "UPDATE_IN_PROGRESS"
    assert result["pending"]["active_or_degraded"] is True


def test_failure_precedence_provenance_foundation_disk_service_credential_ca(
    machine, monkeypatch
):
    module, paths, _, _, services = machine
    (installer_fence.state_root(paths) / "foundation.json").unlink()
    root = paths.versions_root / "3.2.81"
    original = (root / "pc_agent.exe").read_bytes()
    (root / "pc_agent.exe").write_bytes(b"tampered")
    monkeypatch.setattr(
        module,
        "_disk",
        lambda *_: {
            "sufficient": False,
            "scope": "setup_allocation_unknown",
            "free_bytes": 0,
        },
    )
    services["EndpointAgent"]["identity_valid"] = False
    (paths.updates_root.parent / "device-credential").unlink()
    (paths.updates_root.parent / "endpoint-ca.crt").unlink()
    assert (
        module.collect_fleet_preflight(paths, "3.2.82")["eligibility"]
        == "PROVENANCE_CONFLICT"
    )
    (root / "pc_agent.exe").write_bytes(original)
    assert (
        module.collect_fleet_preflight(paths, "3.2.82")["eligibility"]
        == "FOUNDATION_UNKNOWN"
    )


@pytest.mark.parametrize(
    "defects,want",
    [
        (("disk", "service", "credential", "ca"), "DISK_INSUFFICIENT"),
        (("service", "credential", "ca"), "SERVICE_INVALID"),
        (("credential", "ca"), "CREDENTIAL_REPAIR_REQUIRED"),
        (("ca",), "TLS_REPAIR_REQUIRED"),
    ],
)
def test_remaining_failure_precedence_with_overlapping_defects(
    machine, monkeypatch, tmp_path, defects, want
):
    module, paths, _package, _release, services = machine
    if "disk" in defects:
        monkeypatch.setattr(
            module,
            "_disk",
            lambda *_: {
                "sufficient": False,
                "scope": "verified_allocations",
                "free_bytes": 0,
            },
        )
    if "service" in defects:
        services["EndpointAgent"]["identity_valid"] = False
    if "credential" in defects:
        (paths.updates_root.parent / "device-credential").unlink()
    if "ca" in defects:
        (paths.updates_root.parent / "endpoint-ca.crt").unlink()
    before = snapshot(tmp_path)
    assert module.collect_fleet_preflight(paths, "3.2.82")["eligibility"] == want
    assert snapshot(tmp_path) == before


def test_setup_preflight_branches_before_any_diagnostic_or_machine_mutation(
    tmp_path, monkeypatch, capsys
):
    from pc_agent.platform.windows import setup_entry, fleet_preflight
    from pc_agent.tests.windows.test_setup_entry import _write_public_payload

    _write_public_payload(tmp_path)
    monkeypatch.setattr(setup_entry, "_resource_root", lambda: tmp_path)
    paths = WindowsUpdatePaths(
        tmp_path / "missing-install",
        tmp_path / "missing-data/updates/pending_update.json",
    )
    monkeypatch.setattr(
        WindowsUpdatePaths, "production", classmethod(lambda cls: paths)
    )
    monkeypatch.setattr(
        fleet_preflight,
        "collect_fleet_preflight",
        lambda *_a, **_kw: {"eligibility": "FOUNDATION_UNKNOWN"},
    )
    for name in (
        "_record_in_progress",
        "_data_root",
        "_install_embedded_msi",
        "_classify_installation_state",
        "_finish",
    ):
        monkeypatch.setattr(
            setup_entry,
            name,
            lambda *_a, **_kw: pytest.fail("preflight mutated or entered installation"),
        )
    before = snapshot(tmp_path)
    assert setup_entry.main(["--preflight", "--quiet"]) == 0
    assert json.loads(capsys.readouterr().out) == {"eligibility": "FOUNDATION_UNKNOWN"}
    assert snapshot(tmp_path) == before


def test_native_inventory_access_failure_is_unknown_without_exception_text(
    machine, monkeypatch
):
    import pywintypes

    module, paths, *_ = machine

    def denied(*_a, **_kw):
        raise pywintypes.error(
            5, "secret-native-function", "credential-secret-native-error"
        )

    monkeypatch.setattr(msi_inventory, "read_expected_package", denied)
    result = module.collect_fleet_preflight(paths, "3.2.82")
    assert result["eligibility"] == "FOUNDATION_UNKNOWN"
    assert "credential-secret-native-error" not in json.dumps(result)


def test_credential_readable_by_ordinary_users_is_repair_required(machine, monkeypatch):
    from pc_agent.platform.windows.acl import PyWin32AclAdapter, WindowsAclError

    module, paths, *_ = machine

    def insecure(*_):
        raise WindowsAclError("unsafe secret detail")

    monkeypatch.setattr(PyWin32AclAdapter, "assert_protected_file", insecure)
    result = module.collect_fleet_preflight(paths, "3.2.82")
    assert result["eligibility"] == "CREDENTIAL_REPAIR_REQUIRED"
    assert "unsafe secret detail" not in json.dumps(result)


def test_symlinked_selector_is_provenance_conflict_without_mutation(machine, tmp_path):
    module, paths, *_ = machine
    target = tmp_path / "untrusted-selector"
    target.write_bytes(paths.current_path.read_bytes())
    paths.current_path.unlink()
    try:
        paths.current_path.symlink_to(target)
    except OSError:
        pytest.skip("symlink privilege unavailable")
    before = snapshot(tmp_path)
    assert (
        module.collect_fleet_preflight(paths, "3.2.82")["eligibility"]
        == "PROVENANCE_CONFLICT"
    )
    assert snapshot(tmp_path) == before


def test_unknown_complete_setup_cost_is_never_ready_even_with_free_space(
    machine, monkeypatch
):
    module, paths, *_ = machine
    monkeypatch.setattr(
        module,
        "_disk",
        lambda *_: {
            "sufficient": None,
            "scope": "setup_allocation_unknown",
            "free_bytes": 10**12,
        },
    )
    assert (
        module.collect_fleet_preflight(paths, "3.2.82")["eligibility"] == "DISK_UNKNOWN"
    )


def test_windowed_setup_emits_exact_json_to_inherited_pipe(monkeypatch):
    from pc_agent.platform.windows import setup_entry
    import io

    sink = io.BytesIO()
    monkeypatch.setattr(setup_entry.sys, "stdout", None)
    monkeypatch.setattr(
        setup_entry,
        "_write_inherited_stdout",
        lambda value: sink.write(value),
        raising=False,
    )
    setup_entry._emit_preflight({"eligibility": "FOUNDATION_UNKNOWN"})
    assert json.loads(sink.getvalue()) == {"eligibility": "FOUNDATION_UNKNOWN"}
    assert sink.getvalue().endswith(b"\n")


@pytest.mark.parametrize(
    "handle,written,success,want_error",
    [
        (123, 4, True, False),
        (0, 4, True, True),
        (-1, 4, True, True),
        (123, 2, True, True),
        (123, 0, False, True),
    ],
)
def test_inherited_stdout_rejects_invalid_handle_failed_and_partial_write(
    handle, written, success, want_error
):
    import ctypes
    from pc_agent.platform.windows import setup_entry

    class Function:
        def __init__(self, call):
            self.call = call

        def __call__(self, *args):
            return self.call(*args)

    calls = []

    def write(h, buffer, size, count, overlapped):
        calls.append(ctypes.string_at(buffer, size))
        count._obj.value = written
        return success

    kernel = SimpleNamespace(
        GetStdHandle=Function(lambda _: handle), WriteFile=Function(write)
    )
    if want_error:
        with pytest.raises(OSError):
            setup_entry._write_inherited_stdout(b"{}\r\n", kernel=kernel)
    else:
        setup_entry._write_inherited_stdout(b"{}\r\n", kernel=kernel)
        assert calls == [b"{}\r\n"]
    if handle in (0, -1):
        assert calls == []


@pytest.mark.parametrize("retained", [False, True])
def test_real_task7_core_authority_projects_live_and_retained_origin(
    handoff_input, monkeypatch, tmp_path, retained
):
    from pc_agent.platform.windows import fleet_preflight as module, update_transaction
    from pc_agent.platform.windows.acl import PyWin32AclAdapter
    from pc_agent.platform.windows import msi_inventory as inventory

    provenance, paths, root, request, expected = handoff_input
    # Complete the actual canonical handoff producer in a scratch fixture.
    provenance.prepare_installer_provenance(paths, request)
    (root / ".endpoint-msi-runtime.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "version": "3.2.82",
                "component_guid": "33333333-3333-4333-8333-333333333333",
            }
        )
    )
    provenance.reconcile_installed_core(paths, request)
    # Native calls are modeled; ownership, component/path and all payload
    # verification remain the production implementation.
    package = expected.package

    class Native:
        removed = False

        def product(self, _):
            return -1 if self.removed else 5

        def property(self, _code, key):
            return package.version if key == "VersionString" else package.package_code

        def feature(self, _code, _feature):
            return 3

        def component(self, _code, guid):
            component = next(c for c in package.components.values() if c.guid == guid)
            item = next(f for f in package.files if f.name == component.keypath)
            return 3, str(paths.install_root / item.path)

    native = Native()
    monkeypatch.setattr(inventory, "NativeMsi", lambda: native)
    monkeypatch.setattr(inventory, "verify_installed", _VERIFY_INSTALLED)
    monkeypatch.setattr(inventory, "verify_foundation", _VERIFY_FOUNDATION)
    captured = provenance.inspect_installed_core(
        paths, resulting_foundation="3.2.82"
    ).current
    if retained:
        monkeypatch.setattr(inventory, "read_package", lambda *_: expected.package)
        archive = provenance.archive_retained_core(
            paths,
            captured,
            package_path=request["package_path"],
            package=expected.package,
            transaction_id=request["transaction_id"],
        )
        native.removed = True
        for p in root.iterdir():
            p.unlink()
        provenance.restore_retained_core(paths, archive.name)
    data = paths.updates_root.parent
    data.mkdir(parents=True, exist_ok=True)
    (data / "device-credential").write_bytes(b"S" * 43)
    (data / "enrollment-identity.json").write_text(
        json.dumps(
            {
                "schema_version": "endpoint_enrollment_identity_v1",
                "device_id": "11111111-1111-4111-8111-111111111111",
            }
        )
    )
    (data / "endpoint-ca.crt").write_bytes(b"public CA fixture")
    monkeypatch.setattr(update_transaction, "_assert_state_security", lambda *_: None)
    monkeypatch.setattr(PyWin32AclAdapter, "assert_protected_file", lambda *_: None)
    monkeypatch.setattr(module, "_ca_parseable", lambda _: True)
    monkeypatch.setattr(
        module,
        "_services",
        lambda _: {
            name: {
                "present": True,
                "state": "stopped",
                "start_mode": "automatic" if name == "EndpointAgent" else "manual",
                "identity_valid": True,
            }
            for name in module.SERVICES
        },
    )
    before = snapshot(tmp_path)
    result = module.collect_fleet_preflight(paths, "3.2.82")
    assert result["core"]["verified"] is True
    assert result["core"]["origin"] == ("retained_msi" if retained else "msi")
    assert result["core"]["package_sha256"] == expected.package.sha256
    assert result["foundation"]["native_verified"] is (not retained)
    assert snapshot(tmp_path) == before


def test_shared_preparation_plan_counts_only_new_copies_without_publication(
    handoff_input, tmp_path
):
    module, paths, root, request, expected = handoff_input
    inspected = module.inspect_installed_core(
        paths, resulting_foundation=expected.package.version
    )
    before = snapshot(tmp_path)
    allocations, jobs = module.preparation_allocations(
        paths, inspected, expected, request["package_path"]
    )
    assert jobs == ()
    assert allocations == (
        (
            installer_fence.state_root(paths),
            2 * request["package_path"].stat().st_size + 4 * 1024 * 1024 + 16384,
        ),
    )
    assert snapshot(tmp_path) == before


def test_shared_setup_plan_combines_native_wrapper_and_provenance_allocations(
    handoff_input, monkeypatch, tmp_path
):
    from pc_agent.platform.windows import setup_entry

    module, paths, root, request, expected = handoff_input
    media = request["package_path"]
    release = media.with_name("EndpointAgent.release.json")
    release.write_text(json.dumps(request["release"]))
    monkeypatch.setattr(
        setup_entry,
        "_verify_embedded_msi",
        lambda _: (release, media.with_name("Install-EndpointAgentCanary.ps1")),
    )
    monkeypatch.setattr(
        setup_entry, "_msi_disk_costs", lambda _: [(tmp_path / "native-volume", 700000)]
    )
    before = snapshot(tmp_path)
    allocations = setup_entry._setup_disk_allocations(media, paths)
    assert (tmp_path / "native-volume", 700000) in allocations
    assert (
        paths.install_root.parent / "installer-cache",
        media.stat().st_size,
    ) in allocations
    assert (paths.updates_root.parent, media.stat().st_size + 16384) in allocations
    assert (
        installer_fence.state_root(paths),
        2 * media.stat().st_size + 4 * 1024 * 1024 + 16384,
    ) in allocations
    assert snapshot(tmp_path) == before


def test_recovery_budget_uses_saved_authority_with_partial_core(
    handoff_input, monkeypatch, tmp_path
):
    module, paths, root, request, expected = handoff_input
    module.prepare_installer_provenance(paths, request)
    (paths.versions_root / expected.identity.version).mkdir(exist_ok=True)
    fence = {
        "package": {
            "sha256": expected.package.sha256,
            "product_code": expected.package.product_code,
            "package_code": expected.package.package_code,
            "version": expected.package.version,
            "source_revision": expected.identity.source_revision,
        },
        "operation": "install",
        "transaction_id": request["transaction_id"],
        "selected": request["selected"],
        "previous": request["previous"],
    }
    monkeypatch.setattr(installer_fence, "read_fence", lambda _: fence)
    monkeypatch.setattr(
        module,
        "inspect_installed_core",
        lambda *_args, **_kwargs: pytest.fail("ordinary coherent inspection"),
    )
    before = snapshot(tmp_path)
    authority = module.recovery_cost_authority(
        paths, request["package_path"], request["release"]
    )
    assert authority.packages == ((request["package_path"], expected.package),)
    assert authority.operation == "install"
    assert authority.allocations
    assert snapshot(tmp_path) == before
    fence["package"]["package_code"] = "{00000000-0000-4000-8000-000000000000}"
    with pytest.raises(module.ProvenanceConflict):
        module.recovery_cost_authority(
            paths, request["package_path"], request["release"]
        )


def test_equal_zip_requires_handoff_and_package_context_proves_combined_space(
    machine, monkeypatch, tmp_path
):
    module, paths, package, release, *_ = machine
    write_zip(paths, "3.2.82")
    package.version = "3.2.82"
    release["version"] = "3.2.82"
    (installer_fence.state_root(paths) / "foundation.json").write_text(
        json.dumps({"schema_version": 1, "release": release})
    )
    assert (
        module.collect_fleet_preflight(paths, "3.2.82")["eligibility"]
        == "READY_FOR_SETUP_UPGRADE"
    )


@pytest.mark.parametrize("free,want", [(1000000000, True), (1, False)])
def test_package_bound_disk_uses_shared_aggregate_plan(
    handoff_input, monkeypatch, tmp_path, free, want
):
    import shutil
    from pc_agent.platform.windows import fleet_preflight, setup_entry

    module, paths, root, request, expected = handoff_input
    release = request["package_path"].with_name("EndpointAgent.release.json")
    release.write_text(json.dumps(request["release"]))
    monkeypatch.setattr(
        setup_entry, "_verify_embedded_msi", lambda _: (release, release)
    )
    monkeypatch.setattr(setup_entry, "_msi_disk_costs", lambda _: [(tmp_path, 700000)])
    monkeypatch.setattr(shutil, "disk_usage", lambda _: SimpleNamespace(free=free))
    before = snapshot(tmp_path)
    assert fleet_preflight._disk(paths, request["package_path"]) == {
        "sufficient": want,
        "scope": "verified_allocations",
        "free_bytes": free,
    }
    assert snapshot(tmp_path) == before


def test_canonical_current_skips_transition_costing(machine, monkeypatch, tmp_path):
    from pc_agent.platform.windows import setup_entry

    module, paths, package, release, *_ = machine
    write_zip(paths, "3.2.83")
    package.version = "3.2.84"
    release["version"] = "3.2.84"
    (installer_fence.state_root(paths) / "foundation.json").write_text(
        json.dumps({"schema_version": 1, "release": release})
    )

    def disk(_paths, setup_package=None):
        assert setup_package is None
        return {
            "sufficient": None,
            "scope": "setup_allocation_unknown",
            "free_bytes": 0,
        }

    monkeypatch.setattr(module, "_disk", disk)
    canonical = tmp_path / "EndpointAgent.release.json"
    canonical.write_text(
        json.dumps({"version": "3.2.82", "package_sha256": package.sha256})
    )
    monkeypatch.setattr(
        setup_entry, "_verify_embedded_msi", lambda _: (canonical, canonical)
    )
    assert (
        module.collect_fleet_preflight(
            paths, "3.2.82", setup_package=tmp_path / "canonical.msi"
        )["eligibility"]
        == "ALREADY_CURRENT"
    )


@pytest.mark.parametrize(
    "core_version,minimum,feature",
    [
        ("3.2.82", "3.2.82", "complete"),
        ("3.2.81", "3.2.81", "complete"),
        ("3.2.82", "3.2.84", "complete"),
        ("3.2.83", "3.2.84", "foundation_only"),
    ],
)
def test_higher_actual_foundation_skips_older_setup_and_cost(
    machine, monkeypatch, tmp_path, core_version, minimum, feature
):
    from pc_agent.platform.windows import setup_entry

    module, paths, package, release, *_ = machine
    package.version = release["version"] = "3.2.84"
    (installer_fence.state_root(paths) / "foundation.json").write_text(
        json.dumps({"schema_version": 1, "release": release})
    )
    # This is a modern explicit-floor payload fixture, not a grant to immutable81.
    write_zip(paths, core_version, minimum)
    monkeypatch.setattr(msi_inventory, "verify_foundation", lambda *_a, **_kw: feature)
    canonical = tmp_path / "EndpointAgent.release.json"
    canonical.write_text(json.dumps({"version": "3.2.82", "package_sha256": "d" * 64}))
    monkeypatch.setattr(
        setup_entry, "_verify_embedded_msi", lambda _: (canonical, canonical)
    )
    monkeypatch.setattr(
        setup_entry,
        "_setup_disk_allocations",
        lambda *_: pytest.fail("older Setup has no transition to cost"),
    )
    # Restore production cost dispatch; the native cost provider must stay unused.
    monkeypatch.setattr(module, "_disk", _PRODUCTION_DISK)
    before = snapshot(tmp_path)
    result = module.collect_fleet_preflight(paths, "3.2.82", setup_package=canonical)
    assert result["eligibility"] == "ALREADY_CURRENT"
    assert result["core"]["version"] == core_version
    assert result["foundation"]["version"] == "3.2.84"
    assert snapshot(tmp_path) == before


@pytest.mark.parametrize("defect", [None, "missing", "damaged", "owner"])
def test_equal_foundation_checks_actual_target_candidate_while_preserving_newer_zip(
    handoff_input, monkeypatch, tmp_path, defect
):
    from pc_agent.platform.windows import (
        fleet_preflight as module,
        setup_entry,
        update_transaction,
    )
    from pc_agent.tests.windows.test_installation_provenance import zip_core

    provenance, paths, root, request, expected = handoff_input
    monkeypatch.setattr(update_transaction, "_assert_state_security", lambda _: None)
    provenance.prepare_installer_provenance(paths, request)
    (root / ".endpoint-msi-runtime.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "version": "3.2.82",
                "component_guid": "33333333-3333-4333-8333-333333333333",
            }
        )
    )
    provenance.reconcile_installed_core(paths, request)
    paths.previous_path.unlink(missing_ok=True)
    zip_core(paths, version="3.2.83", minimum="3.2.82")
    if defect == "missing":
        (root / "pc_agent.exe").unlink()
    elif defect == "damaged":
        (root / "pc_agent.exe").write_bytes(b"changed")
    elif defect == "owner":
        (installer_fence.state_root(paths) / "core-owners/3.2.82.json").unlink()
    canonical = request["package_path"].with_name("EndpointAgent.release.json")
    canonical.write_text(json.dumps(request["release"]))
    monkeypatch.setattr(
        setup_entry, "_verify_embedded_msi", lambda _: (canonical, canonical)
    )
    monkeypatch.setattr(msi_inventory, "installed_feature_state", lambda _: "complete")
    monkeypatch.setattr(
        module,
        "_foundation",
        lambda _: {
            "version": expected.package.version,
            "source_revision": expected.identity.source_revision,
            "package_sha256": expected.package.sha256,
            "product_code": expected.package.product_code,
            "native_verified": True,
            "feature_state": "complete",
        },
    )
    monkeypatch.setattr(
        module,
        "_services",
        lambda _: {
            name: {
                "present": True,
                "state": "running",
                "start_mode": "automatic",
                "identity_valid": True,
            }
            for name in module.SERVICES
        },
    )
    monkeypatch.setattr(
        module,
        "_shape",
        lambda _: {
            "present": True,
            "shape_valid": True,
            "enrollment_shape_valid": True,
            "authenticated": None,
        },
    )
    monkeypatch.setattr(
        module,
        "_ca",
        lambda _: {"present": True, "parseable": True, "strict_live_tls": None},
    )
    costs = []
    monkeypatch.setattr(
        setup_entry,
        "_msi_disk_costs",
        lambda _: costs.append("native") or [(tmp_path, 4096)],
    )
    before = snapshot(tmp_path)
    result = module.collect_fleet_preflight(
        paths, "3.2.82", setup_package=request["package_path"]
    )
    assert result["eligibility"] == (
        "ALREADY_CURRENT" if defect is None else "READY_FOR_SETUP_UPGRADE"
    )
    assert result["core"]["version"] == "3.2.83"
    assert costs == ([] if defect is None else ["native"])
    assert snapshot(tmp_path) == before


@pytest.mark.parametrize("operation", ["retire-initial-runtime", "uninstall"])
def test_maintenance_recovery_budget_has_no_install_archive_jobs(
    handoff_input, monkeypatch, tmp_path, operation
):
    module, paths, root, request, expected = handoff_input
    module.prepare_installer_provenance(paths, request)
    (root / ".endpoint-msi-runtime.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "version": "3.2.82",
                "component_guid": "33333333-3333-4333-8333-333333333333",
            }
        )
    )
    module.reconcile_installed_core(paths, request)
    module.prepare_maintenance_provenance(paths, request, operation)
    fence = {
        "package": {
            "sha256": expected.package.sha256,
            "product_code": expected.package.product_code,
            "package_code": expected.package.package_code,
            "version": expected.package.version,
            "source_revision": expected.identity.source_revision,
        },
        "operation": operation,
        "transaction_id": request["transaction_id"],
        "selected": request["selected"],
        "previous": request["previous"],
    }
    monkeypatch.setattr(installer_fence, "read_fence", lambda _: fence)
    before = snapshot(tmp_path)
    authority = module.recovery_cost_authority(
        paths, request["package_path"], request["release"]
    )
    assert authority.allocations == ((installer_fence.state_root(paths), 16384),)
    assert authority.packages == ((request["package_path"], expected.package),)
    assert snapshot(tmp_path) == before
    leaf = (
        installer_fence.state_root(paths)
        / "transactions"
        / request["transaction_id"]
        / "maintenance.json"
    )
    leaf.unlink()
    with pytest.raises((ValueError, OSError)):
        module.recovery_cost_authority(
            paths, request["package_path"], request["release"]
        )


def test_canonical_service_query_accepts_only_fixed_command_arguments(
    machine, monkeypatch
):
    import win32service

    module, paths, *_ = machine
    # Restore only the production query function replaced by the machine fixture.
    from importlib import reload

    query = reload(module)._services
    for file in ("endpoint-agent-service.exe", "endpoint-agent-updater.exe"):
        (paths.install_root / file).write_bytes(b"protected host")
    calls = []
    monkeypatch.setattr(
        win32service,
        "OpenSCManager",
        lambda *args: calls.append(("manager", args)) or "manager",
    )
    monkeypatch.setattr(
        win32service,
        "OpenService",
        lambda _manager, name, access: calls.append(("service", access)) or name,
    )
    monkeypatch.setattr(
        win32service,
        "CloseServiceHandle",
        lambda handle: calls.append(("close", handle)),
    )

    def config(name):
        agent = name == "EndpointAgent"
        file = "endpoint-agent-service.exe" if agent else "endpoint-agent-updater.exe"
        argument = "--agent-service" if agent else "--updater-service"
        return (
            16,
            2,
            1,
            f'"{paths.install_root / file}" {argument}',
            None,
            None,
            None,
            "NT AUTHORITY\\LocalService" if agent else "LocalSystem",
            None,
        )

    monkeypatch.setattr(win32service, "QueryServiceConfig", config)
    monkeypatch.setattr(
        win32service, "QueryServiceStatus", lambda _: (16, 4, 0, 0, 0, 0, 0)
    )
    assert all(value["identity_valid"] for value in query(paths).values())
    monkeypatch.setattr(
        win32service,
        "QueryServiceConfig",
        lambda name: (
            *config(name)[:3],
            config(name)[3] + " --untrusted",
            *config(name)[4:],
        ),
    )
    assert all(value["identity_valid"] is False for value in query(paths).values())
    assert all(
        access == win32service.SERVICE_QUERY_CONFIG | win32service.SERVICE_QUERY_STATUS
        for kind, access in calls
        if kind == "service"
    )


def test_recovery_archive_budget_reuses_verified_payload_and_rejects_conflicts(
    handoff_input, monkeypatch, tmp_path
):
    from dataclasses import replace
    from pc_agent.tests.windows.test_installation_provenance import zip_core
    from pc_agent.platform.windows import setup_entry, disk_readiness

    module, paths, root, request, expected = handoff_input
    module.prepare_installer_provenance(paths, request)
    selector = paths.current_path.read_bytes()
    oldroot = zip_core(paths, version="3.2.83", minimum="3.2.82")
    evidence = module.inspect_installed_core(
        paths, resulting_foundation="3.2.82"
    ).current
    oldmedia = tmp_path / "old.msi"
    oldmedia.write_bytes(b"exact old package fixture")
    oldpackage = replace(
        expected.package,
        version="3.2.83",
        product_code="{44444444-4444-4444-8444-444444444444}",
        sha256=hashlib.sha256(oldmedia.read_bytes()).hexdigest(),
    )
    oldrelease = {
        **request["release"],
        "version": "3.2.83",
        "package_sha256": oldpackage.sha256,
        "product_code": oldpackage.product_code,
    }
    evidence = replace(
        evidence,
        origin="msi",
        receipt_bytes=json.dumps({"schema_version": 1, "release": oldrelease}).encode(),
    )
    (oldroot / ".endpoint-update.json").unlink()
    (oldroot / ".endpoint-msi-runtime.json").write_text("{}")
    monkeypatch.setattr(msi_inventory, "read_package", lambda *_: oldpackage)
    archive = module.archive_retained_core(
        paths,
        evidence,
        package_path=oldmedia,
        package=oldpackage,
        transaction_id=request["transaction_id"],
    )
    paths.current_path.write_bytes(selector)
    planpath = (
        installer_fence.state_root(paths)
        / "provenance"
        / request["transaction_id"]
        / "plan.json"
    )
    plan = json.loads(planpath.read_bytes())
    plan["archives"] = [archive.name]
    planpath.write_text(json.dumps(plan))
    fence = {
        "package": {
            "sha256": expected.package.sha256,
            "product_code": expected.package.product_code,
            "package_code": expected.package.package_code,
            "version": expected.package.version,
            "source_revision": expected.identity.source_revision,
        },
        "operation": "install",
        "transaction_id": request["transaction_id"],
        "selected": request["selected"],
        "previous": request["previous"],
    }
    monkeypatch.setattr(installer_fence, "read_fence", lambda _: fence)
    monkeypatch.setattr(msi_inventory, "read_package", lambda *_: oldpackage)
    release = request["package_path"].with_name("EndpointAgent.release.json")
    release.write_text(json.dumps(request["release"]))
    monkeypatch.setattr(
        setup_entry, "_verify_embedded_msi", lambda _: (release, release)
    )
    monkeypatch.setattr(
        setup_entry, "_msi_disk_costs", lambda *_args, **_kwargs: [(tmp_path, 100000)]
    )
    before = snapshot(tmp_path)
    authority = module.recovery_cost_authority(
        paths, request["package_path"], request["release"]
    )
    assert authority.packages[-1] == (archive / "package.msi", oldpackage)
    assert authority.allocations[-1][0] == paths.versions_root
    assert (
        authority.allocations[-1][1]
        >= sum(item.size for item in evidence.identity.files) + 4 * 1024 * 1024
    )
    allocations = setup_entry._setup_disk_allocations(request["package_path"], paths)
    assert authority.allocations[-1] in allocations
    assert snapshot(tmp_path) == before
    import shutil

    monkeypatch.setattr(shutil, "disk_usage", lambda _: SimpleNamespace(free=1))
    with pytest.raises(disk_readiness.DiskInsufficient):
        disk_readiness.require_allocation_space(allocations)
    monkeypatch.setattr(
        msi_inventory,
        "read_package",
        lambda *_: replace(
            oldpackage, package_code="{99999999-9999-4999-8999-999999999999}"
        ),
    )
    with pytest.raises(module.ProvenanceConflict):
        module.recovery_cost_authority(
            paths, request["package_path"], request["release"]
        )
    (archive / "package.msi").write_bytes(b"changed old package")
    with pytest.raises((ValueError, OSError)):
        module.recovery_cost_authority(
            paths, request["package_path"], request["release"]
        )
