"""One-file Windows Setup entrypoint boundaries."""

from __future__ import annotations

import json
import hashlib
import os
import runpy
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

import pytest

from pc_agent.platform.windows import setup_entry
from pc_agent.tests.windows.test_staged_update_state import begin, move, native_protected_root, staged
from pc_agent.windows_setup import (
    SetupClaimError,
    SetupConfig,
    SetupOutcome,
    SetupProvisionError,
)


@pytest.mark.parametrize('defect,wrapper_exit,terminal,receipt', [
    (None, 0, 'accepted', ('UPDATED', 0, 'SERVICE', 'SERVICE_RUNNING')),
    (None, 67, 'rolled-back', ('ROLLED_BACK', 67, 'MSI', 'CANDIDATE_ROLLED_BACK')),
    (None, 3010, 'switching', None),
    (None, 21, 'switching', None),
    (None, 61, 'switching', None),
    (None, 0, 'other-operation', None),
    (None, 0, 'switching', None),
    (None, 0, 'busy', None),
    ('damaged', 0, 'accepted', ('UPDATED', 0, 'SERVICE', 'SERVICE_RUNNING')),
    ('damaged-busy', 0, 'accepted', None),
    ('damaged-foreign', 0, 'accepted', None),
    ('not-frozen', 0, 'accepted', None),
    ('foreign-executable', 0, 'accepted', None),
    ('owner-alive', 0, 'accepted', None),
    ('changed-wrapper', 0, 'accepted', None),
])
def test_frozen_staged_watchdog_uses_package_imports_and_preserves_admission(
        tmp_path, monkeypatch, defect, wrapper_exit, terminal, receipt):
    """Exercise the real file entry, not its package-imported function."""
    from pc_agent.platform.windows import staged_recovery, update_paths

    entry = runpy.run_path(setup_entry.__file__)
    assert not entry['__package__']
    scope = entry['_run_staged_recovery'].__globals__
    paths = update_paths.WindowsUpdatePaths(tmp_path/'Agent', tmp_path/'data/updates/pending.json')
    digest = 'a'*64
    cache = tmp_path/'installer-cache'/('msi-'+digest)
    cache.mkdir(parents=True)
    resource = tmp_path/'resource';resource.mkdir()
    for name in ('EndpointAgent.release.json', 'Install-EndpointAgentCanary.ps1'):
        (resource/name).write_bytes(b'reviewed embedded input')
        (cache/name).write_bytes(b'changed' if defect == 'changed-wrapper' and name.endswith('.ps1') else b'reviewed embedded input')
    operation = '11111111-1111-4111-8111-111111111111'
    record = SimpleNamespace(binding=SimpleNamespace(operation_id=operation), owner={'pid':42})
    finished_binding = SimpleNamespace(operation_id='foreign') if terminal == 'other-operation' else record.binding
    finished = SimpleNamespace(binding=finished_binding, phase=terminal, owner=record.owner)
    events = []
    results = []
    from contextlib import contextmanager

    @contextmanager
    def transaction(actual_paths, *, timeout_ms):
        assert actual_paths is paths and timeout_ms == 0
        if terminal == 'busy':
            raise setup_entry.UpdateInProgress('UPDATE_IN_PROGRESS')
        events.append('receipt-lock')
        try:
            yield
        finally:
            events.append('receipt-unlock')

    scope['update_transaction'] = transaction
    scope['_finish'] = lambda _, **fields: results.append(fields) or fields['code']
    scope['_install_support_after_native'] = lambda root: events.append(('post-install', root))
    monkeypatch.setattr(setup_entry.sys, 'frozen', defect != 'not-frozen', raising=False)
    monkeypatch.setattr(setup_entry.sys, 'executable', str(tmp_path/'foreign.exe' if defect in ('foreign-executable', 'damaged-foreign') else cache/'EndpointAgentSetup.exe'))
    scope['WindowsUpdatePaths'] = SimpleNamespace(production=lambda: paths)
    scope['_resource_root'] = lambda: resource
    scope['_verify_embedded_msi'] = lambda _: (resource/'EndpointAgent.release.json', resource/'Install-EndpointAgentCanary.ps1')
    monkeypatch.setattr(staged_recovery.state, 'read_staged_update', lambda _: finished if 'launch' in events else record)
    if defect in ('damaged', 'damaged-busy', 'damaged-foreign'):
        def read_damaged(actual_paths, operation_id):
            assert actual_paths is paths and operation_id == operation
            return record, b'INDX'
        def restore_damaged(actual_paths, actual_record, damaged):
            assert actual_paths is paths and actual_record is record and damaged == b'INDX'
            events.append('restore-journal')
            if defect == 'damaged-busy':
                raise setup_entry.UpdateInProgress('UPDATE_IN_PROGRESS')
        monkeypatch.setattr(staged_recovery, 'read_recoverable_stage', read_damaged)
        monkeypatch.setattr(staged_recovery, 'restore_damaged_stage', restore_damaged)
    monkeypatch.setattr(staged_recovery, '_validate_recovery_inputs', lambda *_: {'package_sha256':digest})
    monkeypatch.setattr(staged_recovery, 'wait_for_original_owner', lambda *a, **k: events.append('wait'))
    def dead(_):
        events.append('dead')
        if defect == 'owner-alive':
            raise ValueError('OWNER_AUTH_FAILED')
    monkeypatch.setattr(staged_recovery, '_assert_owner_dead', dead)
    monkeypatch.setattr(update_paths, '_native_folder', lambda _: tmp_path/'system32')
    def invoke(command, **kwargs):
        events.append('launch')
        assert command[0] == str(tmp_path/'system32/WindowsPowerShell/v1.0/powershell.exe')
        assert command[command.index('-Operation')+1] == 'RecoverStagedUpdate'
        assert command[command.index('-StagedOperationId')+1] == operation
        assert kwargs['shell'] is False
        return SimpleNamespace(returncode=wrapper_exit)
    monkeypatch.setattr(setup_entry.subprocess, 'run', invoke)
    result = entry['_run_staged_recovery'](operation)
    if defect in (None, 'damaged'):
        expected = ['wait', 'dead']
        if defect == 'damaged':
            expected.append('restore-journal')
        expected.append('launch')
        if wrapper_exit in (0, 67) and terminal != 'busy':
            expected.extend(['receipt-lock', 'receipt-unlock'])
        if receipt is not None and wrapper_exit == 0:
            expected.append(('post-install', paths.pending_path.parents[1]))
        assert events == expected
    else:
        assert 'launch' not in events
        assert ('restore-journal' in events) is (defect == 'damaged-busy')
    if receipt is None:
        assert results == []
        assert result == (wrapper_exit if wrapper_exit in (21, 3010) else setup_entry.EXIT_REPAIR_REQUIRED)
    else:
        assert results == [dict(zip(('status', 'code', 'stage', 'detail'), receipt))]
        assert result == wrapper_exit


@pytest.mark.parametrize(
    "operation",
    ["recovery", "native-cost", "disk-cost", "recovery-cost", "installed", "handoff"],
)
def test_setup_file_entry_executes_package_helpers(tmp_path, monkeypatch, operation):
    """PyInstaller executes the selected source file without a parent package."""
    from pc_agent.platform.windows import installation_provenance, msi_disk_costing, msi_inventory
    from pc_agent.platform.windows.update_paths import WindowsUpdatePaths

    _write_public_payload(tmp_path)
    entry = runpy.run_path(setup_entry.__file__)
    assert not entry["__package__"]
    namespace = entry["_embedded_recovery_operation"].__globals__
    namespace["_data_root"] = lambda: tmp_path / "data"
    paths = WindowsUpdatePaths.production()
    media = tmp_path / "EndpointAgent.msi"
    costs = [(tmp_path, 4096)]
    monkeypatch.setattr(msi_disk_costing, "msi_disk_allocations", lambda *a, **kw: costs.copy())
    monkeypatch.setattr(installation_provenance, "preparation_allocations", lambda *a: ([], []))
    monkeypatch.setattr(msi_inventory, "installed_feature_state", lambda _: "absent")

    if operation == "recovery":
        assert namespace["_embedded_recovery_operation"](media) is None
    elif operation == "native-cost":
        assert namespace["_msi_disk_costs"](media) == costs
    elif operation in {"disk-cost", "recovery-cost"}:
        if operation == "recovery-cost":
            monkeypatch.setattr(
                installation_provenance, "recovery_cost_authority",
                lambda *a: SimpleNamespace(allocations=[], predecessor_media=None),
            )
        allocations = namespace["_setup_disk_allocations"](media, paths)
        assert allocations[0] == costs[0]
        assert (paths.install_root.parent / "installer-cache", media.stat().st_size) in allocations
    elif operation == "installed":
        assert namespace["_installed_msi_version"]() is None
    else:
        assert namespace["_msi_reconciliation_required"](media, paths=paths)


@pytest.fixture(autouse=True)
def literal_msi_costing_boundary(monkeypatch, tmp_path):
    (tmp_path / "data").mkdir(exist_ok=True)
    (tmp_path / "agent-data").mkdir(exist_ok=True)
    monkeypatch.setattr(setup_entry, "_diagnostics_root", lambda: tmp_path / "diagnostics")
    # Setup unit fixtures model state schemas, not machine directory ACLs.
    # Native directory/leaf security is covered by test_update_transaction.
    from pc_agent.platform.windows import update_transaction

    monkeypatch.setattr(update_transaction, "_assert_state_security", lambda _: None)
    # Fixture MSIs are b'msi', not real Installer databases. Keep the disk
    # accounting/check real and replace only the native package reader.
    monkeypatch.setattr(
        setup_entry, "_msi_disk_costs", lambda _: [(tmp_path, 4096)], raising=False
    )
    monkeypatch.setattr(
        setup_entry, "_msi_reconciliation_required", lambda _: False, raising=False
    )
    from pc_agent.platform.windows import (
        installation_provenance as provenance,
        msi_inventory,
    )
    from pc_agent.platform.windows.update_paths import WindowsUpdatePaths

    paths = WindowsUpdatePaths(
        tmp_path / "Agent", tmp_path / "data/updates/pending_update.json"
    )
    monkeypatch.setattr(
        WindowsUpdatePaths, "production", classmethod(lambda cls: paths)
    )
    monkeypatch.setattr(
        msi_inventory,
        "read_expected_package",
        lambda *_: SimpleNamespace(package=SimpleNamespace(version="1.0.0")),
    )
    monkeypatch.setattr(msi_inventory, "binary_size", lambda *a, **kw: 250)
    monkeypatch.setattr(
        provenance,
        "inspect_installed_core",
        lambda *_args, **_kwargs: SimpleNamespace(current=None, previous=None),
    )
    monkeypatch.setattr(provenance, "recovery_cost_authority", lambda *_: None)


def test_setup_counts_new_protected_cache_on_its_own_volume(tmp_path, monkeypatch):
    from pc_agent.platform.windows import disk_readiness
    _write_public_payload(tmp_path)
    data = tmp_path / "data"
    system = tmp_path / "system"
    system.mkdir()
    monkeypatch.setattr(setup_entry, "_data_root", lambda: data)
    monkeypatch.setattr(setup_entry, "_msi_disk_costs", lambda _: [(system, 51200)])
    observed = []
    monkeypatch.setattr(disk_readiness, "allocation_volume", lambda path: path)
    monkeypatch.setattr(disk_readiness, "require_disk_space", lambda path, count: observed.append((path, count)))
    setup_entry._require_setup_disk(tmp_path / "EndpointAgent.msi")
    # Native costing includes Windows Installer cache/temp. Only our protected
    # provenance cache and bounded state are added on the data volume.
    assert (system, 67160064) in observed
    assert (data, 67125251) in observed
    assert (tmp_path/'installer-state',71319558) in observed


def _write_public_payload(root: Path) -> None:
    (root / "EndpointAgent.msi").write_bytes(b"msi")
    (root / "EndpointAgent.release.json").write_text(json.dumps({
        "schema_version": "endpoint_windows_release_v1",
        "version": "1.0.0",
        "source_revision": "a" * 40,
        "product_code": "{11111111-1111-4111-8111-111111111111}",
        "initial_runtime_tree_sha256": "b" * 64,
        "package_sha256": hashlib.sha256(b"msi").hexdigest(),
    }), encoding="utf-8")
    (root / "Install-EndpointAgentCanary.ps1").write_text("# trusted wrapper fixture", encoding="utf-8")
    (root / "endpoint-ca.crt").write_text("public CA", encoding="ascii")
    (root / "setup-config.json").write_text(
        json.dumps(
            {
                "schema_version": "endpoint_windows_setup_config_v1",
                "endpoint_origin": "https://endpoint.sosnadmin.local",
                "installer_version": "1.0.0",
                "installer_release_id": "1.0.0",
            }
        ),
        encoding="utf-8",
    )


def _set_payload_version(root: Path, version: str) -> None:
    config_path = root / "setup-config.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["installer_version"] = version
    config_path.write_text(json.dumps(config), encoding="utf-8")
    manifest_path = root / "EndpointAgent.release.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["version"] = version
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")


def test_low_setup_disk_never_invokes_msi_or_stops_companions(tmp_path, monkeypatch):
    import shutil
    _write_public_payload(tmp_path)
    monkeypatch.setattr(setup_entry, "_resource_root", lambda: tmp_path)
    monkeypatch.setattr(setup_entry, "_data_root", lambda: tmp_path / "data")
    monkeypatch.setattr(setup_entry, "_diagnostics_root", lambda: tmp_path / "diagnostics")
    monkeypatch.setattr(setup_entry, "HttpsSetupTransport", lambda *_: object())
    monkeypatch.setattr(shutil, "disk_usage", lambda _: SimpleNamespace(free=0))
    def forbidden(*_):
        pytest.fail("MSI/service mutation before disk readiness")
    monkeypatch.setattr(setup_entry, "_install_embedded_msi", forbidden)
    monkeypatch.setattr(setup_entry, "_stop_tray_before_msi_update", forbidden)
    assert setup_entry.main(["--quiet"]) == setup_entry.EXIT_PREFLIGHT_FAILED
    result = json.loads((tmp_path / "diagnostics" / "install-result.json").read_text())
    assert result["status"] == "DISK_INSUFFICIENT"
    assert result["detail"] == "DISK_INSUFFICIENT"


def test_unknown_msi_accounting_never_stops_services_or_installs(tmp_path, monkeypatch):
    _write_public_payload(tmp_path)
    monkeypatch.setattr(setup_entry, "_resource_root", lambda: tmp_path)
    monkeypatch.setattr(setup_entry, "_data_root", lambda: tmp_path / "data")
    monkeypatch.setattr(setup_entry, "_diagnostics_root", lambda: tmp_path / "diagnostics")
    def unknown(_):
        raise setup_entry.SetupInstallError("MSI_COST_UNAVAILABLE")
    monkeypatch.setattr(setup_entry, "_msi_disk_costs", unknown)
    monkeypatch.setattr(setup_entry, "_install_embedded_msi", lambda _: pytest.fail("unknown cost must block MSI"))
    monkeypatch.setattr(setup_entry, "_stop_tray_before_msi_update", lambda: pytest.fail("unknown cost must block stop"))
    assert setup_entry.main(["--quiet"]) == setup_entry.EXIT_PREFLIGHT_FAILED
    result = json.loads((tmp_path / "diagnostics" / "install-result.json").read_text())
    assert result["detail"] == "MSI_COST_UNAVAILABLE"


def test_current_msi_rerun_needs_no_new_allocation_budget(tmp_path, monkeypatch):
    _write_public_payload(tmp_path)
    monkeypatch.setattr(setup_entry, "_resource_root", lambda: tmp_path)
    monkeypatch.setattr(setup_entry, "_data_root", lambda: tmp_path / "data")
    monkeypatch.setattr(setup_entry, "_diagnostics_root", lambda: tmp_path / "diagnostics")
    monkeypatch.setattr(setup_entry, "_classify_installation_state", lambda *_args, **_kwargs: "valid")
    monkeypatch.setattr(setup_entry, "_installed_msi_version", lambda: "1.0.0")
    monkeypatch.setattr(setup_entry, "_wait_for_agent_service_running", lambda: True)
    monkeypatch.setattr(setup_entry, "_require_setup_disk", lambda _: pytest.fail("current MSI allocates nothing"), raising=False)
    assert setup_entry.main(["--quiet"]) == setup_entry.EXIT_ALREADY_INSTALLED


@pytest.mark.parametrize("disk_full", [False, True])
def test_setup_disk_probe_os_error_is_bounded_before_any_mutation(tmp_path, monkeypatch, disk_full):
    import errno
    _write_public_payload(tmp_path)
    monkeypatch.setattr(setup_entry, "_resource_root", lambda: tmp_path)
    monkeypatch.setattr(setup_entry, "_data_root", lambda: tmp_path / "data")
    monkeypatch.setattr(setup_entry, "_diagnostics_root", lambda: tmp_path / "diagnostics")
    def unavailable(_):
        raise OSError(errno.ENOSPC if disk_full else errno.EACCES, "untrusted raw OS detail")
    monkeypatch.setattr(setup_entry, "_require_setup_disk", unavailable)
    monkeypatch.setattr(setup_entry, "_install_embedded_msi", lambda _: pytest.fail("probe failure must block MSI"))
    monkeypatch.setattr(setup_entry, "_stop_tray_before_msi_update", lambda: pytest.fail("probe failure must block stop"))
    assert setup_entry.main(["--quiet"]) == setup_entry.EXIT_PREFLIGHT_FAILED
    result = json.loads((tmp_path / "diagnostics" / "install-result.json").read_text())
    assert result["detail"] == ("DISK_INSUFFICIENT" if disk_full else "DISK_UNAVAILABLE")
    assert "untrusted" not in json.dumps(result)


def test_setup_entry_installs_embedded_msi_before_enrollment(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _write_public_payload(tmp_path)
    order: list[str] = []
    observed_config: list[object] = []

    monkeypatch.setattr(setup_entry, "_resource_root", lambda: tmp_path)
    monkeypatch.setattr(setup_entry, "_data_root", lambda: tmp_path / "agent-data")
    monkeypatch.setattr(
        setup_entry,
        "_install_embedded_msi",
        lambda path: order.append(path.name),
    )
    monkeypatch.setattr(
        setup_entry,
        "_installed_provisioner",
        lambda: tmp_path / "endpoint-agent-provision.exe",
    )
    monkeypatch.setattr(setup_entry, "HttpsSetupTransport", lambda *_: object())

    class _Setup:
        def __init__(self, config: object, **_: object) -> None:
            observed_config.append(config)
            self.installation_id_factory = lambda: "win-test"

        def run(self) -> SetupOutcome:
            order.append("enrollment")
            return SetupOutcome("provisioned")

    monkeypatch.setattr(setup_entry, "UniversalWindowsSetup", _Setup)

    assert setup_entry.main(["--quiet"]) == 0
    assert order == ["EndpointAgent.msi", "enrollment"]
    assert observed_config[0].endpoint_origin == "https://endpoint.sosnadmin.local"


def test_completed_native_install_resumes_original_enrollment_without_msi(tmp_path, monkeypatch):
    _write_public_payload(tmp_path)
    transaction = 'd5839dc6-fcf7-41f6-8603-5aca9dce1186'
    executable = tmp_path / 'endpoint-agent-provision.exe'
    monkeypatch.setattr(setup_entry, '_resource_root', lambda: tmp_path)
    monkeypatch.setattr(setup_entry, '_data_root', lambda: tmp_path / 'agent-data')
    monkeypatch.setattr(setup_entry, '_resume_unenrolled_installation', lambda *_: transaction, raising=False)
    monkeypatch.setattr(setup_entry, '_installed_provisioner', lambda: executable)
    monkeypatch.setattr(setup_entry, '_require_setup_disk', lambda _: pytest.fail('resume must not cost MSI'))
    monkeypatch.setattr(setup_entry, '_install_embedded_msi', lambda _: pytest.fail('resume must not replay MSI'))
    monkeypatch.setattr(setup_entry, 'HttpsSetupTransport', lambda *_: object())
    delivered = []

    class Setup:
        def __init__(self, _, *, provision_claim, **kwargs):
            self.provision_claim = provision_claim
            self.installation_id_factory = lambda: 'win-test'

        def run(self):
            assert self.installation_id_factory() == 'win-test'
            self.provision_claim('claim')
            return SetupOutcome('provisioned')

    def provision(path, config, data, installation_id, claim, *, native_transaction_id):
        delivered.append((path, installation_id, claim, native_transaction_id))

    monkeypatch.setattr(setup_entry, 'UniversalWindowsSetup', Setup)
    monkeypatch.setattr(setup_entry, '_run_provisioner', provision)
    assert setup_entry.main(['--quiet']) == 0
    assert delivered == [(executable, 'win-test', 'claim', transaction)]


def test_resume_without_installer_state_leaves_first_install_eligible(tmp_path, monkeypatch):
    from contextlib import nullcontext
    from pc_agent.platform.windows.installer_fence import state_root

    paths = setup_entry.WindowsUpdatePaths.production()
    assert not state_root(paths).exists()
    monkeypatch.setattr(setup_entry, 'update_transaction', lambda *_a, **_kw: nullcontext())
    monkeypatch.setattr(setup_entry, 'active_update_state', lambda _: None)
    assert setup_entry._resume_unenrolled_installation(tmp_path / 'EndpointAgent.msi', paths) is None
    assert not state_root(paths).exists()


@pytest.mark.parametrize('defect', [None, 'different-release', 'receipt', 'selection'])
def test_resume_requires_exact_pending_fact_and_settled_native_receipt(tmp_path, monkeypatch, defect):
    from contextlib import nullcontext
    from pc_agent.platform.windows import installation_lifecycle, installation_provenance as provenance
    from pc_agent.platform.windows import installer_fence, msi_inventory

    paths = setup_entry.WindowsUpdatePaths.production()
    transaction = 'd5839dc6-fcf7-41f6-8603-5aca9dce1186'
    digest = 'a' * 64
    product = '{44A74469-6221-459A-8946-8CCA6F214127}'
    release = {'package_sha256': digest}
    media = tmp_path / 'EndpointAgent.msi'
    media.with_name('EndpointAgent.release.json').write_text(json.dumps(release))
    identity = SimpleNamespace(source_revision='b' * 40, version='3.2.232')
    package = SimpleNamespace(sha256=digest, product_code=product,
                              package_code=product, version=identity.version)
    fact = {'transaction_id': transaction, 'native': {
        'msi_sha256': 'c' * 64 if defect == 'different-release' else digest,
        'product_code': product, 'source_revision': identity.source_revision,
        'version': identity.version, 'exit_code': 0,
    }}
    root = installer_fence.state_root(paths) / 'transactions' / transaction
    root.mkdir(parents=True)
    receipt = {
        'schema_version': 1, 'transaction_id': transaction, 'operation': 'install',
        'phase': 'reconciling' if defect == 'receipt' else 'complete',
        'package': {'sha256': digest, 'product_code': product, 'package_code': product,
                    'version': identity.version, 'source_revision': identity.source_revision},
        'selected': None, 'previous': None, 'startup_restored': True, 'sequence': 10,
        'service_states': {'EndpointAgent': 'absent', 'EndpointAgentUpdater': 'absent'},
        'service_startup': {'EndpointAgent': None, 'EndpointAgentUpdater': None}, 'helpers': [],
    }
    (root / 'completed.json').write_text(json.dumps(receipt))
    monkeypatch.setattr(setup_entry, 'update_transaction', lambda *_a, **_kw: nullcontext())
    monkeypatch.setattr(setup_entry, 'active_update_state', lambda _: None)
    monkeypatch.setattr(installation_lifecycle, 'outbox_for',
                        lambda _: SimpleNamespace(awaiting_enrollment=lambda: fact))
    monkeypatch.setattr(installer_fence, 'assert_state_security', lambda _: None)
    monkeypatch.setattr(msi_inventory, 'read_expected_package',
                        lambda *_: SimpleNamespace(package=package, identity=identity))
    monkeypatch.setattr(msi_inventory, 'verify_registered_cache', lambda *_: None)
    monkeypatch.setattr(msi_inventory, 'verify_installed', lambda *_: None)
    monkeypatch.setattr(provenance, 'verified_foundation_release', lambda _: release)
    monkeypatch.setattr(provenance, 'inspect_installed_core', lambda *_, **_kw: SimpleNamespace(
        current=SimpleNamespace(identity=identity, origin='zip' if defect == 'selection' else 'msi')))

    if defect in ('receipt', 'selection'):
        with pytest.raises(setup_entry.SetupInstallError) as error:
            setup_entry._resume_unenrolled_installation(media, paths)
        assert error.value.detail == 'PROVENANCE_CONFLICT'
    else:
        expected = None if defect == 'different-release' else transaction
        assert setup_entry._resume_unenrolled_installation(media, paths) == expected


@pytest.mark.parametrize("case", [
    "live", "denied", "wrong-pc", "wrong-origin", "existing", "unprotected", "reboot", "race", "short-claim", "bad-expiry",
])
def test_inventory_assignment_requires_exact_windows_claim_before_msi(tmp_path, monkeypatch, case):
    from datetime import UTC, datetime, timedelta

    _write_public_payload(tmp_path)
    config = tmp_path / "setup-config.json"
    if case != "wrong-origin":
        public = json.loads(config.read_text())
        public["endpoint_origin"] = "https://endpoint-staging.sosnadmin.local"
        config.write_text(json.dumps(public))
    data_root = tmp_path / "agent-data"
    assignment = tmp_path / "assignment.json"
    installation_id = "inventory-11111111-1111-4111-8111-111111111111-22222222-2222-4222-8222-222222222222-" + "a" * 32
    fingerprint = "sha256:" + "b" * 64
    assignment.write_text(json.dumps({
        "schema_version": "endpoint_windows_inventory_assignment_v1",
        "installation_id": installation_id,
        "hardware_fingerprint": fingerprint,
    }))
    order = []
    request_id = "33333333-3333-4333-8333-333333333333"

    class Transport:
        def create_request(self, body):
            assert body["installation_id"] == installation_id
            assert body["hardware_fingerprint"] == fingerprint and body["platform"] == "windows"
            order.append("request")
            return {"request_id": request_id, "status": "denied" if case == "denied" else "auto_approved"}

        def request_claim(self, _request_id, proof):
            assert proof["installation_id"] == installation_id and proof["hardware_fingerprint"] == fingerprint
            order.append("claim")
            expires = datetime.now(UTC) + timedelta(minutes=1 if case == "short-claim" else 14)
            return {"claim": "ic_test", "expires_at": "invalid" if case == "bad-expiry" else expires.isoformat()}

        def request_verification(self, _request_id, _capability):
            order.append("heartbeat")
            return {"status": "completed"}

    def check_acl(_self, path):
        assert path == assignment
        if case == "unprotected":
            raise setup_entry.WindowsAclError("fixture private error")

    monkeypatch.setattr(setup_entry.PyWin32AclAdapter, "assert_inventory_assignment_file", check_acl)
    monkeypatch.setattr(setup_entry, "_resource_root", lambda: tmp_path)
    monkeypatch.setattr(setup_entry, "_data_root", lambda: data_root)
    monkeypatch.setattr(setup_entry, "_agent_service_installed", lambda: False)
    monkeypatch.setattr("pc_agent.platform.windows.msi_inventory.NativeMsi", lambda: SimpleNamespace(related_products=lambda _: ()))
    monkeypatch.setattr(setup_entry, "_classify_installation_state", lambda *_a, **_kw: "valid" if case == "existing" else "clean")
    def derive(probe):
        assert probe is setup_entry.collect_windows_inventory_fingerprint
        return "sha256:" + "c" * 64 if case == "wrong-pc" else fingerprint

    monkeypatch.setattr(setup_entry, "_derive_hardware_fingerprint", derive)
    def native_install(_path, *, inventory_fresh_only):
        assert inventory_fresh_only
        order.append("msi")
        if case == "race":
            raise setup_entry.SetupInstallError("INVENTORY_ASSIGNMENT_INELIGIBLE")
        return 3010 if case == "reboot" else 0
    monkeypatch.setattr(setup_entry, "_install_embedded_msi", native_install)
    monkeypatch.setattr(setup_entry, "_installed_provisioner", lambda: tmp_path / "provision.exe")
    monkeypatch.setattr(setup_entry, "_wait_for_agent_service_running", lambda: True)
    def make_transport(*_args, allow_redirects):
        assert allow_redirects is False
        return Transport()
    monkeypatch.setattr(setup_entry, "HttpsSetupTransport", make_transport)
    monkeypatch.setattr(setup_entry, "_run_provisioner", lambda *a, **kw: order.append("provision"))

    result = setup_entry.main(["--quiet", "--inventory-assignment-file", str(assignment)])
    assert result == {"live": 0, "denied": 30, "reboot": 3010, "short-claim": 40, "bad-expiry": 40}.get(case, 20)
    assert order == {
        "live": ["request", "claim", "msi", "provision", "heartbeat"],
        "denied": ["request"],
        "reboot": ["request", "claim", "msi"],
        "race": ["request", "claim", "msi"],
        "short-claim": ["request", "claim"],
        "bad-expiry": ["request", "claim"],
    }.get(case, [])
    for log in (tmp_path / "diagnostics").glob("*"):
        assert installation_id not in log.read_text() and fingerprint not in log.read_text()


@pytest.mark.parametrize("staging", [True, False])
def test_signed_setup_inventory_probe_is_read_only_and_staging_scoped(tmp_path, monkeypatch, capsys, staging):
    _write_public_payload(tmp_path)
    path = tmp_path / "setup-config.json"
    config = json.loads(path.read_text())
    if staging:
        config["endpoint_origin"] = "https://endpoint-staging.sosnadmin.local"
        path.write_text(json.dumps(config))
    fingerprint = "sha256:" + "b" * 64
    monkeypatch.setattr(setup_entry, "_resource_root", lambda: tmp_path)
    def derive(probe):
        assert probe is setup_entry.collect_windows_inventory_fingerprint
        return fingerprint

    monkeypatch.setattr(setup_entry, "_derive_hardware_fingerprint", derive)
    monkeypatch.setattr(setup_entry, "_data_root", lambda: pytest.fail("installer state accessed during probe"))
    assert setup_entry.main(["--inventory-fingerprint"]) == (0 if staging else 20)
    output = capsys.readouterr().out
    assert (json.loads(output) if output else None) == ({"hardware_fingerprint": fingerprint} if staging else None)


@pytest.mark.skipif(os.name != "nt", reason="native Windows ACL")
def test_inventory_file_acl_uses_only_builtin_admin_and_system_sids(tmp_path, monkeypatch):
    import ctypes
    from pc_agent.platform.windows.inventory_setup import read_assignment

    if not ctypes.windll.shell32.IsUserAnAdmin():
        pytest.skip("setting the builtin Administrators owner requires elevation")
    security = pytest.importorskip("win32security")
    assignment = tmp_path / "assignment.json"
    installation_id = "inventory-11111111-1111-4111-8111-111111111111-22222222-2222-4222-8222-222222222222-" + "a" * 32
    fingerprint = "sha256:" + "b" * 64
    assignment.write_text(json.dumps({
        "schema_version": "endpoint_windows_inventory_assignment_v1",
        "installation_id": installation_id,
        "hardware_fingerprint": fingerprint,
    }))
    monkeypatch.setattr(security, "LookupAccountName", lambda *_: pytest.fail("uninstalled service SID lookup"))

    def set_acl(extra=""):
        descriptor = security.ConvertStringSecurityDescriptorToSecurityDescriptor(
            "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)" + extra, 1,
        )
        security.SetNamedSecurityInfo(
            str(assignment), security.SE_FILE_OBJECT,
            security.OWNER_SECURITY_INFORMATION | security.DACL_SECURITY_INFORMATION | security.PROTECTED_DACL_SECURITY_INFORMATION,
            descriptor.GetSecurityDescriptorOwner(), None, descriptor.GetSecurityDescriptorDacl(), None,
        )

    set_acl()
    assert read_assignment(assignment) == (installation_id, fingerprint)
    set_acl("(A;;FR;;;BU)")
    with pytest.raises(setup_entry.WindowsAclError):
        read_assignment(assignment)


def test_inventory_provisioner_handoff_keeps_assignment_and_claim_in_stdin(tmp_path, monkeypatch):
    installation_id = "inventory-11111111-1111-4111-8111-111111111111-22222222-2222-4222-8222-222222222222-" + "a" * 32
    config = SetupConfig("https://endpoint-staging.sosnadmin.local", tmp_path / "ca", "1.0.0", "1.0.0")
    calls = []
    def run(command, **kwargs):
        calls.append((command, kwargs["input"]))
        return SimpleNamespace(returncode=0, stdout="", stderr="")
    setup_entry._run_provisioner(tmp_path / "provision.exe", config, tmp_path, installation_id, "ic_test", run=run)
    command, material = calls[0]
    assert "--inventory-stdin" in command and "--installation-id" not in command
    assert installation_id not in command and "ic_test" not in command
    assert json.loads(material) == {"installation_id": installation_id, "claim": "ic_test"}


@pytest.mark.skipif(os.name != "nt", reason="Win32 inherited handles")
def test_windowed_installer_inherited_pipe_handles_roundtrip():
    import subprocess
    import sys

    result = subprocess.run(
        [sys.executable, "-c",
         "from pc_agent.platform.windows import installer_stdio as s; "
         "s.write_inherited_pipe(s.read_inherited_pipe(30).encode('ascii'))"],
        input=b"fixture-only",
        capture_output=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == b"fixture-only"


def test_setup_entry_records_started_before_installing_embedded_msi(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _write_public_payload(tmp_path)
    data_root = tmp_path / "agent-data"
    monkeypatch.setattr(setup_entry, "_resource_root", lambda: tmp_path)
    monkeypatch.setattr(setup_entry, "_data_root", lambda: data_root)

    def assert_started_before_msi(_: Path) -> None:
        contents = (tmp_path / "diagnostics" / "install.log").read_text(encoding="utf-8")
        assert "status=STARTED" in contents

    monkeypatch.setattr(setup_entry, "_install_embedded_msi", assert_started_before_msi)
    monkeypatch.setattr(
        setup_entry,
        "_installed_provisioner",
        lambda: tmp_path / "endpoint-agent-provision.exe",
    )
    monkeypatch.setattr(setup_entry, "HttpsSetupTransport", lambda *_: object())

    class _Setup:
        def __init__(self, _config: object, **_: object) -> None:
            self.installation_id_factory = lambda: "win-test"

        def run(self) -> SetupOutcome:
            return SetupOutcome("provisioned")

    monkeypatch.setattr(setup_entry, "UniversalWindowsSetup", _Setup)

    assert setup_entry.main(["--quiet"]) == 0


def test_setup_entry_requires_a_running_service_before_reporting_success(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A provisioner return alone must never become a false completed result."""
    _write_public_payload(tmp_path)
    data_root = tmp_path / "agent-data"
    diagnostics_root = tmp_path / "installer-diagnostics"
    monkeypatch.setattr(setup_entry, "_resource_root", lambda: tmp_path)
    monkeypatch.setattr(setup_entry, "_data_root", lambda: data_root)
    monkeypatch.setattr(
        setup_entry, "_diagnostics_root", lambda: diagnostics_root, raising=False
    )
    monkeypatch.setattr(setup_entry, "_install_embedded_msi", lambda _: None)
    monkeypatch.setattr(
        setup_entry,
        "_installed_provisioner",
        lambda: tmp_path / "endpoint-agent-provision.exe",
    )
    monkeypatch.setattr(setup_entry, "HttpsSetupTransport", lambda *_: object())
    monkeypatch.setattr(
        setup_entry,
        "_wait_for_agent_service_running",
        lambda: False,
        raising=False,
    )

    class _Setup:
        def __init__(self, _config: object, **_: object) -> None:
            self.installation_id_factory = lambda: "win-test"

        def run(self) -> SetupOutcome:
            return SetupOutcome("provisioned")

    monkeypatch.setattr(setup_entry, "UniversalWindowsSetup", _Setup)

    assert setup_entry.main(["--quiet"]) == setup_entry.EXIT_SERVICE_FAILED
    result = json.loads(
        (diagnostics_root / "install-result.json").read_text(encoding="utf-8")
    )
    assert result["status"] == "SERVICE_FAILED"
    assert result["detail"] == "SERVICE_NOT_RUNNING"
    assert result["stage"] == "SERVICE"


def test_setup_entry_writes_safe_public_result_for_msi_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """An MSI error must leave an operator-readable class without raw exception text."""
    _write_public_payload(tmp_path)
    diagnostics_root = tmp_path / "installer-diagnostics"
    monkeypatch.setattr(setup_entry, "_resource_root", lambda: tmp_path)
    monkeypatch.setattr(setup_entry, "_data_root", lambda: tmp_path / "agent-data")
    monkeypatch.setattr(
        setup_entry, "_diagnostics_root", lambda: diagnostics_root, raising=False
    )
    monkeypatch.setattr(
        setup_entry,
        "_install_embedded_msi",
        lambda _: (_ for _ in ()).throw(RuntimeError("msi error C:/secret/path")),
    )
    monkeypatch.setattr(setup_entry, "HttpsSetupTransport", lambda *_: object())

    assert setup_entry.main(["--quiet"]) == setup_entry.EXIT_INSTALL_FAILED
    result = json.loads(
        (diagnostics_root / "install-result.json").read_text(encoding="utf-8")
    )
    assert result["status"] == "INSTALL_FAILED"
    assert result["detail"] == "MSI_INSTALL_FAILED"
    assert "secret" not in (diagnostics_root / "install-result.json").read_text(
        encoding="utf-8"
    )


def test_result_write_preserves_installer_outcome_when_diagnostics_acl_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A DACL error must not replace the actual, stable installer result code."""
    monkeypatch.setattr(
        setup_entry,
        "_prepare_diagnostics_root",
        lambda: (_ for _ in ()).throw(OSError("diagnostics ACL failed")),
        raising=False,
    )

    assert (
        setup_entry._finish(
            tmp_path,
            status="INSTALL_FAILED",
            code=setup_entry.EXIT_INSTALL_FAILED,
            stage="MSI",
            detail="MSI_INSTALL_FAILED",
        )
        == setup_entry.EXIT_INSTALL_FAILED
    )


@pytest.mark.parametrize("recover_failed_core", [False, True])
def test_embedded_msi_installation_is_silent_and_windowless(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, recover_failed_core: bool,
) -> None:
    """Removing quiet MSI flags or child window suppression would reintroduce UI flashes."""
    _write_public_payload(tmp_path)
    msi_path = tmp_path / "EndpointAgent.msi"
    captured: dict[str, object] = {}

    def fake_run(*args: object, **kwargs: object) -> SimpleNamespace:
        captured["args"] = args
        captured["kwargs"] = kwargs
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(setup_entry.subprocess, "run", fake_run)
    monkeypatch.setattr(
        setup_entry, "_windowless_creation_flags", lambda: 4242, raising=False
    )

    setup_entry._install_embedded_msi(msi_path, recover_failed_core=recover_failed_core)

    assert "-WindowStyle" in captured["args"][0]
    assert "Hidden" in captured["args"][0]
    assert ("-RecoverFailedCore" in captured["args"][0]) is recover_failed_core
    assert "-Operation" not in captured["args"][0]
    assert captured["kwargs"]["creationflags"] == 4242


def test_provisioner_is_started_without_a_console_window(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A console-capable provisioner must inherit an explicit no-window flag."""
    captured: dict[str, object] = {}

    def fake_run(*args: object, **kwargs: object) -> SimpleNamespace:
        captured["kwargs"] = kwargs
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(
        setup_entry, "_windowless_creation_flags", lambda: 4242, raising=False
    )
    setup_entry._run_provisioner(
        tmp_path / "endpoint-agent-provision.exe",
        SetupConfig(
            endpoint_origin="https://endpoint.sosnadmin.local",
            ca_file=tmp_path / "endpoint-ca.crt",
            installer_version="1.0.0",
            installer_release_id="1.0.0",
        ),
        tmp_path / "agent-data",
        "win-test",
        "ic_safe-claim",
        run=fake_run,
    )

    assert captured["kwargs"]["creationflags"] == 4242


def test_normal_installation_displays_a_concrete_success_result(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A non-quiet successful install must report its verified result to the user."""
    _write_public_payload(tmp_path)
    displayed: list[tuple[str, int, str]] = []
    monkeypatch.setattr(setup_entry, "_resource_root", lambda: tmp_path)
    monkeypatch.setattr(setup_entry, "_data_root", lambda: tmp_path / "agent-data")
    monkeypatch.setattr(
        setup_entry,
        "_diagnostics_root",
        lambda: tmp_path / "installer-diagnostics",
        raising=False,
    )
    monkeypatch.setattr(setup_entry, "_install_embedded_msi", lambda _: None)
    monkeypatch.setattr(
        setup_entry,
        "_installed_provisioner",
        lambda: tmp_path / "endpoint-agent-provision.exe",
    )
    monkeypatch.setattr(setup_entry, "HttpsSetupTransport", lambda *_: object())
    monkeypatch.setattr(
        setup_entry,
        "_wait_for_agent_service_running",
        lambda: True,
        raising=False,
    )
    monkeypatch.setattr(
        setup_entry,
        "_show_result_dialog",
        lambda status, code, detail: displayed.append((status, code, detail)),
        raising=False,
    )

    class _Setup:
        def __init__(self, _config: object, **_: object) -> None:
            self.installation_id_factory = lambda: "win-test"

        def run(self) -> SetupOutcome:
            return SetupOutcome("provisioned")

    monkeypatch.setattr(setup_entry, "UniversalWindowsSetup", _Setup)

    assert setup_entry.main([]) == setup_entry.EXIT_SUCCESS
    assert displayed == [("COMPLETED", 0, "SERVICE_RUNNING")]


def test_successful_interactive_update_restarts_both_user_companions(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """An interactive update restores both companions stopped by the MSI."""
    (tmp_path / "enrollment-identity.json").write_text(
        '{"device_id":"550e8400-e29b-41d4-a716-446655440000","schema_version":"endpoint_enrollment_identity_v1"}',
        encoding="ascii",
    )
    (tmp_path / "device-credential").write_text("a" * 43, encoding="ascii")
    resources = tmp_path / "payload"
    resources.mkdir()
    _write_public_payload(resources)
    _set_payload_version(resources, "3.2.56")
    started: list[object] = []

    monkeypatch.setattr(setup_entry, "_data_root", lambda: tmp_path)
    monkeypatch.setattr(setup_entry, "_resource_root", lambda: resources)
    monkeypatch.setattr(setup_entry, "_installed_msi_version", lambda: "3.2.55")
    monkeypatch.setattr(setup_entry, "_install_embedded_msi", lambda _path: None)
    monkeypatch.setattr(setup_entry, "_wait_for_agent_service_running", lambda: True)
    monkeypatch.setattr(setup_entry, "_is_interactive_windows_session", lambda: True)
    monkeypatch.setattr(
        setup_entry, "_restart_tray_companion", lambda: started.append("tray") or True
    )
    monkeypatch.setattr(
        setup_entry, "_restart_user_sensor_companion", lambda: started.append("sensor") or True
    )

    assert setup_entry.main(["--quiet"]) == setup_entry.EXIT_SUCCESS
    assert started == ["tray", "sensor"]


def test_interactive_update_reports_user_sensor_start_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(setup_entry, "_is_interactive_windows_session", lambda: True)
    monkeypatch.setattr(setup_entry, "_restart_tray_companion", lambda: True)
    monkeypatch.setattr(setup_entry, "_restart_user_sensor_companion", lambda: False)

    assert setup_entry._service_ready_detail() == "SERVICE_RUNNING_USER_SENSOR_START_FAILED"


def test_successful_system_update_does_not_start_an_invisible_tray(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """SYSTEM/session-0 updates leave tray launch to the interactive user session."""
    monkeypatch.setattr(setup_entry.os, "name", "nt")
    monkeypatch.setenv("SESSIONNAME", "Services")
    monkeypatch.setenv("USERNAME", "SYSTEM")
    monkeypatch.setattr(
        setup_entry,
        "_installed_tray_companion",
        lambda: tmp_path / "EndpointAgentTray.exe",
    )
    monkeypatch.setattr(
        setup_entry.subprocess,
        "Popen",
        lambda *_args, **_kwargs: pytest.fail("session-0 must not start a tray UI"),
    )

    assert setup_entry._restart_tray_companion() is False
    assert setup_entry._restart_user_sensor_companion() is False


def test_interactive_session_detection_uses_windows_session_id_when_env_is_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A normal desktop launch does not require terminal-only SESSIONNAME."""
    monkeypatch.setattr(setup_entry.os, "name", "nt")
    monkeypatch.delenv("SESSIONNAME", raising=False)
    monkeypatch.setenv("USERNAME", "operator")
    monkeypatch.setattr(setup_entry, "_current_process_session_id", lambda: 1)

    assert setup_entry._is_interactive_windows_session() is True


def test_session_zero_never_starts_the_tray_when_env_is_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A SYSTEM-like session remains non-interactive even without its env label."""
    monkeypatch.setattr(setup_entry.os, "name", "nt")
    monkeypatch.delenv("SESSIONNAME", raising=False)
    monkeypatch.setenv("USERNAME", "operator")
    monkeypatch.setattr(setup_entry, "_current_process_session_id", lambda: 0)

    assert setup_entry._is_interactive_windows_session() is False


def test_setup_entry_rejects_config_that_contains_extra_material(
    tmp_path: Path,
) -> None:
    _write_public_payload(tmp_path)
    (tmp_path / "setup-config.json").write_text(
        json.dumps(
            {
                "schema_version": "endpoint_windows_setup_config_v1",
                "endpoint_origin": "https://endpoint.sosnadmin.local",
                "installer_version": "1.0.0",
                "installer_release_id": "1.0.0",
                "unexpected": "not allowed",
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="configuration is invalid"):
        setup_entry._read_public_setup_config(tmp_path / "setup-config.json")


def test_setup_state_classifies_a_valid_identity_and_credential(tmp_path: Path) -> None:
    identity = tmp_path / "enrollment-identity.json"
    credential = tmp_path / "device-credential"
    identity.write_text(
        '{"device_id":"550e8400-e29b-41d4-a716-446655440000","schema_version":"endpoint_enrollment_identity_v1"}',
        encoding="ascii",
    )
    credential.write_text("a" * 43, encoding="ascii")

    assert setup_entry._classify_installation_state(tmp_path) == "valid"


def test_setup_state_fails_closed_for_incomplete_enrollment_material(
    tmp_path: Path,
) -> None:
    (tmp_path / "device-credential").write_text("a" * 43, encoding="ascii")

    assert setup_entry._classify_installation_state(tmp_path) == "conflicted"


def test_setup_state_marks_valid_identity_without_service_repairable(
    tmp_path: Path,
) -> None:
    (tmp_path / "enrollment-identity.json").write_text(
        '{"device_id":"550e8400-e29b-41d4-a716-446655440000","schema_version":"endpoint_enrollment_identity_v1"}',
        encoding="ascii",
    )
    (tmp_path / "device-credential").write_text("a" * 43, encoding="ascii")

    assert (
        setup_entry._classify_installation_state(tmp_path, service_installed=False)
        == "repairable"
    )


@pytest.mark.parametrize(
    ("outcome", "expected"),
    [
        (SetupOutcome("denied", reason="POLICY_DENIED"), 30),
        (SetupOutcome("timed_out", reason="WAITING_APPROVAL"), 31),
        (SetupOutcome("review_required", reason="DUPLICATE_IDENTITY"), 32),
        (SetupOutcome("expired", reason="REQUEST_EXPIRED"), 33),
    ],
)
def test_setup_entry_maps_terminal_request_outcomes_to_stable_exit_codes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    outcome: SetupOutcome,
    expected: int,
) -> None:
    _write_public_payload(tmp_path)
    monkeypatch.setattr(setup_entry, "_resource_root", lambda: tmp_path)
    monkeypatch.setattr(setup_entry, "_data_root", lambda: tmp_path / "agent-data")
    monkeypatch.setattr(setup_entry, "_install_embedded_msi", lambda _: None)
    monkeypatch.setattr(
        setup_entry,
        "_installed_provisioner",
        lambda: tmp_path / "endpoint-agent-provision.exe",
    )
    monkeypatch.setattr(setup_entry, "HttpsSetupTransport", lambda *_: object())

    class _Setup:
        def __init__(self, _config: object, **_: object) -> None:
            self.installation_id_factory = lambda: "win-test"

        def run(self) -> SetupOutcome:
            return outcome

    monkeypatch.setattr(setup_entry, "UniversalWindowsSetup", _Setup)

    assert setup_entry.main(["--quiet"]) == expected


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (SetupClaimError("claim handoff failed"), setup_entry.EXIT_CLAIM_FAILED),
        (
            SetupProvisionError("provisioning failed"),
            setup_entry.EXIT_PROVISIONING_FAILED,
        ),
    ],
)
def test_setup_entry_distinguishes_claim_and_provisioning_failures(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    error: RuntimeError,
    expected: int,
) -> None:
    _write_public_payload(tmp_path)
    monkeypatch.setattr(setup_entry, "_resource_root", lambda: tmp_path)
    monkeypatch.setattr(setup_entry, "_data_root", lambda: tmp_path / "agent-data")
    monkeypatch.setattr(setup_entry, "_install_embedded_msi", lambda _: None)
    monkeypatch.setattr(
        setup_entry,
        "_installed_provisioner",
        lambda: tmp_path / "endpoint-agent-provision.exe",
    )
    monkeypatch.setattr(setup_entry, "HttpsSetupTransport", lambda *_: object())

    class _Setup:
        def __init__(self, _config: object, **_: object) -> None:
            self.installation_id_factory = lambda: "win-test"

        def run(self) -> SetupOutcome:
            raise error

    monkeypatch.setattr(setup_entry, "UniversalWindowsSetup", _Setup)

    assert setup_entry.main(["--quiet"]) == expected


def test_setup_entry_logs_safe_provisioner_failure_detail(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _write_public_payload(tmp_path)
    data_root = tmp_path / "agent-data"
    monkeypatch.setattr(setup_entry, "_resource_root", lambda: tmp_path)
    monkeypatch.setattr(setup_entry, "_data_root", lambda: data_root)
    monkeypatch.setattr(setup_entry, "_install_embedded_msi", lambda _: None)
    monkeypatch.setattr(
        setup_entry,
        "_installed_provisioner",
        lambda: tmp_path / "endpoint-agent-provision.exe",
    )
    monkeypatch.setattr(setup_entry, "HttpsSetupTransport", lambda *_: object())

    class _Setup:
        def __init__(self, _config: object, **_: object) -> None:
            self.installation_id_factory = lambda: "win-test"

        def run(self) -> SetupOutcome:
            raise SetupProvisionError(
                "Windows provisioning failed", detail="PROVISIONER_WINDOWSACLERROR"
            )

    monkeypatch.setattr(setup_entry, "UniversalWindowsSetup", _Setup)

    assert setup_entry.main(["--quiet"]) == setup_entry.EXIT_PROVISIONING_FAILED
    assert "detail=PROVISIONER_WINDOWSACLERROR" in (
        tmp_path / "diagnostics" / "install.log"
    ).read_text(encoding="utf-8")


def test_provisioner_failure_maps_only_its_safe_class_name(
    tmp_path: Path,
) -> None:
    with pytest.raises(SetupProvisionError) as raised:
        setup_entry._run_provisioner(
            tmp_path / "endpoint-agent-provision.exe",
            SetupConfig(
                endpoint_origin="https://endpoint.sosnadmin.local",
                ca_file=tmp_path / "endpoint-ca.crt",
                installer_version="1.0.0",
                installer_release_id="1.0.0",
            ),
            tmp_path / "agent-data",
            "win-test",
            "ic_safe-claim",
            run=lambda *_args, **_kwargs: SimpleNamespace(
                returncode=1,
                stdout="",
                stderr="Windows provisioning failed: WindowsAclError\nC:/secret/path\n",
            ),
        )

    assert raised.value.detail == "PROVISIONER_WINDOWSACLERROR"
    assert "secret" not in raised.value.detail


def test_provisioner_start_failure_is_logged_without_os_error_text(
    tmp_path: Path,
) -> None:
    def fail_to_start(*_args: object, **_kwargs: object) -> object:
        raise OSError("C:/secret/path")

    with pytest.raises(SetupProvisionError) as raised:
        setup_entry._run_provisioner(
            tmp_path / "endpoint-agent-provision.exe",
            SetupConfig(
                endpoint_origin="https://endpoint.sosnadmin.local",
                ca_file=tmp_path / "endpoint-ca.crt",
                installer_version="1.0.0",
                installer_release_id="1.0.0",
            ),
            tmp_path / "agent-data",
            "win-test",
            "ic_safe-claim",
            run=fail_to_start,
        )

    assert raised.value.detail == "PROVISIONER_START_FAILED"
    assert "secret" not in raised.value.detail


def test_install_log_never_persists_secret_detail(tmp_path: Path) -> None:
    log_path = tmp_path / "install.log"
    setup_entry._write_install_log(
        log_path,
        step="ENROLLMENT",
        status="DENIED",
        code=30,
        detail="POLICY_DENIED",
    )

    contents = log_path.read_text(encoding="utf-8")
    assert "POLICY_DENIED" in contents
    assert "ic_" not in contents
    assert "device_token" not in contents


def test_setup_status_before_msi_does_not_create_unowned_agent_data(tmp_path, monkeypatch):
    data_root = tmp_path / "not-yet-installed" / "Agent"
    results = []
    monkeypatch.setattr(setup_entry, "_write_install_result", lambda **fields: results.append(fields))

    assert setup_entry._finish(
        data_root, status="STARTED", code=0, stage="MSI", detail="STARTED"
    ) == 0

    assert not data_root.exists()
    assert results == [{"status": "STARTED", "code": 0, "stage": "MSI", "detail": "STARTED"}]


def test_failed_fresh_setup_and_retry_do_not_contaminate_agent_data(tmp_path, monkeypatch):
    data_root = tmp_path / "fresh-agent"
    data_root.mkdir()
    diagnostics = tmp_path / "installer-diagnostics"
    monkeypatch.setattr(setup_entry, "_diagnostics_root", lambda: diagnostics)
    for status, code in [("INSTALL_FAILED", 21), ("STARTED", 0)]:
        assert setup_entry._finish(data_root, status=status, code=code,
                                   stage="MSI", detail="MSI_EVIDENCE_FAILED") == code
        assert list(data_root.iterdir()) == []
    contents = (diagnostics / "install.log").read_text(encoding="utf-8")
    assert "status=INSTALL_FAILED" in contents
    assert "status=STARTED" in contents


def test_rejected_diagnostics_directory_never_receives_a_log(tmp_path, monkeypatch):
    diagnostics = tmp_path / "untrusted-diagnostics"
    diagnostics.mkdir()
    monkeypatch.setattr(setup_entry, "_diagnostics_root", lambda: diagnostics)
    monkeypatch.setattr(setup_entry, "_prepare_diagnostics_root",
                        lambda: (_ for _ in ()).throw(OSError("untrusted directory")))
    assert setup_entry._finish(tmp_path, status="INSTALL_FAILED", code=21) == 21
    assert list(diagnostics.iterdir()) == []


def test_diagnostics_log_rejects_hardlinked_leaf(tmp_path, monkeypatch):
    import os
    diagnostics = tmp_path / "diagnostics"
    diagnostics.mkdir()
    outside = tmp_path / "unrelated-file"
    outside.write_bytes(b"unchanged")
    os.link(outside, diagnostics / "install.log")
    monkeypatch.setattr(setup_entry, "_diagnostics_root", lambda: diagnostics)
    assert setup_entry._finish(tmp_path, status="INSTALL_FAILED", code=21) == 21
    assert outside.read_bytes() == b"unchanged"


@pytest.mark.skipif(os.name != 'nt', reason="native NTFS junction")
def test_rejected_diagnostics_junction_does_not_redirect_log(tmp_path, monkeypatch):
    import _winapi
    outside = tmp_path / "outside"
    outside.mkdir()
    diagnostics = tmp_path / "diagnostics-junction"
    _winapi.CreateJunction(str(outside), str(diagnostics))
    monkeypatch.setattr(setup_entry, "_diagnostics_root", lambda: diagnostics)
    try:
        assert setup_entry._finish(tmp_path, status="INSTALL_FAILED", code=21) == 21
        assert list(outside.iterdir()) == []
    finally:
        diagnostics.rmdir()


def test_valid_rerun_stops_before_msi_or_enrollment(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    (tmp_path / "enrollment-identity.json").write_text(
        '{"device_id":"550e8400-e29b-41d4-a716-446655440000","schema_version":"endpoint_enrollment_identity_v1"}',
        encoding="ascii",
    )
    (tmp_path / "device-credential").write_text("a" * 43, encoding="ascii")
    monkeypatch.setattr(setup_entry, "_data_root", lambda: tmp_path)
    resources = tmp_path / "payload"
    resources.mkdir()
    _write_public_payload(resources)
    monkeypatch.setattr(setup_entry, "_resource_root", lambda: resources)
    monkeypatch.setattr(setup_entry, "_installed_msi_version", lambda: "1.0.0")
    monkeypatch.setattr(
        setup_entry,
        "_install_embedded_msi",
        lambda _path: pytest.fail("equal installer must not invoke MSI"),
    )

    assert setup_entry.main(["--quiet"]) == 10


def test_valid_existing_agent_installs_a_strictly_newer_embedded_msi(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Removing the valid-state upgrade branch would strand deployed agents."""
    (tmp_path / "enrollment-identity.json").write_text(
        '{"device_id":"550e8400-e29b-41d4-a716-446655440000","schema_version":"endpoint_enrollment_identity_v1"}',
        encoding="ascii",
    )
    (tmp_path / "device-credential").write_text("a" * 43, encoding="ascii")
    resources = tmp_path / "payload"
    resources.mkdir()
    _write_public_payload(resources)
    _set_payload_version(resources, "3.2.49")
    calls: list[str] = []
    monkeypatch.setattr(setup_entry, "_data_root", lambda: tmp_path)
    monkeypatch.setattr(setup_entry, "_resource_root", lambda: resources)
    monkeypatch.setattr(
        setup_entry, "_installed_msi_version", lambda: "3.2.47", raising=False
    )
    monkeypatch.setattr(
        setup_entry, "_install_embedded_msi", lambda path: calls.append(path.name)
    )
    monkeypatch.setattr(setup_entry, "_wait_for_agent_service_running", lambda: True)
    monkeypatch.setattr(
        setup_entry,
        "UniversalWindowsSetup",
        lambda *_args, **_kwargs: pytest.fail("an update must not re-enroll"),
    )

    assert setup_entry.main(["--quiet"]) == setup_entry.EXIT_SUCCESS
    assert calls == ["EndpointAgent.msi"]


def test_valid_existing_agent_delegates_tray_stop_to_locked_wrapper(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The Setup payload is newer than the MSI-installed helper during an upgrade."""
    (tmp_path / "enrollment-identity.json").write_text(
        '{"device_id":"550e8400-e29b-41d4-a716-446655440000","schema_version":"endpoint_enrollment_identity_v1"}',
        encoding="ascii",
    )
    (tmp_path / "device-credential").write_text("a" * 43, encoding="ascii")
    resources = tmp_path / "payload"
    resources.mkdir()
    _write_public_payload(resources)
    _set_payload_version(resources, "3.2.62")
    order: list[str] = []
    monkeypatch.setattr(setup_entry, "_data_root", lambda: tmp_path)
    monkeypatch.setattr(setup_entry, "_resource_root", lambda: resources)
    monkeypatch.setattr(setup_entry, "_installed_msi_version", lambda: "3.2.59")
    monkeypatch.setattr(setup_entry, "_stop_tray_before_msi_update", lambda: order.append("tray"))
    monkeypatch.setattr(setup_entry, "_install_embedded_msi", lambda _: order.append("msi"))
    monkeypatch.setattr(setup_entry, "_wait_for_agent_service_running", lambda: True)

    assert setup_entry.main(["--quiet"]) == setup_entry.EXIT_SUCCESS
    assert order == ["msi"]  # Wrapper owns tray/service stop under the transaction.


def test_valid_existing_agent_does_not_install_an_equal_embedded_msi(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """An equal package is an idempotent rerun, never an MSI churn event."""
    (tmp_path / "enrollment-identity.json").write_text(
        '{"device_id":"550e8400-e29b-41d4-a716-446655440000","schema_version":"endpoint_enrollment_identity_v1"}',
        encoding="ascii",
    )
    (tmp_path / "device-credential").write_text("a" * 43, encoding="ascii")
    resources = tmp_path / "payload"
    resources.mkdir()
    _write_public_payload(resources)
    calls: list[str] = []
    monkeypatch.setattr(setup_entry, "_data_root", lambda: tmp_path)
    monkeypatch.setattr(setup_entry, "_resource_root", lambda: resources)
    monkeypatch.setattr(
        setup_entry, "_installed_msi_version", lambda: "1.0.0", raising=False
    )
    monkeypatch.setattr(
        setup_entry, "_install_embedded_msi", lambda _path: calls.append("msi")
    )

    assert setup_entry.main(["--quiet"]) == setup_entry.EXIT_ALREADY_INSTALLED
    assert calls == []


def test_equal_version_missing_runtime_feature_still_runs_canonical_msi(monkeypatch,tmp_path):
    _write_public_payload(tmp_path)
    monkeypatch.setattr(setup_entry,'_data_root',lambda:tmp_path/'data')
    monkeypatch.setattr(setup_entry,'_resource_root',lambda:tmp_path)
    monkeypatch.setattr(setup_entry,'_classify_installation_state',lambda *_a,**_kw:'valid')
    monkeypatch.setattr(setup_entry,'_installed_msi_version',lambda:'1.0.0')
    monkeypatch.setattr(setup_entry,'_msi_reconciliation_required',lambda _:True)
    monkeypatch.setattr(setup_entry,'_wait_for_agent_service_running',lambda:True)
    calls=[]
    monkeypatch.setattr(setup_entry,'_install_embedded_msi',lambda path:calls.append(path.name))
    assert setup_entry.main(['--quiet'])==setup_entry.EXIT_SUCCESS
    assert calls==['EndpointAgent.msi']


@pytest.mark.parametrize("foundation", ["1.0.0", "1.0.2"])
def test_shared_operation_decision_keeps_higher_foundation_and_checks_equal_candidate(
    monkeypatch, tmp_path, foundation
):
    _write_public_payload(tmp_path)
    monkeypatch.setattr(setup_entry, "_data_root", lambda: tmp_path / "data")
    monkeypatch.setattr(setup_entry, "_resource_root", lambda: tmp_path)
    monkeypatch.setattr(setup_entry, "_classify_installation_state", lambda *_a, **_kw: "valid")
    monkeypatch.setattr(setup_entry, "_installed_msi_version", lambda: foundation)
    monkeypatch.setattr(setup_entry, "_wait_for_agent_service_running", lambda: True)
    calls = []
    monkeypatch.setattr(setup_entry, "_msi_reconciliation_required", lambda _: calls.append("candidate") or True)
    monkeypatch.setattr(setup_entry, "_require_setup_disk", lambda _: calls.append("cost"))
    monkeypatch.setattr(setup_entry, "_install_embedded_msi", lambda _: calls.append("install"))
    result = setup_entry.main(["--quiet"])
    assert result == (setup_entry.EXIT_SUCCESS if foundation == "1.0.0" else setup_entry.EXIT_ALREADY_INSTALLED)
    assert calls == (["candidate", "cost", "install"] if foundation == "1.0.0" else [])


def _installer_selected_digest(selector, origin):
    from endpoint_contracts.runtime_payload import PayloadFile, PayloadIdentity
    from pc_agent.platform.windows.installation_provenance import CoreEvidence

    selected = json.loads(selector)
    core = PayloadFile("pc_agent.exe", 7, hashlib.sha256(b"fixture").hexdigest())
    identity = PayloadIdentity(selected["version"], selected["source_revision"], None, (core,))
    manifest = json.dumps({"schema_version": 1, **selected, "files": [vars(core)]}).encode()
    receipt = json.dumps({"origin": origin, "version": identity.version}).encode()
    return CoreEvidence(origin, identity, selector, manifest, receipt).digest


@pytest.fixture
def interrupted_repair(monkeypatch, tmp_path):
    from pc_agent.platform.windows import installation_provenance, installer_fence

    _write_public_payload(tmp_path)
    release = json.loads((tmp_path / "EndpointAgent.release.json").read_text())
    paths = setup_entry.WindowsUpdatePaths(tmp_path / "Agent", tmp_path / "data/updates/pending.json")
    paths.install_root.mkdir()
    selector = json.dumps({"schema_version": 1, "version": release["version"],
                           "source_revision": release["source_revision"]}).encode()
    paths.current_path.write_bytes(selector)
    transaction = "11111111-1111-4111-8111-111111111111"
    fence = {
        "transaction_id": transaction, "operation": "install", "phase": "msi-executing", "sequence": 2,
        "package": {"sha256": release["package_sha256"], **{key: release[key] for key in
                    ("product_code", "version", "source_revision")}},
        "selected": _installer_selected_digest(selector, "msi"), "previous": None,
    }
    root = installer_fence.state_root(paths)
    plan_path = root / "provenance" / transaction / "plan.json"
    plan_path.parent.mkdir(parents=True)
    plan = {
        "schema_version": 1, "phase": "prepared", "package_sha256": release["package_sha256"],
        "transaction_id": transaction, "selected": fence["selected"], "previous": None,
        "result": "already_current", "archives": [], "handoff": False,
        "current_before": selector.hex(), "current_after": selector.hex(),
        "previous_before": None, "previous_after": None,
    }
    plan_path.write_text(json.dumps(plan))
    fence_path = root / "active-fence.json"
    fence_path.write_text(json.dumps(fence))
    baseline = {path: path.read_bytes() for path in (plan_path, fence_path, paths.current_path)}
    monkeypatch.setattr(installer_fence, "read_fence", lambda _: json.loads(fence_path.read_bytes()))
    def check_plan(path):
        assert path in {plan_path, root / "foundation.json"}

    monkeypatch.setattr(installation_provenance, "_assert_security", check_plan)
    return paths, plan_path, fence_path, baseline


@pytest.mark.parametrize("core", ["same-msi", "newer-zip", "equal-zip", "older", "absent"])
def test_interrupted_same_version_repair_holds_before_native_launch(monkeypatch, tmp_path, interrupted_repair, core):
    from pc_agent.platform.windows import installation_provenance, installer_fence

    paths, plan_path, fence_path, baseline = interrupted_repair
    if core != "same-msi":
        release = json.loads((tmp_path / "EndpointAgent.release.json").read_bytes())
        version, result = {"newer-zip": ("1.0.1", "preserved"), "equal-zip": ("1.0.0", "handoff"),
                           "older": ("0.9.0", "migrated"), "absent": (None, "migrated")}[core]
        selector = None if version is None else json.dumps({
            "schema_version": 1, "version": version, "source_revision": "a" * 40,
        }).encode()
        if selector is None:
            paths.current_path.unlink()
            del baseline[paths.current_path]
        else:
            paths.current_path.write_bytes(selector)
        fence = json.loads(fence_path.read_bytes())
        plan = json.loads(plan_path.read_bytes())
        fence["selected"] = plan["selected"] = _installer_selected_digest(selector, "zip") if selector else None
        plan.update(result=result, handoff=result == "handoff", current_before=selector.hex() if selector else None)
        if result in ("preserved", "handoff"):
            plan["current_after"] = selector.hex()
        plan_path.write_text(json.dumps(plan))
        fence_path.write_text(json.dumps(fence))
        authority = fence_path.parent / "foundation.json"
        authority.write_text(json.dumps({"schema_version": 1, "release": release}))
        check_security = installer_fence.assert_state_security
        monkeypatch.setattr(installer_fence, "assert_state_security",
                            lambda path, **kw: check_security(path, **kw) if path != authority else None)
        baseline = {path: path.read_bytes() for path in (*baseline, authority)}
    monkeypatch.setattr(installation_provenance, "verified_foundation_release",
                        lambda *_: pytest.fail("hold must not use live MSI registration"))
    monkeypatch.setattr(setup_entry.WindowsUpdatePaths, "production", classmethod(lambda cls: paths))
    monkeypatch.setattr(setup_entry, "_resource_root", lambda: tmp_path)
    monkeypatch.setattr(setup_entry, "_data_root", lambda: tmp_path / "data")
    monkeypatch.setattr(setup_entry, "_diagnostics_root", lambda: tmp_path / "diagnostics")
    monkeypatch.setattr(setup_entry, "_classify_installation_state", lambda *a, **k: "valid")
    monkeypatch.setattr(setup_entry, "_agent_service_installed", lambda: False)
    monkeypatch.setattr(setup_entry, "_installed_msi_version", lambda: "1.0.0")
    costing = []
    monkeypatch.setattr(setup_entry, "_require_setup_disk", costing.append)
    monkeypatch.setattr(setup_entry.subprocess, "run", lambda *_a, **_k: pytest.fail("native wrapper launched"))

    assert setup_entry.main(["--quiet"]) == 21
    result = json.loads((tmp_path / "diagnostics/install-result.json").read_bytes())
    assert result["detail"] == "MSI_OUTCOME_UNCONFIRMED"
    assert costing == []
    assert all(path.read_bytes() == original for path, original in baseline.items())
    assert paths.current_path.exists() == (core != "absent")


@pytest.mark.parametrize("phase,result,handoff", [
    ("msi-starting", "already_current", False),
    ("msi-returned", "already_current", False),
    ("reconciling", "already_current", False),
    ("msi-executing", "migrated", False),
    ("msi-executing", "preserved", False),
    ("msi-executing", "handoff", True),
])
def test_interrupted_repair_guard_preserves_other_recovery_modes(interrupted_repair, phase, result, handoff):
    from pc_agent.platform.windows.installation_provenance import interrupted_same_version_repair

    paths, plan_path, fence_path, _ = interrupted_repair
    plan = json.loads(plan_path.read_bytes())
    plan.update(result=result, handoff=handoff)
    plan_path.write_text(json.dumps(plan))
    fence = json.loads(fence_path.read_bytes())
    assert not interrupted_same_version_repair(paths, {**fence, "phase": phase})


def test_preserved_ota_core_does_not_make_other_foundation_a_repair(monkeypatch, interrupted_repair):
    from pc_agent.platform.windows import installation_provenance, installer_fence

    paths, plan_path, fence_path, _ = interrupted_repair
    plan = json.loads(plan_path.read_bytes())
    plan["result"] = "preserved"
    plan_path.write_text(json.dumps(plan))
    authority = fence_path.parent / "foundation.json"
    authority.write_text(json.dumps({"schema_version": 1, "release": {"package_sha256": "b" * 64}}))
    monkeypatch.setattr(installer_fence, "assert_state_security", lambda path: path == authority)
    monkeypatch.setattr(installation_provenance, "verified_foundation_release",
                        lambda *_: pytest.fail("hold must not use live MSI registration"))

    assert not installation_provenance.interrupted_same_version_repair(paths, json.loads(fence_path.read_bytes()))


def test_authenticated_wrapper_inspection_holds_unknown_native_outcome(monkeypatch, interrupted_repair):
    from pc_agent.platform.windows import installer_transaction_bridge as bridge, msi_inventory

    paths, _, fence_path, baseline = interrupted_repair
    fence = json.loads(fence_path.read_bytes())
    capability = {"operation": "install", "recovery": True, "package": fence["package"]}
    messages = []
    client = SimpleNamespace(phase="inspect", capability=capability, request=lambda *args: messages.append(args))
    monkeypatch.setattr(bridge, "_request_data", lambda *_: {"package_path": "fixture"})
    monkeypatch.setattr(bridge, "_public_fence", lambda *_: fence)
    monkeypatch.setattr(bridge, "_settled", lambda _: None)
    monkeypatch.setattr(msi_inventory, "read_expected_package", lambda *_: object())
    monkeypatch.setattr(bridge, "_validate_install_recovery", lambda *_: pytest.fail("recovery advanced"))

    result = bridge._execute_authorized_phase(client, paths)
    assert result["msi_outcome_unconfirmed"] is True
    assert messages == [("complete", result)]
    assert all(path.read_bytes() == original for path, original in baseline.items())


def test_direct_recovery_wrapper_exits_before_scm_and_msi():
    import base64
    import shutil
    import subprocess

    powershell = shutil.which("powershell.exe") or shutil.which("pwsh")
    if powershell is None:
        pytest.skip("PowerShell needed to exercise the direct wrapper gate")
    wrapper = Path(__file__).resolve().parents[3] / "packaging/windows/Install-EndpointAgentCanary.ps1"
    snippet = r"""
$source = [IO.File]::ReadAllText('__PATH__')
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseInput($source, [ref]$tokens, [ref]$errors)
if ($errors.Count) {exit 90}
$checks = @($ast.FindAll({param($node)
    $node -is [Management.Automation.Language.IfStatementAst] -and
    $node.Clauses[0].Item1.Extent.Text -match 'msi_outcome_unconfirmed'
}, $true))
if ($checks.Count -ne 1) {exit 91}
$offset = $checks[0].Extent.StartOffset
$inspect = $source.LastIndexOf("Invoke-InstallerHelper -Bridge $"+ "bridge -Phase 'inspect'", $offset)
$stop = $source.IndexOf('Stop-ManagedAgentServices -PreviousStates', $offset)
$native = $source.IndexOf('Start-WindowsInstaller', $offset)
if ($inspect -lt 0 -or $stop -le $offset -or $native -le $stop) {exit 92}
$Operation = 'RecoverInterruptedInstall'
$initial = [pscustomobject]@{msi_outcome_unconfirmed=$false}
$LASTEXITCODE = 0
& ([scriptblock]::Create($checks[0].Extent.Text))
if ($LASTEXITCODE -ne 0) {exit 93}
$initial = [pscustomobject]@{msi_outcome_unconfirmed=$true}
. ([scriptblock]::Create($checks[0].Extent.Text))
exit 99
""".replace("__PATH__", str(wrapper).replace("'", "''"))
    encoded = base64.b64encode(snippet.encode("utf-16-le")).decode("ascii")
    result = subprocess.run([powershell, "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
                            check=False, capture_output=True, timeout=30)
    assert result.returncode == 21, result.stderr


def test_same_package_interruption_selects_wrapper_recovery_without_clearing_fence(monkeypatch,tmp_path):
    from pc_agent.platform.windows import installer_fence
    _write_public_payload(tmp_path)
    release=json.loads((tmp_path/'EndpointAgent.release.json').read_text())
    fence={'operation':'install','package':{'sha256':release['package_sha256'],'product_code':release['product_code'],
        'version':release['version'],'source_revision':release['source_revision']}}
    monkeypatch.setattr(installer_fence,'read_fence',lambda _:fence)
    calls=[]
    monkeypatch.setattr(setup_entry.subprocess,'run',lambda command,**kw:(calls.append(command) or SimpleNamespace(returncode=0)))
    setup_entry._install_embedded_msi(tmp_path/'EndpointAgent.msi')
    assert calls[0][-2:]==['-Operation','RecoverInterruptedInstall']
    fence['package']['sha256']='0'*64
    with pytest.raises(setup_entry.SetupInstallError) as failure:
        setup_entry._install_embedded_msi(tmp_path/'EndpointAgent.msi')
    assert failure.value.detail=='PROVENANCE_CONFLICT'
    assert len(calls)==1


@pytest.mark.parametrize('native_result',[68,69,3010,1641])
def test_wrapper_cleanup_and_reboot_results_reach_setup(monkeypatch,tmp_path,native_result):
    _write_public_payload(tmp_path)
    monkeypatch.setattr(setup_entry.subprocess,'run',lambda *_a,**_kw:SimpleNamespace(returncode=native_result))
    assert setup_entry._install_embedded_msi(tmp_path/'EndpointAgent.msi')==native_result


def test_conflicted_rerun_stops_before_msi_or_enrollment(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    (tmp_path / "device-credential").write_text("a" * 43, encoding="ascii")
    monkeypatch.setattr(setup_entry, "_data_root", lambda: tmp_path)
    monkeypatch.setattr(
        setup_entry,
        "_resource_root",
        lambda: pytest.fail("conflicted rerun must not read embedded payload"),
    )

    assert setup_entry.main(["--quiet"]) == 60

@pytest.mark.parametrize('leaf,payload',[
    ('pending_update.json',{'operation_id':'operation','version':'3.2.82'}),
    ('startup-attempt.json',{'operation_id':'operation','version':'3.2.82','attempt_id':'a'*32}),
    ('terminal-outcome.json',{'operation_id':'operation','reported_version':'3.2.79','status':'failed','safe_code':'launcher_apply_failed'}),
])
def test_active_ota_prevents_all_setup_mutation(tmp_path,monkeypatch,leaf,payload):
    from pc_agent.tests.windows.test_update_transaction import _protect
    data=tmp_path/'data';updates=data/'updates';updates.mkdir(parents=True)
    marker=updates/leaf;marker.write_text(json.dumps(payload));_protect(marker)
    monkeypatch.setattr(setup_entry,'_data_root',lambda:data)
    monkeypatch.setattr(setup_entry,'_diagnostics_root',lambda:tmp_path/'diagnostics')
    monkeypatch.setattr(setup_entry,'_install_embedded_msi',lambda *_:pytest.fail('active OTA reached MSI'))
    monkeypatch.setattr(setup_entry,'_stop_tray_before_msi_update',lambda:pytest.fail('active OTA stopped tray'))
    monkeypatch.setattr(setup_entry,'_agent_service_installed',lambda:pytest.fail('active OTA reached service phase'))
    before=marker.read_bytes()
    assert setup_entry.main(['--quiet'])==61
    result=json.loads((tmp_path/'diagnostics'/'install-result.json').read_text())
    assert result['status']==result['detail']=='UPDATE_IN_PROGRESS'
    assert marker.read_bytes()==before


@pytest.mark.parametrize("profile, expected", [
    ("interrupted", 21),
    ("interrupted-source-uninstall", 21),
    ("mutex-busy", 61),
    ("mutex-unreadable", 61),
    ("staged-owner-live", 61),
    ("native-owner-live", 61),
    ("active-ota", 61),
    ("foreign-release", 61),
    ("foreign-embedded-package", 61),
    ("foreign-operation", 61),
    ("foreign-fence", 61),
    ("successor-attempt", 61),
    ("no-native-attempt", 61),
    ("no-native-entry", 61),
    ("native-outcome-recorded", 61),
])
def test_ordinary_setup_classifies_staged_native_hold_before_any_mutation(
    staged, tmp_path, monkeypatch, profile, expected,
):
    from dataclasses import replace
    from pc_agent.platform.windows import compound_upgrade_plan, installer_fence, staged_recovery, update_transaction

    state, paths, binding, owner = staged
    _write_public_payload(tmp_path)
    _set_payload_version(tmp_path, binding.candidate_version)
    manifest = tmp_path / "EndpointAgent.release.json"
    release = {**binding.new_release, "package_sha256": hashlib.sha256(b"msi").hexdigest()}
    manifest.write_text(json.dumps(release), encoding="utf-8")
    binding = replace(binding, new_release=release)
    if profile == "foreign-embedded-package":
        manifest.write_text(json.dumps({
            **release, "product_code": "{11111111-1111-4111-8111-111111111111}"
        }), encoding="utf-8")
    staged = state, paths, binding, owner
    begin(staged)
    move(staged, "preparing", "prepared")
    move(staged, "prepared", "switching")
    paths.current_path.write_bytes(b"\0" * len(binding.selected_before))
    if profile == "active-ota":
        from pc_agent.tests.windows.test_update_transaction import _protect
        paths.pending_path.write_text(json.dumps({"operation_id": "ota", "version": "3.2.125"}))
        _protect(paths.pending_path)
    def snapshot():
        return {leaf: leaf.read_bytes() for leaf in paths.install_root.parent.rglob("*") if leaf.is_file()}

    baseline = snapshot()
    native_owner = {**owner, "pid": owner["pid"] + 1}

    def mutex(timeout_ms):
        assert timeout_ms == 0
        if profile == "mutex-busy":
            raise setup_entry.UpdateInProgress("UPDATE_IN_PROGRESS")
        if profile == "mutex-unreadable":
            pywintypes = pytest.importorskip("pywintypes")
            raise pywintypes.error(5, "GetSecurityInfo", "Access denied")
        return nullcontext()

    def assert_owner_dead(candidate):
        if (candidate == owner and profile == "staged-owner-live") or (
            candidate == native_owner and profile == "native-owner-live"
        ):
            raise ValueError("RECOVERY_REQUIRED")

    def inspect_authority(_paths, supplied_release):
        assert _paths == paths and supplied_release == release
        if profile == "foreign-release":
            raise ValueError("PROVENANCE_CONFLICT")
        return {
            "transaction_id": "different" if profile == "foreign-operation" else binding.operation_id,
            "parent_upgrade_id": "successor" if profile == "successor-attempt" else "original",
            "original_upgrade_id": "original",
            "old": {"package": binding.old_release, "transaction_id": "original-uninstall"},
            "selected": None, "previous": None, "msi_outcome_unconfirmed": True,
        }

    def read_fence(_paths):
        child = installer_fence.fence_path(_paths).parent.name == binding.operation_id
        source = profile == "interrupted-source-uninstall"
        if child == source:
            return None
        leg = binding.old_release if source else release
        transaction = "original-uninstall" if source else binding.operation_id
        package = {"sha256": leg["package_sha256"], **{
            key: leg[key] for key in ("product_code", "version", "source_revision")
        }}
        return {"transaction_id": "different" if profile == "foreign-fence" else transaction,
                "operation": "uninstall" if source else "install", "selected": None,
                "previous": None, "package": package,
                "phase": "msi-starting" if profile == "no-native-entry" else "msi-executing"}

    monkeypatch.setattr(setup_entry, "WindowsUpdatePaths", lambda **_: paths)
    monkeypatch.setattr(setup_entry, "_data_root", lambda: paths.updates_root.parent)
    monkeypatch.setattr(setup_entry, "_resource_root", lambda: tmp_path)
    monkeypatch.setattr(setup_entry, "_diagnostics_root", lambda: tmp_path / "diagnostics")
    monkeypatch.setattr(setup_entry, "_record_in_progress", lambda: pytest.fail("wrote in-progress state"))
    monkeypatch.setattr(update_transaction, "_windows_transaction", mutex)
    monkeypatch.setattr(staged_recovery, "_assert_owner_dead", assert_owner_dead)
    monkeypatch.setattr(staged_recovery, "_native_attempt", lambda *_: None if profile == "no-native-attempt" else {
        "schema_version": 2, "owner": native_owner,
        "native_exit": 0 if profile == "native-outcome-recorded" else None,
    })
    monkeypatch.setattr(compound_upgrade_plan, "inspect_recovery_authority", inspect_authority)
    monkeypatch.setattr(installer_fence, "read_fence", read_fence)
    for name in ("_install_embedded_msi", "_require_setup_disk", "_agent_service_installed"):
        monkeypatch.setattr(setup_entry, name, lambda *_a, name=name: pytest.fail(f"unexpected {name}"))

    assert setup_entry.main(["--quiet"]) == expected
    result = json.loads((tmp_path / "diagnostics" / "install-result.json").read_text())
    assert result["detail"] == ("MSI_OUTCOME_UNCONFIRMED" if expected == 21 else "UPDATE_IN_PROGRESS")
    after = snapshot()
    after.pop(tmp_path / "diagnostics" / "install-result.json", None)
    assert after == baseline


@pytest.mark.parametrize('wrapper_code,detail',[(61,'UPDATE_IN_PROGRESS'),(62,'UPDATE_STATE_INVALID')])
def test_wrapper_exclusion_codes_survive_suppressed_output(tmp_path,monkeypatch,wrapper_code,detail):
    _write_public_payload(tmp_path)
    monkeypatch.setattr(setup_entry.subprocess,'run',lambda *_a,**_k:SimpleNamespace(returncode=wrapper_code))
    with pytest.raises(setup_entry.SetupInstallError) as caught:
        setup_entry._install_embedded_msi(tmp_path/'EndpointAgent.msi')
    assert caught.value.detail==detail


@pytest.mark.parametrize('installation_state',['valid','fresh'])
def test_completed_uninstall_recovery_never_starts_or_enrolls(tmp_path,monkeypatch,installation_state):
    _write_public_payload(tmp_path)
    monkeypatch.setattr(setup_entry,'_resource_root',lambda:tmp_path)
    monkeypatch.setattr(setup_entry,'_data_root',lambda:tmp_path/'data')
    monkeypatch.setattr(setup_entry,'_diagnostics_root',lambda:tmp_path/'diagnostics')
    monkeypatch.setattr(setup_entry,'_classify_installation_state',lambda *_a,**_k:installation_state)
    monkeypatch.setattr(setup_entry,'_installed_msi_version',lambda:None)
    monkeypatch.setattr(setup_entry,'_embedded_recovery_operation',lambda _: 'uninstall',raising=False)
    monkeypatch.setattr(setup_entry,'_require_setup_disk',lambda _:None)
    monkeypatch.setattr(setup_entry,'_install_embedded_msi',lambda _:0)
    monkeypatch.setattr(setup_entry,'_wait_for_agent_service_running',lambda:pytest.fail('uninstalled service start'))
    monkeypatch.setattr(setup_entry,'_installed_provisioner',lambda:pytest.fail('uninstalled enrollment'))
    assert setup_entry.main(['--quiet'])==0
    assert json.loads((tmp_path/'diagnostics'/'install-result.json').read_text())['status']=='UNINSTALLED'


def test_other_package_recovery_rejects_before_native_costing(tmp_path,monkeypatch):
    _write_public_payload(tmp_path)
    monkeypatch.setattr(setup_entry,'_resource_root',lambda:tmp_path)
    monkeypatch.setattr(setup_entry,'_data_root',lambda:tmp_path/'data')
    monkeypatch.setattr(setup_entry,'_diagnostics_root',lambda:tmp_path/'diagnostics')
    def conflict(_): raise setup_entry.SetupInstallError('PROVENANCE_CONFLICT')
    monkeypatch.setattr(setup_entry,'_embedded_recovery_operation',conflict,raising=False)
    monkeypatch.setattr(setup_entry,'_require_setup_disk',lambda _:pytest.fail('unrelated package costed'))
    assert setup_entry.main(['--quiet'])==setup_entry.EXIT_PREFLIGHT_FAILED


def test_provenance_conflict_survives_helper_wrapper_and_setup_evidence(tmp_path,monkeypatch):
    import shutil
    import sys
    powershell = shutil.which("powershell.exe") or shutil.which("pwsh")
    if powershell is None:
        pytest.skip("PowerShell required for extracted exception classification contract")
    from contextlib import contextmanager
    import subprocess
    from pc_agent.platform.windows import service_launcher,installer_transaction_bridge as bridge,msi_inventory
    from endpoint_contracts.runtime_payload import PayloadConflict
    @contextmanager
    def owned(*_):
        yield SimpleNamespace(capability={'package': {'package_sha256': 'b'*64}})
    monkeypatch.setattr(bridge,'owner_authorized_phase',owned)
    # This test covers exception transport, including Linux CI with pwsh. MSI
    # media-root admission has its own actual Windows API tests.
    monkeypatch.setattr(msi_inventory,'immutable_installer_media_roots',lambda *_:())
    monkeypatch.setitem(sys.modules,'win32api',None)
    monkeypatch.setattr(service_launcher.WindowsUpdatePaths,'production',classmethod(lambda cls:cls(tmp_path/'Agent',tmp_path/'data/updates/pending_update.json')))
    def conflict(*_a,**_kw): raise PayloadConflict()
    monkeypatch.setattr(bridge,'execute_authorized_phase',conflict)
    helper_code=service_launcher.main(['--installer-phase','inspect','--installer-session','11111111-1111-4111-8111-111111111111'])
    assert helper_code==63
    script=tmp_path/'classified-failure.ps1'
    script.write_text(r'''param($Source,[int]$Code)
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'parse failure'}
$pump=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Invoke-InstallerOwnerPump'},$true)
$classification=$pump.Find({param($n) $n -is [Management.Automation.Language.IfStatementAst] -and $n.Extent.Text.Contains('$Bridge.Policy.MarkMsiExited($Process.ExitCode)')},$true)
$outer=$ast.Find({param($n) $n -is [Management.Automation.Language.CatchClauseAst] -and $n.Extent.Text.Contains("if (`$_.Exception.Message -eq 'UPDATE_IN_PROGRESS')")},$true)
if($null -eq $classification -or $null -eq $outer){throw 'classification boundary missing'}
$Msi=$false;$Process=[pscustomobject]@{ExitCode=$Code};$completed=$false
Invoke-Expression ('try {'+$classification.Extent.Text+'} '+$outer.Extent.Text)
''',encoding='utf-8')
    wrapper=Path(__file__).resolve().parents[3]/'packaging/windows/Install-EndpointAgentCanary.ps1'
    actual_run=subprocess.run
    def wrapper_result(*_a,**kw):
        assert kw['stdout']==subprocess.DEVNULL and kw['stderr']==subprocess.DEVNULL
        result=actual_run([powershell,'-NoProfile','-NonInteractive','-File',str(script),str(wrapper),str(helper_code)],capture_output=True,text=True,timeout=15)
        assert 'classification boundary missing' not in result.stderr and 'null-valued' not in result.stderr,result.stderr
        return result
    _write_public_payload(tmp_path)
    monkeypatch.setattr(setup_entry,'_resource_root',lambda:tmp_path)
    monkeypatch.setattr(setup_entry,'_data_root',lambda:tmp_path/'data')
    monkeypatch.setattr(setup_entry,'_diagnostics_root',lambda:tmp_path/'diagnostics')
    monkeypatch.setattr(setup_entry,'_classify_installation_state',lambda *_a,**_kw:'fresh')
    monkeypatch.setattr(setup_entry,'_embedded_recovery_operation',lambda _:None)
    monkeypatch.setattr(setup_entry,'_require_setup_disk',lambda _:None)
    monkeypatch.setattr(setup_entry,'_agent_service_installed',lambda:False)
    monkeypatch.setattr(setup_entry.subprocess,'run',wrapper_result)
    assert setup_entry.main(['--quiet'])==setup_entry.EXIT_INSTALL_FAILED
    result=json.loads((tmp_path/'diagnostics/install-result.json').read_text())
    assert result['detail']=='PROVENANCE_CONFLICT'
    assert helper_code==63


def test_wrapper_rollback_is_reported_separately(tmp_path, monkeypatch):
    _write_public_payload(tmp_path)
    monkeypatch.setattr(setup_entry.subprocess, 'run', lambda *_a, **_k: SimpleNamespace(returncode=67))
    assert setup_entry._install_embedded_msi(tmp_path / 'EndpointAgent.msi') == 67


def test_accepted_native_upgrade_attempts_support_before_core_health_check(monkeypatch,tmp_path):
    from pc_agent.platform.windows import provision
    from pc_agent.platform.windows import installation_notification
    _write_public_payload(tmp_path)
    monkeypatch.setattr(setup_entry,'_data_root',lambda:tmp_path/'data')
    monkeypatch.setattr(setup_entry,'_resource_root',lambda:tmp_path)
    monkeypatch.setattr(setup_entry,'_classify_installation_state',lambda *_a,**_kw:'valid')
    monkeypatch.setattr(setup_entry,'_installed_msi_version',lambda:'1.0.0')
    monkeypatch.setattr(setup_entry,'_msi_reconciliation_required',lambda _:True)
    events=[]
    monkeypatch.setattr(installation_notification,'sync_enrolled_installation',lambda _:events.append('lifecycle') or 'delivered')
    monkeypatch.setattr(setup_entry,'_install_embedded_msi',lambda _:events.append('native-accepted') or 0)
    monkeypatch.setattr(provision,'install_enrolled_support',lambda root:events.append('support') or {'installed':False})
    monkeypatch.setattr(setup_entry,'_wait_for_agent_service_running',lambda:events.append('core-health') or False)
    assert setup_entry.main(['--quiet']) == setup_entry.EXIT_SERVICE_FAILED
    assert events == ['native-accepted','lifecycle','support','core-health']
    result=json.loads((tmp_path/'diagnostics'/'support-install-result.json').read_text())
    assert result['installed'] is False
    assert result['status'] == 'unavailable'


def test_fresh_provisioner_reports_support_failure_separately_without_changing_success(tmp_path):
    config=SetupConfig(endpoint_origin='https://endpoint.sosnadmin.local',ca_file=tmp_path/'ca.pem',
        installer_version='1.0.0',installer_release_id='1.0.0')
    setup_entry._run_provisioner(tmp_path/'provision.exe',config,tmp_path/'data','win-test','claim',
        run=lambda *a,**kw:SimpleNamespace(returncode=0,stdout='{"support_access_status":"unavailable"}',stderr=''))
    result=json.loads((tmp_path/'diagnostics'/'support-install-result.json').read_text())
    assert result['installed'] is False
    assert result['status']=='unavailable'


def test_same_version_setup_retries_only_support_without_msi_or_enrollment(monkeypatch,tmp_path):
    from pc_agent.platform.windows import provision
    from pc_agent.platform.windows import installation_notification
    _write_public_payload(tmp_path)
    monkeypatch.setattr(setup_entry,'_data_root',lambda:tmp_path/'data')
    monkeypatch.setattr(setup_entry,'_resource_root',lambda:tmp_path)
    monkeypatch.setattr(setup_entry,'_classify_installation_state',lambda *_a,**_kw:'valid')
    monkeypatch.setattr(setup_entry,'_installed_msi_version',lambda:'1.0.2')
    monkeypatch.setattr(setup_entry,'_msi_reconciliation_required',lambda _:False)
    events=[]
    monkeypatch.setattr(installation_notification,'sync_enrolled_installation',lambda _:events.append('lifecycle-retry') or 'delivered')
    monkeypatch.setattr(setup_entry,'_install_embedded_msi',lambda _:events.append('MSI'))
    monkeypatch.setattr(setup_entry,'_run_provisioner',lambda *a,**k:events.append('enrollment'))
    monkeypatch.setattr(provision,'install_enrolled_support',lambda root:events.append('support') or {'installed':True})
    monkeypatch.setattr(setup_entry,'_wait_for_agent_service_running',lambda:events.append('core-health') or True)
    assert setup_entry.main(['--quiet'])==setup_entry.EXIT_ALREADY_INSTALLED
    assert events==['lifecycle-retry','support','core-health']
    assert json.loads((tmp_path/'diagnostics'/'support-install-result.json').read_text())['installed'] is True

@pytest.mark.parametrize('state,installed,native_recovery,interrupted,admitted', [
    ('valid', '3.2.245', None, False, True),
    ('valid', '3.2.252', None, False, False),
    ('valid', '3.2.253', None, False, False),
    ('valid', None, None, False, False),
    ('clean', None, None, False, False),
    ('repairable', None, None, False, False),
    ('valid', '3.2.245', 'uninstall', False, False),
    ('valid', '3.2.245', None, True, False),
])
def test_operator_failed_core_recovery_requires_enrolled_strict_upgrade(
    tmp_path, monkeypatch, state, installed, native_recovery, interrupted, admitted,
):
    _write_public_payload(tmp_path)
    _set_payload_version(tmp_path, '3.2.252')
    monkeypatch.setattr(setup_entry, '_resource_root', lambda: tmp_path)
    monkeypatch.setattr(setup_entry, '_data_root', lambda: tmp_path/'data')
    monkeypatch.setattr(setup_entry, '_classify_installation_state', lambda *_, **__: state)
    monkeypatch.setattr(setup_entry, '_installed_msi_version', lambda: installed)
    monkeypatch.setattr(setup_entry, '_embedded_recovery_operation', lambda _: native_recovery)
    monkeypatch.setattr(setup_entry, '_require_setup_disk', lambda _: None)
    monkeypatch.setattr(setup_entry, '_wait_for_agent_service_running', lambda: True)

    def transaction(*_, **__):
        if interrupted:
            raise setup_entry.UpdateInProgress('INSTALLER_RECOVERY_REQUIRED')
        return nullcontext()

    calls = []

    def install(path, **kwargs):
        calls.append((path.name, kwargs))
        return 0

    monkeypatch.setattr(setup_entry, 'update_transaction', transaction)
    monkeypatch.setattr(setup_entry, '_install_embedded_msi', install)
    monkeypatch.setattr(setup_entry, '_resume_unenrolled_installation',
                        lambda *_: pytest.fail('operator recovery must never resume unenrolled installation'))
    monkeypatch.setattr(setup_entry, 'UniversalWindowsSetup',
                        lambda *_, **__: pytest.fail('operator recovery must never re-enroll'))

    expected = setup_entry.EXIT_SUCCESS if admitted else setup_entry.EXIT_PREFLIGHT_FAILED
    assert setup_entry.main(['--quiet', '--recover-failed-core']) == expected
    assert calls == ([('EndpointAgent.msi', {'recover_failed_core': True})] if admitted else [])

def test_operator_failed_core_wrapper_ineligibility_is_bounded(tmp_path, monkeypatch):
    _write_public_payload(tmp_path)
    monkeypatch.setattr(setup_entry.subprocess, 'run',
                        lambda *_args, **_kw: SimpleNamespace(returncode=65))
    with pytest.raises(setup_entry.SetupInstallError) as failure:
        setup_entry._install_embedded_msi(tmp_path/'EndpointAgent.msi', recover_failed_core=True)
    assert failure.value.detail == 'FAILED_CORE_RECOVERY_INELIGIBLE'

@pytest.mark.parametrize("frozen", [True, False])
def test_setup_admits_wrapper_media_on_cache_volume(tmp_path, monkeypatch, frozen):
    from pc_agent.platform.windows.update_paths import WindowsUpdatePaths

    _write_public_payload(tmp_path)
    setup_image = tmp_path / "setup.exe"
    setup_image.write_bytes(b"s" * 1500)
    archive = tmp_path / "EndpointCore.zip"
    archive.write_bytes(b"c" * 400)
    monkeypatch.setattr(setup_entry.sys, "frozen", frozen, raising=False)
    monkeypatch.setattr(setup_entry.sys, "executable", str(setup_image))
    msi = tmp_path / "EndpointAgent.msi"
    paths = WindowsUpdatePaths.production()
    cache = paths.install_root.parent / "installer-cache"
    cache.mkdir()
    cache_leaf = cache / ("msi-" + hashlib.sha256(msi.read_bytes()).hexdigest())
    cache_leaf.mkdir()
    (cache_leaf / "EndpointAgent.msi").write_bytes(b"unverified cache")
    before = {p: p.stat().st_mtime_ns for p in cache.rglob("*")}
    allocations = setup_entry._setup_disk_allocations(msi, paths)
    copied = [msi, archive]
    if frozen:
        copied += [setup_image, tmp_path / "EndpointAgent.release.json",
                   tmp_path / "Install-EndpointAgentCanary.ps1"]
    assert sum(size for path, size in allocations if path == cache) == (
        sum(path.stat().st_size for path in copied) + 250
    )
    assert {p: p.stat().st_mtime_ns for p in cache.rglob("*")} == before

@pytest.mark.parametrize("recovery", [False, True])
@pytest.mark.parametrize("cached", [False, True])
def test_setup_admits_predecessor_media_on_cache_volume(tmp_path, monkeypatch, cached, recovery):
    from pc_agent.platform.windows import installation_provenance, installer_fence, msi_inventory
    from pc_agent.platform.windows.update_paths import WindowsUpdatePaths

    _write_public_payload(tmp_path)
    monkeypatch.setattr(setup_entry.sys, "frozen", False, raising=False)
    msi = tmp_path / "EndpointAgent.msi"
    paths = WindowsUpdatePaths.production()
    cache = paths.install_root.parent / "installer-cache"
    predecessor = b"previous MSI media"
    digest = hashlib.sha256(predecessor).hexdigest()
    previous = {"version": "0.9.0", "package_sha256": digest,
                "product_code": "{22222222-2222-4222-8222-222222222222}"}
    state = installer_fence.state_root(paths)
    old_media = state / "packages" / digest / "EndpointAgent.msi"
    old_media.parent.mkdir(parents=True)
    old_media.write_bytes(predecessor)
    if recovery:
        authority = installation_provenance.RecoveryCostAuthority(
            "install", (), (), predecessor_media=old_media,
        )
        monkeypatch.setattr(installation_provenance, "recovery_cost_authority", lambda *_: authority)
        monkeypatch.setattr(setup_entry, "_msi_disk_costs", lambda *_a, **_kw: [])
    else:
        monkeypatch.setattr(installation_provenance, "verified_foundation_release", lambda _: previous)
    monkeypatch.setattr(msi_inventory, "binary_size", lambda path, *a, **kw: 500 if path == old_media else 250)
    if cached:
        old_cache = cache / ("msi-" + digest)
        old_cache.mkdir(parents=True)
        (old_cache / "EndpointAgent.msi").write_bytes(b"unverified predecessor")
    allocations = setup_entry._setup_disk_allocations(msi, paths)
    assert sum(size for path, size in allocations if path == cache) == (
        msi.stat().st_size + 250 + len(predecessor) + 500
    )


@pytest.mark.parametrize("origin", [None, "msi", "retained_msi"])
def test_setup_counts_legacy_rollback_msi_without_legacy_helper(tmp_path, monkeypatch, origin):
    from pc_agent.platform.windows import installation_provenance, legacy_foundation_upgrade, msi_inventory
    from pc_agent.platform.windows.update_paths import WindowsUpdatePaths
    from pc_agent.tests.windows.test_legacy_foundation_admission import RELEASE as release

    _write_public_payload(tmp_path)
    _set_payload_version(tmp_path, "3.2.275")
    msi = tmp_path / "EndpointAgent.msi"
    paths = WindowsUpdatePaths.production()
    cache = paths.install_root.parent / "installer-cache"
    previous = b"exact signed canonical legacy MSI"
    digest = release["package_sha256"]
    source = paths.updates_root.parent / "installer-cache" / f"msi-{digest}" / "EndpointAgent.msi"
    source.parent.mkdir(parents=True)
    source.write_bytes(previous)
    role = legacy_foundation_upgrade.LegacyPredecessor(release, SimpleNamespace(sha256=digest), source)
    monkeypatch.setattr(legacy_foundation_upgrade, "_registered_foundation", lambda _: role)
    monkeypatch.setattr(installation_provenance, "verified_foundation_release", lambda _: release)
    monkeypatch.setattr(
        installation_provenance, "inspect_installed_core",
        lambda *_a, **_kw: SimpleNamespace(current=SimpleNamespace(origin=origin) if origin else None, previous=None),
    )
    monkeypatch.setattr(installation_provenance, "preparation_allocations", lambda *_: ([], []))
    monkeypatch.setattr(setup_entry.sys, "frozen", False, raising=False)

    def helper_size(path, *_args, **_kwargs):
        assert path == msi
        return 250

    monkeypatch.setattr(msi_inventory, "binary_size", helper_size)
    allocations = setup_entry._setup_disk_allocations(msi, paths)
    rollback_bytes = len(previous) if origin else 0
    assert sum(size for path, size in allocations if path == cache) == 3 + 250 + rollback_bytes
    assert not cache.exists()
