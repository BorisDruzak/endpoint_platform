"""Contracts for the offline, privileged Windows update worker."""

from __future__ import annotations

import hashlib
import inspect
import json
import sys
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest


def _pending(paths, artifact: Path, **changes: object) -> Path:
    payload: dict[str, object] = {
        "archive_type": "zip",
        "artifact_path": str(artifact),
        "channel": "canary",
        "operation_id": "caa31a48-bf2f-4f1c-8b77-d1be77e12b4e",
        "received_at": datetime.now(UTC).isoformat(),
        "requested_by": "gateway",
        "requested_reason": "scheduled_rollout",
        "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
        "size": artifact.stat().st_size,
        "target": "windows_amd64",
        "version": "3.2.0",
    }
    payload.update(changes)
    paths.pending_path.parent.mkdir(parents=True, exist_ok=True)
    paths.pending_path.write_text(json.dumps(payload), encoding="utf-8")
    return paths.pending_path


def _artifact(path: Path, content: bytes = b"agent") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("pc_agent.exe", content)
        archive.writestr("_internal/runtime.dat", b"runtime")
    return path


class _Acl:
    def __init__(self, *, reject: bool = False) -> None:
        self.reject = reject
        self.checked: list[Path] = []

    def assert_update_path(self, path: Path) -> None:
        self.checked.append(path)
        if self.reject:
            raise ValueError("wrong owner or ACL")


def _paths(tmp_path: Path):
    from pc_agent.platform.windows.update_paths import WindowsUpdatePaths

    return WindowsUpdatePaths(
        install_root=tmp_path / "install",
        pending_path=tmp_path / "data" / "updates" / "pending_update.json",
    )


def test_release_verifier_uses_fixed_enrolled_state_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The candidate verifier requires the local CA and enrolled durable state."""
    from pc_agent.platform.windows import updater_service
    from pc_agent.platform.windows.updater_service import SubprocessReleaseVerifier

    paths = _paths(tmp_path)
    executable = tmp_path / "candidate" / "pc_agent.exe"
    calls: list[tuple[list[str], str]] = []

    def run(command: list[str], *, cwd: str, **_kwargs):
        calls.append((command, cwd))
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(updater_service.subprocess, "run", run)

    assert SubprocessReleaseVerifier(paths).verify(executable)
    assert calls == [(
        [
            str(executable), "--verify", "--data-dir", str(paths.updates_root.parent),
            "--install-root", str(paths.install_root),
            "--ca-file", str(paths.updates_root.parent / "endpoint-ca.crt"),
        ],
        str(executable.parent),
    )]


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"unexpected": True}, "unknown"),
        ({"service_name": "Spooler"}, "unknown"),
        ({"executable": "C:/Windows/System32/cmd.exe"}, "unknown"),
        ({"sha256": "0" * 64}, "hash"),
        ({"size": 1}, "size"),
    ],
)
def test_pending_validator_rejects_untrusted_fields_and_artifact_integrity(
    tmp_path: Path, change: dict[str, object], message: str
) -> None:
    """A root worker must accept only its fixed request shape and bytes."""
    from pc_agent.platform.windows.updater_service import PendingUpdateValidator

    paths = _paths(tmp_path)
    artifact = _artifact(paths.downloads_root / "candidate.zip")
    _pending(paths, artifact, **change)

    with pytest.raises(ValueError, match=message):
        PendingUpdateValidator(paths, _Acl()).load()


def test_pending_validator_rejects_artifact_outside_fixed_download_root(tmp_path: Path) -> None:
    """An absolute artifact path is safe only under the service-owned downloads root."""
    from pc_agent.platform.windows.updater_service import PendingUpdateValidator

    paths = _paths(tmp_path)
    artifact = _artifact(tmp_path / "outside.zip")
    _pending(paths, artifact)

    with pytest.raises(ValueError, match="artifact"):
        PendingUpdateValidator(paths, _Acl()).load()


def test_pending_validator_rejects_reparse_point_traversal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Path resolution after a reparse point would let an untrusted leaf redirect root."""
    from pc_agent.platform.windows import updater_service
    from pc_agent.platform.windows.updater_service import PendingUpdateValidator

    paths = _paths(tmp_path)
    artifact = _artifact(paths.downloads_root / "candidate.zip")
    _pending(paths, artifact)
    original_lstat = Path.lstat

    class _Details:
        st_file_attributes = 0x400

    def reparse_lstat(path: Path):
        if path == paths.downloads_root:
            return _Details()
        return original_lstat(path)

    monkeypatch.setattr(updater_service.Path, "lstat", reparse_lstat)
    with pytest.raises(ValueError, match="reparse"):
        PendingUpdateValidator(paths, _Acl()).load()


def test_pending_validator_delegates_owner_and_acl_check(tmp_path: Path) -> None:
    """Filesystem shape alone cannot establish Windows ownership or DACL integrity."""
    from pc_agent.platform.windows.updater_service import PendingUpdateValidator

    paths = _paths(tmp_path)
    artifact = _artifact(paths.downloads_root / "candidate.zip")
    _pending(paths, artifact)

    with pytest.raises(ValueError, match="owner or ACL"):
        PendingUpdateValidator(paths, _Acl(reject=True)).load()


def test_pending_validator_rejects_different_bytes_for_existing_target_version(
    tmp_path: Path,
) -> None:
    """A version directory is immutable; reusing its version label cannot replace bytes."""
    from pc_agent.platform.windows.updater_service import PendingUpdateValidator, WindowsUpdater

    paths = _paths(tmp_path)
    artifact = _artifact(paths.downloads_root / "candidate.zip", b"candidate")
    existing = paths.versions_root / "3.2.0"
    existing.mkdir(parents=True)
    (existing / ".endpoint-update.json").write_text(
        json.dumps({"sha256": "f" * 64, "size": 99, "version": "3.2.0"}),
        encoding="utf-8",
    )
    _pending(paths, artifact)

    pending = PendingUpdateValidator(paths, _Acl()).load()

    class _Service:
        def stop(self): pass
        def start(self): pass
        def wait_stopped(self): return True
        def crashed_early(self): return False
    class _Verifier:
        def verify(self, _path): return True
    class _Confirmation:
        def is_confirmed(self, **_kwargs): return True

    updater = WindowsUpdater(paths, acl=_Acl(), service=_Service(), verifier=_Verifier(), confirmation=_Confirmation())
    staging = updater._extract_to_staging(pending)
    with pytest.raises(ValueError, match="collision"):
        updater._publish(staging, pending)


def test_updater_records_a_rejected_handoff_for_the_reconnected_agent(
    tmp_path: Path,
) -> None:
    """A privileged failure must become a bounded local terminal outcome, not a stranded rollout."""
    from pc_agent.platform.windows.updater_service import WindowsUpdater

    paths = _paths(tmp_path)
    artifact = paths.downloads_root / "candidate.zip"
    artifact.parent.mkdir(parents=True)
    artifact.write_bytes(b"not a ZIP")
    _pending(paths, artifact)
    paths.install_root.mkdir(parents=True)
    paths.current_path.write_text('{"version":"3.1.9"}', encoding="utf-8")

    class _Service:
        def stop(self): pass
        def start(self): pass
        def wait_stopped(self): return True
        def crashed_early(self): return False

    result = WindowsUpdater(paths, acl=_Acl(), service=_Service()).run_once()

    assert result.status == "rejected"
    assert json.loads((paths.updates_root / "terminal-outcome.json").read_text()) == {
        "operation_id": "caa31a48-bf2f-4f1c-8b77-d1be77e12b4e",
        "reported_version": "3.1.9",
        "safe_code": "launcher_apply_failed",
        "status": "failed",
    }


def test_updater_rejects_a_stale_pending_build_after_an_msi_runtime_transition(
    tmp_path: Path,
) -> None:
    """A queued canary cannot downgrade a selector advanced by an MSI repair."""
    from pc_agent.platform.windows.updater_service import WindowsUpdater

    paths = _paths(tmp_path)
    artifact = _artifact(paths.downloads_root / "candidate.zip")
    _pending(paths, artifact, version="3.2.4")
    paths.install_root.mkdir(parents=True)
    paths.current_path.write_text('{"version":"3.2.5"}', encoding="utf-8")

    class _Service:
        def stop(self): pass
        def start(self): pass
        def wait_stopped(self): return True
        def crashed_early(self): return False
    class _Verifier:
        def verify(self, _path): return True
    class _Confirmation:
        def is_confirmed(self, **_kwargs): return True

    result = WindowsUpdater(
        paths, acl=_Acl(), service=_Service(), verifier=_Verifier(), confirmation=_Confirmation(),
    ).run_once()

    assert result.status == "rejected"
    assert json.loads((paths.updates_root / "terminal-outcome.json").read_text())["status"] == "failed"
    assert json.loads(paths.current_path.read_text()) == {"version": "3.2.5"}


def test_updater_accepts_an_agent_service_already_stopped_by_the_handoff(
    tmp_path: Path,
) -> None:
    """The updater follows an EXIT_UPDATE_PENDING child without racing SCM's stopped state."""
    from pc_agent.platform.windows.updater_service import WindowsUpdater

    paths = _paths(tmp_path)
    artifact = _artifact(paths.downloads_root / "candidate.zip")
    _pending(paths, artifact, version="3.2.7")
    paths.install_root.mkdir(parents=True)
    paths.current_path.write_text('{"version":"3.2.6"}', encoding="utf-8")

    class _InactiveServiceError(OSError):
        winerror = 1062
    class _Service:
        def stop(self): raise _InactiveServiceError()
        def start(self): pass
        def wait_stopped(self): return True
        def crashed_early(self): return False
    class _Verifier:
        def verify(self, _path): return True
    class _Confirmation:
        def is_confirmed(self, **_kwargs): return True

    result = WindowsUpdater(
        paths, acl=_Acl(), service=_Service(), verifier=_Verifier(), confirmation=_Confirmation(),
    ).run_once()

    assert result.status == "applied"
    assert json.loads(paths.current_path.read_text()) == {"version": "3.2.7"}


def test_updater_contract_has_fixed_identity_and_no_network_or_listener_api() -> None:
    """The updater is an offline SCM worker, never an HTTP daemon."""
    from pc_agent.platform.windows import updater_service
    from pc_agent.platform.windows.update_paths import (
        INSTALL_ROOT,
        PENDING_UPDATE_PATH,
        UPDATER_SERVICE_NAME,
    )

    source = Path(updater_service.__file__).read_text(encoding="utf-8").lower()
    assert UPDATER_SERVICE_NAME == "EndpointAgentUpdater"
    assert str(PENDING_UPDATE_PATH) == r"C:\ProgramData\Endpoint Platform\Agent\updates\pending_update.json"
    assert str(INSTALL_ROOT) == r"C:\Program Files\Endpoint Platform\Agent"
    assert "aiohttp" not in source
    assert "socket" not in source


def test_updater_default_adapters_remain_import_safe_off_windows() -> None:
    """MSI can construct the demand-start worker before pywin32 is available on test hosts."""
    from pc_agent.platform.windows.updater_service import WindowsUpdater

    assert isinstance(WindowsUpdater(), WindowsUpdater)


def test_updater_install_contract_is_demand_start_with_fixed_start_acl() -> None:
    """No caller-controlled service name may broaden SCM start authority."""
    from pc_agent.platform.windows import service_control

    spec = service_control.WindowsUpdaterServiceInstallSpec()
    assert spec.name == "EndpointAgentUpdater"
    assert spec.start_type == "demand"
    assert spec.start_principals == ("S-1-5-18", "S-1-5-32-544", "NT SERVICE\\EndpointAgent")
    assert list(inspect.signature(service_control.restrict_updater_start_permissions).parameters) == []


def test_updater_start_acl_keeps_management_rights_without_granting_start_to_others() -> None:
    """Replacing the whole DACL with RP-only ACEs breaks administration and is unnecessary."""
    from pc_agent.platform.windows.service_control import updater_start_access_policy

    policy = updater_start_access_policy(service_all_access=0xFFFF, service_start=0x10)
    assert policy == {
        "S-1-5-18": 0xFFFF,
        "S-1-5-32-544": 0xFFFF,
        "NT SERVICE\\EndpointAgent": 0x10,
    }


def test_update_acl_rejects_inherited_deny_or_wrong_access_mask() -> None:
    """A SID subset check wrongly accepts a weak allow ACE or an overriding deny ACE."""
    from pc_agent.platform.windows.updater_service import _validate_strict_update_dacl

    class _Dacl:
        def __init__(self, aces): self.aces = aces
        def GetAceCount(self): return len(self.aces)
        def GetAce(self, index): return self.aces[index]
    class _Descriptor:
        def __init__(self, aces, control): self.aces, self.control = aces, control
        def GetSecurityDescriptorDacl(self): return _Dacl(self.aces)
        def GetSecurityDescriptorControl(self): return self.control, 1
    class _Security:
        ACCESS_ALLOWED_ACE_TYPE = 0
        SE_DACL_PROTECTED = 0x1000
        INHERITED_ACE = 0x10
        FILE_ALL_ACCESS = 0xFF
        FILE_GENERIC_READ = 0x01
        FILE_GENERIC_WRITE = 0x02
        DELETE = 0x04
        @staticmethod
        def ConvertSidToStringSid(sid): return sid
        @staticmethod
        def LookupAccountName(_server, principal):
            return {"NT SERVICE\\EndpointAgent": "agent", "NT SERVICE\\EndpointAgentUpdater": "updater"}[principal], None, None

    security = _Security()
    bad = _Descriptor([((1, 0), 0xFF, "S-1-5-18")], security.SE_DACL_PROTECTED)
    with pytest.raises(ValueError, match="ACL"):
        _validate_strict_update_dacl(bad, security)
    inherited = _Descriptor([((0, 0x10), 0xFF, "S-1-5-18")], security.SE_DACL_PROTECTED)
    with pytest.raises(ValueError, match="ACL"):
        _validate_strict_update_dacl(inherited, security)


def test_pending_validator_accepts_the_real_orchestrator_received_at_field(tmp_path: Path) -> None:
    """The headless agent producer includes its reception timestamp in Windows requests."""
    from pc_agent.platform.windows.updater_service import PendingUpdateValidator

    paths = _paths(tmp_path)
    artifact = _artifact(paths.downloads_root / "candidate.zip")
    _pending(paths, artifact, received_at=datetime.now(UTC).isoformat())

    assert PendingUpdateValidator(paths, _Acl()).load().version == "3.2.0"


def test_updater_exposes_a_fixed_name_scm_dispatcher_without_importing_pywin32() -> None:
    """The MSI service binary needs an actual EndpointAgentUpdater dispatch entrypoint."""
    from pc_agent.platform.windows import updater_service

    assert updater_service.UPDATER_SERVICE_NAME == "EndpointAgentUpdater"
    assert callable(updater_service.run_windows_updater_service)


def test_startup_proof_writer_binds_the_post_handshake_proof_to_pending_operation(
    tmp_path: Path,
) -> None:
    """A matching version alone would allow a stale success marker to authorize a release."""
    from pc_agent.platform.windows.startup_confirmation import StartupProofWriter

    paths = _paths(tmp_path)
    artifact = _artifact(paths.downloads_root / "candidate.zip")
    operation_id = "caa31a48-bf2f-4f1c-8b77-d1be77e12b4e"
    _pending(paths, artifact, received_at=datetime.now(UTC).isoformat(), operation_id=operation_id)
    paths.install_root.mkdir(parents=True)
    paths.current_path.write_text(json.dumps({"version": "3.2.0"}), encoding="utf-8")
    (paths.updates_root / "startup-attempt.json").write_text(json.dumps({
        "attempt_id": "candidate-attempt", "operation_id": operation_id, "version": "3.2.0",
    }), encoding="utf-8")

    assert StartupProofWriter(paths).record_after_server_handshake() is True
    proof = json.loads((paths.updates_root / "startup-confirmation.json").read_text())
    assert proof["operation_id"] == operation_id
    assert proof["attempt_id"] == "candidate-attempt"
    assert proof["version"] == "3.2.0"
    assert proof["status"] == "confirmed"


def test_startup_proof_writer_is_a_noop_on_clean_install(tmp_path: Path) -> None:
    from pc_agent.platform.windows.startup_confirmation import StartupProofWriter

    paths = _paths(tmp_path)
    assert StartupProofWriter(paths).record_after_server_handshake() is False
    assert not (paths.updates_root / "startup-confirmation.json").exists()


def test_confirmation_rejects_a_stale_or_wrong_operation_proof(tmp_path: Path) -> None:
    from pc_agent.platform.windows.updater_service import FileStartupConfirmation

    paths = _paths(tmp_path)
    paths.updates_root.mkdir(parents=True)
    (paths.updates_root / "startup-confirmation.json").write_text(json.dumps({
        "status": "confirmed", "version": "3.2.0", "operation_id": "old",
        "confirmed_at": (datetime.now(UTC) - timedelta(minutes=1)).isoformat(),
    }), encoding="utf-8")

    assert FileStartupConfirmation(paths).is_confirmed(
        version="3.2.0", operation_id="new", attempt_id="new-attempt", not_before=datetime.now(UTC) - timedelta(seconds=5)
    ) is False


def test_extraction_rejects_an_artifact_replaced_after_validation(tmp_path: Path) -> None:
    """Hashing a pathname then reopening it lets a replacement archive win the race."""
    from pc_agent.platform.windows.updater_service import PendingUpdateValidator, WindowsUpdater

    paths = _paths(tmp_path)
    artifact = _artifact(paths.downloads_root / "candidate.zip")
    _pending(paths, artifact)
    pending = PendingUpdateValidator(paths, _Acl()).load()
    artifact.write_bytes(b"replacement")

    class _Service:
        def stop(self): pass
        def start(self): pass
        def wait_stopped(self): return True
        def crashed_early(self): return False
    class _Verifier:
        def verify(self, _path): return True
    class _Confirmation:
        def is_confirmed(self, **_kwargs): return True

    updater = WindowsUpdater(paths, acl=_Acl(), service=_Service(), verifier=_Verifier(), confirmation=_Confirmation())
    with pytest.raises(ValueError, match="artifact changed"):
        updater._extract_to_staging(pending)


def test_corrupt_zip_removes_the_private_pinned_artifact_copy(tmp_path: Path) -> None:
    """A corrupt archive must not leave a root-owned sibling for a later confused run."""
    from pc_agent.platform.windows.updater_service import PendingUpdateValidator, WindowsUpdater

    paths = _paths(tmp_path)
    artifact = paths.downloads_root / "candidate.zip"
    artifact.parent.mkdir(parents=True)
    artifact.write_bytes(b"not a zip")
    _pending(paths, artifact)
    pending = PendingUpdateValidator(paths, _Acl()).load()
    class _Service:
        def stop(self): pass
        def start(self): pass
        def wait_stopped(self): return True
        def crashed_early(self): return False
    class _Verifier:
        def verify(self, _path): return True
    class _Confirmation:
        def is_confirmed(self, **_kwargs): return True
    updater = WindowsUpdater(paths, acl=_Acl(), service=_Service(), verifier=_Verifier(), confirmation=_Confirmation())
    with pytest.raises(Exception):
        updater._extract_to_staging(pending)
    assert not list((paths.versions_root / "_staging").glob(".artifact-*.zip"))


def test_confirmation_requires_a_new_candidate_attempt_id(tmp_path: Path) -> None:
    """A previous proof for the same rollout must not confirm a restarted candidate."""
    from pc_agent.platform.windows.updater_service import FileStartupConfirmation

    paths = _paths(tmp_path)
    paths.updates_root.mkdir(parents=True)
    (paths.updates_root / "startup-confirmation.json").write_text(json.dumps({
        "attempt_id": "old-attempt", "confirmed_at": datetime.now(UTC).isoformat(),
        "operation_id": "op", "status": "confirmed", "version": "3.2.0",
    }), encoding="utf-8")
    assert FileStartupConfirmation(paths).is_confirmed(
        version="3.2.0", operation_id="op", attempt_id="new-attempt", not_before=datetime.now(UTC) - timedelta(seconds=1)
    ) is False


def test_strict_update_acl_rejects_any_propagation_flag() -> None:
    """Explicit object/container/inherit-only ACE propagation is not a protected file DACL."""
    from pc_agent.platform.windows.updater_service import _validate_strict_update_dacl

    class _Dacl:
        def GetAceCount(self): return 4
        def GetAce(self, index): return ((0, 0x01 if index == 0 else 0), 0xFF if index < 2 else 0x07, ("S-1-5-18", "S-1-5-32-544", "agent", "updater")[index])
    class _Descriptor:
        def GetSecurityDescriptorControl(self): return 0x1000, 1
        def GetSecurityDescriptorDacl(self): return _Dacl()
    class _Security:
        ACCESS_ALLOWED_ACE_TYPE = 0
        SE_DACL_PROTECTED = 0x1000
        INHERITED_ACE = 0x10
        @staticmethod
        def ConvertSidToStringSid(sid): return sid
        @staticmethod
        def LookupAccountName(_server, principal):
            return {"NT SERVICE\\EndpointAgent": "agent", "NT SERVICE\\EndpointAgentUpdater": "updater"}[principal], None, None
    class _Rights:
        FILE_ALL_ACCESS = 0xFF
        FILE_GENERIC_READ = 1
        FILE_GENERIC_WRITE = 2
        DELETE = 4
    with pytest.raises(ValueError, match="ACL"):
        _validate_strict_update_dacl(_Descriptor(), _Security(), _Rights())


def test_strict_update_acl_accepts_explicit_child_inheritance_for_protected_directory() -> None:
    """The protected updates root must keep its four explicit child-inheritable ACEs."""
    from pc_agent.platform.windows.updater_service import _validate_strict_update_dacl

    class _Dacl:
        def GetAceCount(self): return 4
        def GetAce(self, index): return ((0, 0x03), 0xFF if index < 2 else 0x07, ("S-1-5-18", "S-1-5-32-544", "agent", "updater")[index])
    class _Descriptor:
        def GetSecurityDescriptorControl(self): return 0x1000, 1
        def GetSecurityDescriptorDacl(self): return _Dacl()
    class _Security:
        ACCESS_ALLOWED_ACE_TYPE = 0
        SE_DACL_PROTECTED = 0x1000
        INHERITED_ACE = 0x10
        OBJECT_INHERIT_ACE = 0x01
        CONTAINER_INHERIT_ACE = 0x02
        @staticmethod
        def ConvertSidToStringSid(sid): return sid
        @staticmethod
        def LookupAccountName(_server, principal):
            return {"NT SERVICE\\EndpointAgent": "agent", "NT SERVICE\\EndpointAgentUpdater": "updater"}[principal], None, None
    class _Rights:
        FILE_ALL_ACCESS = 0xFF
        FILE_GENERIC_READ = 1
        FILE_GENERIC_WRITE = 2
        DELETE = 4

    _validate_strict_update_dacl(
        _Descriptor(), _Security(), _Rights(), allow_child_inheritance=True,
    )


@pytest.mark.parametrize(
    ("worker_status", "expected_statuses"),
    [
        (
            "applied",
            [
                (2, {}),
                (4, {}),
                (3, {}),
                (1, {}),
            ],
        ),
        (
            "rejected",
            [
                (2, {}),
                (4, {}),
                (1, {"win32ExitCode": 1066, "svcExitCode": 0x20000001}),
            ],
        ),
    ],
)
def test_updater_dispatcher_leaves_single_terminal_status_to_native_pywin32_host(
    monkeypatch: pytest.MonkeyPatch,
    worker_status: str,
    expected_statuses: list[tuple[int, dict[str, int]]],
) -> None:
    """PythonService.service_main must own the sole terminal SCM report."""
    from pc_agent.platform.windows import updater_service

    events: list[tuple[int, dict[str, int]]] = []
    errors: list[str] = []
    hosted: dict[str, type] = {}
    win32service = ModuleType("win32service")
    win32service.SERVICE_STOPPED = 1
    win32service.SERVICE_START_PENDING = 2
    win32service.SERVICE_STOP_PENDING = 3
    win32service.SERVICE_RUNNING = 4
    win32service.ERROR_SERVICE_SPECIFIC_ERROR = 1066

    class _ServiceFrameworkBaseSequence:
        """Exact status sequence used by pywin32 ServiceFramework.SvcRun."""

        def __init__(self, _args) -> None:
            pass

        def ReportServiceStatus(self, status: int, **kwargs: int) -> None:
            events.append((status, kwargs))

        def SvcRun(self) -> None:
            self.ReportServiceStatus(win32service.SERVICE_RUNNING)
            self.SvcDoRun()
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)

    win32serviceutil = ModuleType("win32serviceutil")
    win32serviceutil.ServiceFramework = _ServiceFrameworkBaseSequence
    servicemanager = ModuleType("servicemanager")
    servicemanager.Initialize = lambda: None

    def prepare(service_class: type) -> None:
        hosted["service_class"] = service_class

    def dispatch() -> None:
        service = hosted["service_class"](["EndpointAgentUpdater"])
        # Faithful boundary sequence from pywin32 311 PythonService.cpp:
        # native service_main brackets the Python SvcRun call with the initial
        # START_PENDING and exactly one final STOPPED report.
        service.ReportServiceStatus(win32service.SERVICE_START_PENDING)
        try:
            service.SvcRun()
        except Exception as error:
            errors.append(str(error))
            service.ReportServiceStatus(
                win32service.SERVICE_STOPPED,
                win32ExitCode=win32service.ERROR_SERVICE_SPECIFIC_ERROR,
                svcExitCode=0x20000001,
            )
        else:
            service.ReportServiceStatus(win32service.SERVICE_STOPPED)

    servicemanager.PrepareToHostSingle = prepare
    servicemanager.StartServiceCtrlDispatcher = dispatch
    monkeypatch.setitem(sys.modules, "servicemanager", servicemanager)
    monkeypatch.setitem(sys.modules, "win32service", win32service)
    monkeypatch.setitem(sys.modules, "win32serviceutil", win32serviceutil)
    monkeypatch.setattr(
        updater_service,
        "WindowsUpdater",
        lambda: SimpleNamespace(
            run_once=lambda: SimpleNamespace(
                status=worker_status, message="candidate validation failed"
            )
        ),
    )

    assert updater_service.run_windows_updater_service() == 0
    assert events == expected_statuses
    if worker_status == "rejected":
        assert errors == [
            "EndpointAgentUpdater worker failed with status 'rejected': "
            "candidate validation failed"
        ]
    else:
        assert errors == []
