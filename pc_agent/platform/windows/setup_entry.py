"""Standalone universal Windows Setup entrypoint."""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import time
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Literal

from ctypes import wintypes

from pc_agent.core.device_fingerprint import collect_device_fingerprint
from pc_agent.device_credential import read_device_credential
from pc_agent.enrollment_bootstrap import _derive_hardware_fingerprint
from pc_agent.enrollment_identity import (
    ENROLLMENT_IDENTITY_FILENAME,
    read_enrollment_device_id,
)
from pc_agent.platform.windows.update_paths import WindowsUpdatePaths
from pc_agent.platform.windows.update_transaction import update_transaction, active_update_state, UpdateInProgress
from pc_agent.platform.windows.acl import PyWin32AclAdapter, WindowsAclError
from pc_agent.platform.windows.disk_readiness import (
    DiskInsufficient, MAX_ARTIFACT_BYTES,
    is_disk_full, require_allocation_space,
)
from pc_agent.windows_setup import (
    HttpsSetupTransport,
    SetupClaimError,
    SetupConfig,
    SetupProvisionError,
    UniversalWindowsSetup,
)


EXIT_SUCCESS = 0
EXIT_ALREADY_INSTALLED = 10
EXIT_PREFLIGHT_FAILED = 20
EXIT_INSTALL_FAILED = 21
EXIT_ENROLLMENT_DENIED = 30
EXIT_APPROVAL_TIMEOUT = 31
EXIT_REVIEW_REQUIRED = 32
EXIT_REQUEST_EXPIRED = 33
EXIT_CLAIM_FAILED = 40
EXIT_PROVISIONING_FAILED = 41
EXIT_SERVICE_FAILED = 50
EXIT_WSS_TIMEOUT = 51
EXIT_CONTEXT_TIMEOUT = 52
EXIT_REPAIR_REQUIRED = 60
EXIT_UPDATE_IN_PROGRESS = 61
_SAFE_LOG_DETAIL = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_INSTALL_RESULT_FILENAME = "install-result.json"
_PROVISIONER_ERROR = re.compile(
    r"^Windows provisioning failed: ([A-Za-z][A-Za-z0-9_]{0,63})$"
)
_SEMVER = re.compile(
    r"^(?P<major>0|[1-9][0-9]*)\.(?P<minor>0|[1-9][0-9]*)\."
    r"(?P<patch>0|[1-9][0-9]*)(?:-(?P<pre>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)


class SetupInstallError(RuntimeError):
    """A bounded MSI-installation failure safe for local diagnostics."""

    def __init__(self, detail: str) -> None:
        super().__init__("Windows Setup MSI installation failed")
        self.detail = detail


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="EndpointAgentSetup.exe")
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--preflight", action="store_true")
    return parser


def _resource_root() -> Path:
    """Locate one-file PyInstaller resources without accepting caller paths."""
    if getattr(sys, "frozen", False):
        return Path(sys._MEIPASS) / "payload"  # type: ignore[attr-defined]
    return Path(__file__).resolve().parents[3] / "setup-payload"


def _read_public_setup_config(path: Path) -> dict[str, str]:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise ValueError("Windows Setup configuration is unavailable") from error
    if not raw or len(raw) > 4096:
        raise ValueError("Windows Setup configuration is invalid")
    try:
        payload: Any = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("Windows Setup configuration is invalid") from error
    required = {
        "schema_version",
        "endpoint_origin",
        "installer_version",
        "installer_release_id",
    }
    if not isinstance(payload, dict) or set(payload) != required:
        raise ValueError("Windows Setup configuration is invalid")
    if payload.get("schema_version") != "endpoint_windows_setup_config_v1":
        raise ValueError("Windows Setup configuration is invalid")
    values = {name: payload[name] for name in required if name != "schema_version"}
    if not all(isinstance(value, str) and value for value in values.values()):
        raise ValueError("Windows Setup configuration is invalid")
    return values


def _verify_embedded_msi(msi_path: Path) -> tuple[Path, Path]:
    """Bind the extracted MSI to its embedded canonical release evidence."""
    if not msi_path.is_file():
        raise SetupInstallError("MSI_UNAVAILABLE")
    manifest_path = msi_path.with_name("EndpointAgent.release.json")
    wrapper_path = msi_path.with_name("Install-EndpointAgentCanary.ps1")
    if not manifest_path.is_file() or not wrapper_path.is_file():
        raise SetupInstallError("MSI_RELEASE_UNAVAILABLE")
    try:
        manifest_bytes = manifest_path.read_bytes()
        if not manifest_bytes or len(manifest_bytes) > 4096:
            raise ValueError("invalid manifest length")
        manifest = json.loads(manifest_bytes)
        config = _read_public_setup_config(msi_path.with_name("setup-config.json"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise SetupInstallError("MSI_RELEASE_INVALID") from error
    if not isinstance(manifest, dict) or set(manifest) != {
        "initial_runtime_tree_sha256", "package_sha256", "product_code",
        "schema_version", "source_revision", "version",
    } or manifest.get("schema_version") != "endpoint_windows_release_v1":
        raise SetupInstallError("MSI_RELEASE_INVALID")
    if (
        not isinstance(manifest["version"], str)
        or manifest["version"] != config["installer_version"]
        or not isinstance(manifest["product_code"], str)
        or re.fullmatch(r"\{[0-9A-F-]{36}\}", manifest["product_code"]) is None
        or not isinstance(manifest["source_revision"], str)
        or re.fullmatch(r"[0-9a-f]{40}", manifest["source_revision"]) is None
        or not isinstance(manifest["initial_runtime_tree_sha256"], str)
        or re.fullmatch(r"[0-9a-f]{64}", manifest["initial_runtime_tree_sha256"]) is None
        or not isinstance(manifest["package_sha256"], str)
        or re.fullmatch(r"[0-9a-f]{64}", manifest["package_sha256"]) is None
    ):
        raise SetupInstallError("MSI_RELEASE_INVALID")
    digest = hashlib.sha256()
    try:
        with msi_path.open("rb") as source:
            for block in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as error:
        raise SetupInstallError("MSI_UNAVAILABLE") from error
    if digest.hexdigest() != manifest["package_sha256"]:
        raise SetupInstallError("MSI_HASH_MISMATCH")
    return manifest_path, wrapper_path


def _embedded_recovery_operation(msi_path: Path) -> str | None:
    manifest_path, _ = _verify_embedded_msi(msi_path)
    from .installer_fence import read_fence
    fence = read_fence(WindowsUpdatePaths.production())
    if fence is not None:
        release = json.loads(manifest_path.read_text(encoding='utf-8'))
        if any(fence['package'][name] != release[key] for name,key in (
            ('sha256','package_sha256'),('product_code','product_code'),('version','version'),('source_revision','source_revision'))):
            raise SetupInstallError('PROVENANCE_CONFLICT')
        return fence['operation']
    return None


def _install_embedded_msi(msi_path: Path) -> int:
    manifest_path, wrapper_path = _verify_embedded_msi(msi_path)
    operation = ['-Operation','RecoverInterruptedInstall'] if _embedded_recovery_operation(msi_path) else []
    windows_powershell = (
        Path(os.environ.get("SystemRoot", r"C:\Windows"))
        / "System32" / "WindowsPowerShell" / "v1.0"
    )
    powershell = windows_powershell / "powershell.exe"
    environment = os.environ.copy()
    # A frozen Python process can inherit PowerShell 7's module path. Windows
    # PowerShell 5.1 then cannot autoload its own Get-FileHash/JSON modules.
    environment["PSModulePath"] = str(windows_powershell / "Modules")
    try:
        completed = subprocess.run(
            [str(powershell), "-NoLogo", "-NoProfile", "-NonInteractive",
             "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-File",
             str(wrapper_path), "-MsiPath", str(msi_path),
             "-ReleaseManifest", str(manifest_path), *operation],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            shell=False,
            env=environment,
            creationflags=_windowless_creation_flags(),
        )
    except OSError as error:
        raise SetupInstallError("MSI_EVIDENCE_FAILED") from error
    if completed.returncode == 61:
        raise SetupInstallError("UPDATE_IN_PROGRESS")
    if completed.returncode == 62:
        raise SetupInstallError("UPDATE_STATE_INVALID")
    if completed.returncode == 63:
        raise SetupInstallError("PROVENANCE_CONFLICT")
    if completed.returncode not in (0,3010,1641):
        raise SetupInstallError("MSI_EVIDENCE_FAILED")
    return completed.returncode


def _msi_disk_costs(msi_path: Path, *, recovery_context=None) -> list[tuple[Path, int]]:
    from .msi_disk_costing import MsiCostError, msi_disk_allocations
    try:
        return msi_disk_allocations(msi_path) if recovery_context is None else msi_disk_allocations(msi_path,recovery_context=recovery_context)
    except MsiCostError as error:
        if is_disk_full(error):
            raise DiskInsufficient() from error
        raise SetupInstallError("MSI_COST_UNAVAILABLE") from error


def _setup_disk_allocations(
    msi_path: Path, paths: WindowsUpdatePaths
) -> list[tuple[Path, int]]:
    """One package-bound read-only plan for native, wrapper and retained copies."""
    from . import installation_provenance as provenance, msi_inventory
    from endpoint_contracts.runtime_payload import read_json

    manifest_path, _wrapper = _verify_embedded_msi(msi_path)
    release = read_json(manifest_path.read_bytes(), 4096)
    expected = msi_inventory.read_expected_package(msi_path, release)
    authority = provenance.recovery_cost_authority(paths, msi_path, release)
    size = msi_path.stat().st_size
    if not 0 < size <= MAX_ARTIFACT_BYTES:
        raise SetupInstallError("MSI_COST_INVALID")
    # PyInstaller's extracted MSI already exists. Cost only new Windows
    # Installer components/cache/temp plus our additional protected MSI copy.
    if authority is None:
        inspected = provenance.inspect_installed_core(
            paths, resulting_foundation=expected.package.version
        )
        allocations = _msi_disk_costs(msi_path)
        preparation, _jobs = provenance.preparation_allocations(
            paths, inspected, expected, msi_path
        )
    else:
        from .msi_disk_costing import RecoveryCostContext

        allocations = _msi_disk_costs(
            msi_path, recovery_context=RecoveryCostContext(paths, release)
        )
        preparation = authority.allocations
    # The provenance wrapper allocates an execution copy in ProgramFiles and
    # a protected cache copy in ProgramData. Both coexist with input.
    allocations.extend(
        [
            (paths.install_root.parent / "installer-cache", size),
            (paths.updates_root.parent, size + 16 * 1024),
        ]
    )
    allocations.extend(preparation)
    return allocations


def _require_setup_disk(msi_path: Path) -> None:
    paths = WindowsUpdatePaths.production()
    try:
        allocations = _setup_disk_allocations(msi_path, paths)
    except ValueError as error:
        raise SetupInstallError("PROVENANCE_CONFLICT") from error
    require_allocation_space(allocations)


def _stop_tray_before_msi_update() -> None:
    """Remove the running companion before MSI invokes the old installed helper."""
    if os.name != "nt":
        return
    try:
        from pc_agent.platform.windows.service_launcher import stop_tray_companions

        stop_tray_companions()
    except Exception as error:
        raise SetupInstallError("TRAY_SHUTDOWN_FAILED") from error


def _installed_provisioner() -> Path:
    program_files = os.environ.get("ProgramW6432") or os.environ.get("ProgramFiles")
    if not program_files:
        raise RuntimeError("Windows Setup Program Files location is unavailable")
    executable = (
        Path(program_files)
        / "Endpoint Platform"
        / "Agent"
        / "endpoint-agent-provision.exe"
    )
    if not executable.is_file():
        raise RuntimeError("Windows Setup provisioner is unavailable")
    return executable


def _installed_tray_companion() -> Path:
    """Return only the tray executable installed in the fixed product directory."""
    program_files = os.environ.get("ProgramW6432") or os.environ.get("ProgramFiles")
    if not program_files:
        raise RuntimeError("Windows Setup Program Files location is unavailable")
    executable = (
        Path(program_files) / "Endpoint Platform" / "Agent" / "EndpointAgentTray.exe"
    )
    if not executable.is_file():
        raise RuntimeError("Windows Setup tray companion is unavailable")
    return executable


def _installed_user_sensor_companion() -> Path:
    program_files = os.environ.get("ProgramW6432") or os.environ.get("ProgramFiles")
    if not program_files:
        raise RuntimeError("Windows Setup Program Files location is unavailable")
    executable = (
        Path(program_files) / "Endpoint Platform" / "Agent" / "EndpointUserSensor.exe"
    )
    if not executable.is_file():
        raise RuntimeError("Windows Setup user sensor companion is unavailable")
    return executable


def _current_process_session_id() -> int | None:
    """Return this process's Windows session identifier when it is available."""
    if os.name != "nt":
        return None
    try:
        session_id = wintypes.DWORD()
        process_id_to_session_id = ctypes.WinDLL(
            "kernel32", use_last_error=True
        ).ProcessIdToSessionId
        process_id_to_session_id.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
        process_id_to_session_id.restype = wintypes.BOOL
        if not process_id_to_session_id(os.getpid(), ctypes.byref(session_id)):
            return None
    except (AttributeError, OSError):
        return None
    return int(session_id.value)


def _is_interactive_windows_session() -> bool:
    """Avoid creating a session-0 tray process during service/SYSTEM deployments."""
    if os.name != "nt":
        return False
    session_name = os.environ.get("SESSIONNAME", "")
    username = os.environ.get("USERNAME", "")
    if session_name.casefold() == "services" or username.casefold() == "system":
        return False
    session_id = _current_process_session_id()
    if session_id is not None:
        return session_id != 0
    return bool(session_name)


def _start_installed_user_companion(executable: Callable[[], Path]) -> bool:
    if not _is_interactive_windows_session():
        return False
    try:
        subprocess.Popen(  # noqa: S603 - fixed, installed executable only
            [str(executable())],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=False,
            close_fds=True,
            creationflags=_windowless_creation_flags(),
        )
    except (OSError, RuntimeError):
        return False
    return True


def _restart_tray_companion() -> bool:
    """Restore the user-visible tray after MSI stopped it for an update."""
    return _start_installed_user_companion(_installed_tray_companion)


def _restart_user_sensor_companion() -> bool:
    """Restore Activity sampling in this interactive session after MSI update."""
    return _start_installed_user_companion(_installed_user_sensor_companion)


def _service_ready_detail() -> str:
    """Report whether both user companions resumed after an interactive update."""
    if not _is_interactive_windows_session():
        return "SERVICE_RUNNING"
    tray_started = _restart_tray_companion()
    sensor_started = _restart_user_sensor_companion()
    if tray_started and sensor_started:
        return "SERVICE_RUNNING"
    if not tray_started and not sensor_started:
        return "SERVICE_RUNNING_USER_COMPANIONS_START_FAILED"
    if not tray_started:
        return "SERVICE_RUNNING_TRAY_START_FAILED"
    return "SERVICE_RUNNING_USER_SENSOR_START_FAILED"


def _data_root() -> Path:
    program_data = os.environ.get("ProgramData", r"C:\ProgramData")
    return Path(program_data) / "Endpoint Platform" / "Agent"


def _installed_product_version(product_code: str) -> str | None:
    """Read Windows Installer's installed product identity, independent of ZIP selection."""
    if os.name != "nt":
        return None
    try:
        installer = ctypes.WinDLL("msi", use_last_error=True)
        query_state = installer.MsiQueryProductStateW
        query_state.argtypes = [wintypes.LPCWSTR]
        query_state.restype = ctypes.c_int
        if query_state(product_code) != 5:
            return None
        product_info = installer.MsiGetProductInfoW
        product_info.argtypes = [
            wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPWSTR,
            ctypes.POINTER(wintypes.DWORD),
        ]
        product_info.restype = wintypes.UINT
        value = ctypes.create_unicode_buffer(64)
        length = wintypes.DWORD(len(value))
        if product_info(product_code, "VersionString", value, ctypes.byref(length)) != 0:
            return None
    except (AttributeError, OSError):
        return None
    return value.value


def _installed_msi_version() -> str | None:
    """Trust an installed MSI version only with matching protected cache and product."""
    from .installer_fence import state_root,assert_state_security
    from .installation_provenance import _read
    from .msi_inventory import read_expected_package, verify_foundation
    from endpoint_contracts.runtime_payload import read_json
    paths = WindowsUpdatePaths.production()
    foundation = state_root(paths) / 'foundation.json'
    if foundation.exists():
        try:
            assert_state_security(foundation)
            authority = read_json(_read(foundation,4096),4096)
            if (set(authority) != {'schema_version','release'} or type(authority['schema_version']) is not int
                or authority['schema_version'] != 1 or not isinstance(authority['release'],dict)
                or not isinstance(authority['release'].get('package_sha256'),str)
                or re.fullmatch('[0-9a-f]{64}',authority['release']['package_sha256']) is None):
                return None
            release = authority['release']
            package_path=state_root(paths)/'packages'/release['package_sha256']/'EndpointAgent.msi'
            assert_state_security(package_path)
            package = read_expected_package(package_path,release)
            verify_foundation(package.package,paths.install_root,expected=package)
            return package.package.version
        except (OSError,ValueError,KeyError,TypeError):
            return None
    cache_root = _data_root() / "installer-cache"
    provenance_path = cache_root / "installer-provenance.json"
    try:
        raw = provenance_path.read_bytes()
        if not raw or len(raw) > 4096:
            return None
        provenance = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(provenance, dict) or set(provenance) != {
        "cache_file", "initial_runtime_tree_sha256", "package_sha256", "product_code",
        "release_manifest_schema_version", "schema_version", "source_revision", "version",
    }:
        return None
    version = provenance["version"]
    package_hash = provenance["package_sha256"]
    product_code = provenance["product_code"]
    if (
        provenance["schema_version"] != "endpoint_windows_installer_provenance_v1"
        or provenance["release_manifest_schema_version"] != "endpoint_windows_release_v1"
        or not isinstance(version, str)
        or re.fullmatch(r"\d+\.\d+\.\d+", version) is None
        or not isinstance(package_hash, str)
        or re.fullmatch(r"[0-9a-f]{64}", package_hash) is None
        or provenance["cache_file"] != f"msi-{package_hash}/EndpointAgent.msi"
        or not isinstance(product_code, str)
        or re.fullmatch(r"\{[0-9A-F-]{36}\}", product_code) is None
        or not isinstance(provenance["source_revision"], str)
        or re.fullmatch(r"[0-9a-f]{40}", provenance["source_revision"]) is None
        or not isinstance(provenance["initial_runtime_tree_sha256"], str)
        or re.fullmatch(r"[0-9a-f]{64}", provenance["initial_runtime_tree_sha256"]) is None
    ):
        return None
    cache_path = cache_root / f"msi-{package_hash}" / "EndpointAgent.msi"
    if not cache_path.is_file() or cache_path.is_symlink() or provenance_path.is_symlink():
        return None
    try:
        acl = PyWin32AclAdapter()
        acl.assert_protected_file(provenance_path)
        acl.assert_protected_file(cache_path)
        digest = hashlib.sha256()
        with cache_path.open("rb") as source:
            for block in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(block)
    except (OSError, WindowsAclError):
        return None
    if digest.hexdigest() != package_hash:
        return None
    return version if _installed_product_version(product_code) == version else None


def _msi_reconciliation_required(msi_path: Path) -> bool:
    """Version equality cannot prove the optional runtime feature or ownership."""
    from . import installation_provenance as provenance, msi_inventory
    from .installer_fence import state_root
    from endpoint_contracts.runtime_payload import read_json
    paths=WindowsUpdatePaths.production()
    try:
        release=json.loads(msi_path.with_name('EndpointAgent.release.json').read_text(encoding='utf-8'))
        expected=msi_inventory.read_expected_package(msi_path,release)
        if msi_inventory.installed_feature_state(expected.package)!='complete':
            return True
        authority=read_json(provenance._read(state_root(paths)/'foundation.json',4096),4096)
        if authority!={'schema_version':1,'release':release}:
            return True
        inspected=provenance.inspect_installed_core(paths,resulting_foundation=expected.package.version)
        if inspected.current is None:
            return True
        selector={'schema_version':1,'version':expected.identity.version,'source_revision':expected.identity.source_revision}
        candidate=provenance._inspect_core_value(paths,provenance._selector_bytes(expected.identity),selector,expected.package.version)
        return candidate.origin!='msi' or candidate.identity!=expected.identity
    except (OSError,ValueError,KeyError,TypeError):
        # The locked wrapper performs authoritative conflict/repair selection;
        # this read-only decision never authorizes an overwrite on its own.
        return True


def _is_strictly_newer_version(candidate: str, installed: str) -> bool:
    """Compare public SemVer installer releases without accepting malformed input."""
    candidate_match = _SEMVER.fullmatch(candidate)
    installed_match = _SEMVER.fullmatch(installed)
    if candidate_match is None or installed_match is None:
        return False
    candidate_core = tuple(
        int(candidate_match.group(name)) for name in ("major", "minor", "patch")
    )
    installed_core = tuple(
        int(installed_match.group(name)) for name in ("major", "minor", "patch")
    )
    if candidate_core != installed_core:
        return candidate_core > installed_core
    return (
        _compare_prerelease(candidate_match.group("pre"), installed_match.group("pre"))
        > 0
    )


def _compare_prerelease(candidate: str | None, installed: str | None) -> int:
    if candidate is None:
        return 0 if installed is None else 1
    if installed is None:
        return -1
    for left, right in zip(candidate.split("."), installed.split(".")):
        if left == right:
            continue
        if left.isdigit() and right.isdigit():
            return 1 if int(left) > int(right) else -1
        if left.isdigit():
            return -1
        if right.isdigit():
            return 1
        return 1 if left > right else -1
    return (len(candidate.split(".")) > len(installed.split("."))) - (
        len(candidate.split(".")) < len(installed.split("."))
    )


def _diagnostics_root() -> Path:
    """Keep installer results outside the agent's credential-protected directory."""
    program_data = os.environ.get("ProgramData", r"C:\ProgramData")
    return Path(program_data) / "Endpoint Platform" / "Installer"


def _classify_installation_state(
    data_root: Path, *, service_installed: bool = True
) -> Literal["clean", "valid", "repairable", "conflicted"]:
    """Fail closed before a rerun can overwrite enrollment-owned local state."""
    credential = data_root / "device-credential"
    identity = data_root / ENROLLMENT_IDENTITY_FILENAME
    if not credential.exists() and not identity.exists():
        return "clean"
    if not credential.is_file() or not identity.is_file():
        return "conflicted"
    try:
        read_device_credential(credential)
        read_enrollment_device_id(identity)
    except ValueError:
        return "conflicted"
    return "valid" if service_installed else "repairable"


def _agent_service_installed() -> bool:
    """Read the fixed service state without accepting a caller-controlled service name."""
    if os.name != "nt":
        return True
    executable = (
        Path(os.environ.get("SystemRoot", r"C:\\Windows")) / "System32" / "sc.exe"
    )
    try:
        completed = subprocess.run(
            [str(executable), "query", "EndpointAgent"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            shell=False,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return completed.returncode == 0


def _agent_service_running() -> bool:
    """Prove the fixed service has reached the Windows running state."""
    if os.name != "nt":
        return True
    try:
        import win32service  # type: ignore[import-not-found]
        import win32serviceutil  # type: ignore[import-not-found]
    except ImportError:
        return False
    try:
        status = win32serviceutil.QueryServiceStatus("EndpointAgent")
    except Exception:
        return False
    return status[1] == win32service.SERVICE_RUNNING


def _wait_for_agent_service_running(
    *, timeout_seconds: float = 30.0, poll_seconds: float = 0.5
) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while True:
        if _agent_service_running():
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(poll_seconds)


def _windowless_creation_flags() -> int:
    if os.name != "nt":
        return 0
    return int(getattr(subprocess, "CREATE_NO_WINDOW", 0))


def _write_install_log(
    path: Path, *, step: str, status: str, code: int, detail: str | None = None
) -> None:
    """Append bounded setup telemetry without accepting raw server or secret material."""
    if not (
        _SAFE_LOG_DETAIL.fullmatch(step)
        and _SAFE_LOG_DETAIL.fullmatch(status)
        and isinstance(code, int)
    ):
        raise ValueError("Windows Setup log fields are invalid")
    safe_detail = (
        detail if detail and _SAFE_LOG_DETAIL.fullmatch(detail) else "REDACTED"
    )
    line = (
        f"{datetime.now(UTC).isoformat()} step={step} status={status} "
        f"code={code} detail={safe_detail}\n"
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as target:
        target.write(line)


def _log_path(data_root: Path) -> Path:
    return data_root / "install.log"


def _result_path() -> Path:
    return _diagnostics_root() / _INSTALL_RESULT_FILENAME


def _prepare_diagnostics_root() -> Path:
    """Create a result directory that users may read but cannot modify."""
    root = _diagnostics_root()
    try:
        PyWin32AclAdapter().protect_operator_diagnostics(root)
    except WindowsAclError as error:
        raise OSError("installer diagnostics directory is unavailable") from error
    return root


def _write_install_result(
    *, status: str, code: int, stage: str, detail: str | None = None
) -> None:
    """Atomically persist an operator-readable, secret-free install outcome."""
    if not (
        _SAFE_LOG_DETAIL.fullmatch(status)
        and _SAFE_LOG_DETAIL.fullmatch(stage)
        and isinstance(code, int)
    ):
        raise ValueError("Windows Setup result fields are invalid")
    safe_detail = (
        detail if detail and _SAFE_LOG_DETAIL.fullmatch(detail) else "REDACTED"
    )
    path = _prepare_diagnostics_root() / _INSTALL_RESULT_FILENAME
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(
            {
                "schema_version": "endpoint_windows_install_result_v1",
                "status": status,
                "exit_code": code,
                "stage": stage,
                "detail": safe_detail,
                "updated_at": datetime.now(UTC).isoformat(),
            },
            separators=(",", ":"),
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    temporary.replace(path)


def _finish(
    data_root: Path,
    *,
    status: str,
    code: int,
    stage: str = "SETUP",
    detail: str | None = None,
) -> int:
    try:
        _write_install_result(status=status, code=code, stage=stage, detail=detail)
    except OSError:
        # A result-write failure must not hide the actual installer process result.
        pass
    try:
        _write_install_log(
            _log_path(data_root),
            step="SETUP",
            status=status,
            code=code,
            detail=detail,
        )
    except OSError:
        # A logging failure must not change an otherwise bounded installer result.
        pass
    return code


def _record_in_progress() -> None:
    try:
        _write_install_result(
            status="IN_PROGRESS", code=EXIT_SUCCESS, stage="SETUP", detail="STARTED"
        )
    except OSError:
        pass


def _show_result_dialog(status: str, code: int, detail: str) -> None:
    """Show a normal Windows result dialog without opening a console window."""
    if os.name != "nt":
        return
    if status in {"COMPLETED", "REPAIRED", "UPDATED", "ALREADY_INSTALLED"}:
        message = "Endpoint Agent установлен и служба EndpointAgent запущена."
        icon = 0x40  # MB_ICONINFORMATION
    elif status in {"WAITING_APPROVAL", "REVIEW_REQUIRED"}:
        message = "Установка ожидает решения администратора."
        icon = 0x30  # MB_ICONWARNING
    else:
        message = "Установка Endpoint Agent не завершена."
        icon = 0x10  # MB_ICONERROR
    message += f"\n\nКод: {code}\nПричина: {detail}\nРезультат: {_result_path()}"
    try:
        import ctypes

        ctypes.windll.user32.MessageBoxW(None, message, "Endpoint Agent Setup", icon)
    except Exception:
        # The persisted result and exit code remain the authoritative diagnostics.
        pass


def _complete(
    args: argparse.Namespace,
    data_root: Path,
    *,
    status: str,
    code: int,
    stage: str = "SETUP",
    detail: str | None = None,
) -> int:
    safe_detail = (
        detail if detail and _SAFE_LOG_DETAIL.fullmatch(detail) else "REDACTED"
    )
    result = _finish(
        data_root, status=status, code=code, stage=stage, detail=safe_detail
    )
    if not args.quiet:
        _show_result_dialog(status, code, safe_detail)
    return result


def _inventory() -> dict[str, object]:
    return {"hostname": socket.gethostname(), "macs": []}


def _provisioner_command(
    executable: Path, config: SetupConfig, data_dir: Path, installation_id: str
) -> list[str]:
    return [
        str(executable),
        "--endpoint-origin",
        config.endpoint_origin,
        "--ca-file",
        str(config.ca_file),
        "--data-dir",
        str(data_dir),
        "--installation-id",
        installation_id,
    ]


def _provisioner_failure_detail(stdout: str, stderr: str) -> str:
    """Return a bounded child failure class, never its untrusted output."""
    for line in (stderr + "\n" + stdout).splitlines():
        match = _PROVISIONER_ERROR.fullmatch(line.strip())
        if match:
            return f"PROVISIONER_{match.group(1).upper()}"
    return "PROVISIONER_EXIT_NONZERO"


def _run_provisioner(
    executable: Path,
    config: SetupConfig,
    data_dir: Path,
    installation_id: str,
    claim: str,
    *,
    run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> None:
    try:
        completed = run(
            _provisioner_command(executable, config, data_dir, installation_id),
            input=claim + "\n",
            text=True,
            capture_output=True,
            check=False,
            shell=False,
            creationflags=_windowless_creation_flags(),
        )
    except OSError as error:
        raise SetupProvisionError(
            "Windows provisioning failed", detail="PROVISIONER_START_FAILED"
        ) from error
    if completed.returncode != 0:
        raise SetupProvisionError(
            "Windows provisioning failed",
            detail=_provisioner_failure_detail(
                str(completed.stdout or ""), str(completed.stderr or "")
            ),
        )


def _write_inherited_stdout(value: bytes, *, kernel=None) -> None:
    """Windowed PyInstaller has no sys.stdout; use only its inherited pipe."""
    kernel = kernel or ctypes.WinDLL("kernel32", use_last_error=True)
    query = kernel.GetStdHandle
    query.argtypes = [wintypes.DWORD]
    query.restype = wintypes.HANDLE
    handle = query(wintypes.DWORD(-11).value)
    if handle in (None, 0, -1, wintypes.HANDLE(-1).value):
        raise OSError("PREFLIGHT_STDOUT_UNAVAILABLE")
    write = kernel.WriteFile
    write.argtypes = [
        wintypes.HANDLE,
        wintypes.LPCVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID,
    ]
    write.restype = wintypes.BOOL
    buffer = ctypes.create_string_buffer(value)
    count = wintypes.DWORD()
    if not write(
        handle, buffer, len(value), ctypes.byref(count), None
    ) or count.value != len(value):
        raise OSError("PREFLIGHT_STDOUT_WRITE_FAILED")


def _emit_preflight(value: dict[str, object]) -> None:
    from pc_agent.platform.windows.fleet_preflight import MAX_PREFLIGHT_BYTES

    record = json.dumps(value, separators=(",", ":"), sort_keys=True) + "\n"
    encoded = record.encode("utf-8")
    if len(encoded) > MAX_PREFLIGHT_BYTES:
        raise ValueError("PREFLIGHT_BOUND_EXCEEDED")
    if sys.stdout is None:
        _write_inherited_stdout(encoded)
    else:
        sys.stdout.write(record)
        sys.stdout.flush()


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.preflight:
        from pc_agent.platform.windows.fleet_preflight import collect_fleet_preflight

        try:
            config = _read_public_setup_config(_resource_root() / "setup-config.json")
            result = collect_fleet_preflight(
                WindowsUpdatePaths.production(), config["installer_version"],
                setup_package=_resource_root()/"EndpointAgent.msi"
            )
            _emit_preflight(result)
            return EXIT_SUCCESS
        except Exception:
            try:
                _emit_preflight({"error": "PREFLIGHT_UNAVAILABLE"})
            except (OSError, ValueError):
                pass
            return EXIT_PREFLIGHT_FAILED
    data_root = _data_root()
    _record_in_progress()
    interrupted_setup = False
    try:
        paths = WindowsUpdatePaths(
            pending_path=data_root / "updates" / "pending_update.json"
        )
        with update_transaction(paths, timeout_ms=0):
            if active_update_state(paths) is not None:
                raise UpdateInProgress("UPDATE_IN_PROGRESS")
    except UpdateInProgress as error:
        if str(error) == 'INSTALLER_RECOVERY_REQUIRED':
            # This only permits reading the embedded package and dispatching
            # its owner wrapper. It grants no mutation/fence-bypass scope.
            interrupted_setup = True
        else:
            return _complete(args, data_root, status="UPDATE_IN_PROGRESS", code=EXIT_UPDATE_IN_PROGRESS,
                stage="PREFLIGHT", detail="UPDATE_IN_PROGRESS")
    except (OSError, ValueError):
        return _complete(args, data_root, status="REPAIR_REQUIRED", code=EXIT_REPAIR_REQUIRED,
            stage="PREFLIGHT", detail="UPDATE_STATE_INVALID")
    installation_state = _classify_installation_state(
        data_root, service_installed=_agent_service_installed()
    )
    if installation_state == "conflicted":
        return _complete(
            args,
            data_root,
            status="REPAIR_REQUIRED",
            code=EXIT_REPAIR_REQUIRED,
            stage="SETUP",
            detail="LOCAL_STATE_CONFLICT",
        )
    resources = _resource_root()
    try:
        public_config = _read_public_setup_config(resources / "setup-config.json")
        config = SetupConfig(
            endpoint_origin=public_config["endpoint_origin"],
            ca_file=resources / "endpoint-ca.crt",
            installer_version=public_config["installer_version"],
            installer_release_id=public_config["installer_release_id"],
        )
        config.validate()
    except Exception:
        return _complete(
            args,
            data_root,
            status="PREFLIGHT_FAILED",
            code=EXIT_PREFLIGHT_FAILED,
            stage="PREFLIGHT",
            detail="PREFLIGHT_INVALID",
        )
    try:
        _verify_embedded_msi(resources / "EndpointAgent.msi")
        recovery_operation = _embedded_recovery_operation(resources / "EndpointAgent.msi")
        installed_version = _installed_msi_version() if installation_state == "valid" else None
        needs_msi = interrupted_setup or recovery_operation is not None or installation_state != "valid" or installed_version is None or _is_strictly_newer_version(
            config.installer_version, installed_version
        ) or (installed_version == config.installer_version and _msi_reconciliation_required(resources / "EndpointAgent.msi"))
        if needs_msi:
            _require_setup_disk(resources / "EndpointAgent.msi")
    except DiskInsufficient:
        return _complete(args, data_root, status="DISK_INSUFFICIENT", code=EXIT_PREFLIGHT_FAILED,
            stage="PREFLIGHT", detail="DISK_INSUFFICIENT")
    except SetupInstallError as error:
        return _complete(
            args, data_root, status="PREFLIGHT_FAILED", code=EXIT_PREFLIGHT_FAILED,
            stage="PREFLIGHT", detail=error.detail,
        )
    except OSError as error:
        detail = "DISK_INSUFFICIENT" if is_disk_full(error) else "DISK_UNAVAILABLE"
        return _complete(
            args, data_root, status=detail if is_disk_full(error) else "PREFLIGHT_FAILED",
            code=EXIT_PREFLIGHT_FAILED, stage="PREFLIGHT", detail=detail,
        )
    if installation_state == "valid":
        if needs_msi:
            _finish(
                data_root,
                status="STARTED",
                code=EXIT_SUCCESS,
                stage="MSI",
                detail="STARTED",
            )
            try:
                native_result = _install_embedded_msi(resources / "EndpointAgent.msi")
                if native_result in (3010,1641):
                    return _complete(args,data_root,status='REBOOT_REQUIRED',code=native_result,stage='MSI',detail='REBOOT_REQUIRED')
                if recovery_operation == 'uninstall':
                    return _complete(args,data_root,status='UNINSTALLED',code=EXIT_SUCCESS,stage='MSI',detail='UNINSTALLED')
            except SetupInstallError as error:
                return _complete(
                    args,
                    data_root,
                    status=("UPDATE_IN_PROGRESS" if error.detail == "UPDATE_IN_PROGRESS" else "REPAIR_REQUIRED" if error.detail == "UPDATE_STATE_INVALID" else "INSTALL_FAILED"),
                    code=(EXIT_UPDATE_IN_PROGRESS if error.detail == "UPDATE_IN_PROGRESS" else EXIT_REPAIR_REQUIRED if error.detail == "UPDATE_STATE_INVALID" else EXIT_INSTALL_FAILED),
                    stage="MSI",
                    detail=error.detail,
                )
            except Exception:
                return _complete(
                    args,
                    data_root,
                    status="INSTALL_FAILED",
                    code=EXIT_INSTALL_FAILED,
                    stage="MSI",
                    detail="MSI_INSTALL_FAILED",
                )
            if not _wait_for_agent_service_running():
                return _complete(
                    args,
                    data_root,
                    status="SERVICE_FAILED",
                    code=EXIT_SERVICE_FAILED,
                    stage="SERVICE",
                    detail="SERVICE_NOT_RUNNING",
                )
            detail = _service_ready_detail()
            return _complete(
                args,
                data_root,
                status="UPDATED",
                code=EXIT_SUCCESS,
                stage="SERVICE",
                detail=detail,
            )
        if not _wait_for_agent_service_running():
            return _complete(
                args,
                data_root,
                status="SERVICE_FAILED",
                code=EXIT_SERVICE_FAILED,
                stage="SERVICE",
                detail="SERVICE_NOT_RUNNING",
            )
        return _complete(
            args,
            data_root,
            status="ALREADY_INSTALLED",
            code=EXIT_ALREADY_INSTALLED,
            stage="SERVICE",
            detail="SERVICE_RUNNING",
        )
    _finish(
        data_root, status="STARTED", code=EXIT_SUCCESS, stage="MSI", detail="STARTED"
    )
    try:
        native_result = _install_embedded_msi(resources / "EndpointAgent.msi")
        if native_result in (3010,1641):
            return _complete(args,data_root,status='REBOOT_REQUIRED',code=native_result,stage='MSI',detail='REBOOT_REQUIRED')
        if recovery_operation == 'uninstall':
            return _complete(args,data_root,status='UNINSTALLED',code=EXIT_SUCCESS,stage='MSI',detail='UNINSTALLED')
        if installation_state == "repairable":
            if not _wait_for_agent_service_running():
                return _complete(
                    args,
                    data_root,
                    status="SERVICE_FAILED",
                    code=EXIT_SERVICE_FAILED,
                    stage="SERVICE",
                    detail="SERVICE_NOT_RUNNING",
                )
            detail = _service_ready_detail()
            return _complete(
                args,
                data_root,
                status="REPAIRED",
                code=EXIT_ALREADY_INSTALLED,
                stage="SERVICE",
                detail=detail,
            )
        provisioner = _installed_provisioner()
    except SetupInstallError as error:
        return _complete(
            args,
            data_root,
            status=("UPDATE_IN_PROGRESS" if error.detail == "UPDATE_IN_PROGRESS" else "REPAIR_REQUIRED" if error.detail == "UPDATE_STATE_INVALID" else "INSTALL_FAILED"),
            code=(EXIT_UPDATE_IN_PROGRESS if error.detail == "UPDATE_IN_PROGRESS" else EXIT_REPAIR_REQUIRED if error.detail == "UPDATE_STATE_INVALID" else EXIT_INSTALL_FAILED),
            stage="MSI",
            detail=error.detail,
        )
    except Exception:
        return _complete(
            args,
            data_root,
            status="INSTALL_FAILED",
            code=EXIT_INSTALL_FAILED,
            stage="MSI",
            detail="MSI_INSTALL_FAILED",
        )

    transport = HttpsSetupTransport(config.endpoint_origin, config.ca_file)
    installation_id: str | None = None

    def run_provisioner(claim: str) -> None:
        if installation_id is None:
            raise RuntimeError("installation identity unavailable")
        _run_provisioner(provisioner, config, _data_root(), installation_id, claim)

    setup = UniversalWindowsSetup(
        config,
        transport=transport,
        provision_claim=run_provisioner,
        fingerprint_probe=lambda: _derive_hardware_fingerprint(
            collect_device_fingerprint
        ),
        inventory_probe=_inventory,
        clock=lambda: datetime.now(UTC),
    )
    original_installation_factory = setup.installation_id_factory

    def capture_installation_id() -> str:
        nonlocal installation_id
        installation_id = original_installation_factory()
        return installation_id

    setup.installation_id_factory = capture_installation_id
    try:
        outcome = setup.run()
    except SetupClaimError:
        return _complete(
            args,
            data_root,
            status="CLAIM_FAILED",
            code=EXIT_CLAIM_FAILED,
            stage="ENROLLMENT",
            detail="CLAIM_FAILED",
        )
    except SetupProvisionError as error:
        return _complete(
            args,
            data_root,
            status="PROVISIONING_FAILED",
            code=EXIT_PROVISIONING_FAILED,
            stage="PROVISIONING",
            detail=error.detail,
        )
    except Exception:
        return _complete(
            args,
            data_root,
            status="PROVISIONING_FAILED",
            code=EXIT_PROVISIONING_FAILED,
            stage="PROVISIONING",
            detail="PROVISIONING_UNEXPECTED",
        )
    if outcome.status == "provisioned":
        if not _wait_for_agent_service_running():
            return _complete(
                args,
                data_root,
                status="SERVICE_FAILED",
                code=EXIT_SERVICE_FAILED,
                stage="SERVICE",
                detail="SERVICE_NOT_RUNNING",
            )
        detail = _service_ready_detail()
        return _complete(
            args,
            data_root,
            status="COMPLETED",
            code=EXIT_SUCCESS,
            stage="SERVICE",
            detail=detail,
        )
    exit_code = {
        "denied": EXIT_ENROLLMENT_DENIED,
        "timed_out": (
            EXIT_WSS_TIMEOUT
            if outcome.reason == "WAITING_WSS"
            else EXIT_CONTEXT_TIMEOUT
            if outcome.reason == "WAITING_CONTEXT"
            else EXIT_APPROVAL_TIMEOUT
        ),
        "waiting_approval": EXIT_APPROVAL_TIMEOUT,
        "review_required": EXIT_REVIEW_REQUIRED,
        "expired": EXIT_REQUEST_EXPIRED,
    }[outcome.status]
    return _complete(
        args,
        data_root,
        status=outcome.status.upper(),
        code=exit_code,
        stage="ENROLLMENT",
        detail=outcome.reason,
    )


if __name__ == "__main__":
    raise SystemExit(main())
