"""Standalone universal Windows Setup entrypoint."""

from __future__ import annotations

import argparse
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

from pc_agent.core.device_fingerprint import collect_device_fingerprint
from pc_agent.device_credential import read_device_credential
from pc_agent.enrollment_bootstrap import _derive_hardware_fingerprint
from pc_agent.enrollment_identity import (
    ENROLLMENT_IDENTITY_FILENAME,
    read_enrollment_device_id,
)
from pc_agent.platform.windows.acl import PyWin32AclAdapter, WindowsAclError
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


def _install_embedded_msi(msi_path: Path) -> None:
    if not msi_path.is_file():
        raise SetupInstallError("MSI_UNAVAILABLE")
    completed = subprocess.run(
        ["msiexec.exe", "/i", str(msi_path), "/qn", "/norestart"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        shell=False,
        creationflags=_windowless_creation_flags(),
    )
    if completed.returncode not in {0, 3010}:
        raise SetupInstallError(f"MSI_EXIT_{completed.returncode}")


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


def _is_interactive_windows_session() -> bool:
    """Avoid creating a session-0 tray process during service/SYSTEM deployments."""
    if os.name != "nt":
        return False
    session_name = os.environ.get("SESSIONNAME", "")
    username = os.environ.get("USERNAME", "")
    return (
        bool(session_name)
        and session_name.casefold() != "services"
        and username.casefold() != "system"
    )


def _restart_tray_companion() -> bool:
    """Restore the user-visible tray after MSI safely stopped it for an update."""
    if not _is_interactive_windows_session():
        return False
    try:
        subprocess.Popen(  # noqa: S603 - fixed, installed executable only
            [str(_installed_tray_companion())],
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


def _service_ready_detail() -> str:
    """Keep a successful non-interactive deployment distinct from a tray launch fault."""
    if not _is_interactive_windows_session():
        return "SERVICE_RUNNING"
    return (
        "SERVICE_RUNNING"
        if _restart_tray_companion()
        else "SERVICE_RUNNING_TRAY_START_FAILED"
    )


def _data_root() -> Path:
    program_data = os.environ.get("ProgramData", r"C:\ProgramData")
    return Path(program_data) / "Endpoint Platform" / "Agent"


def _installed_runtime_version() -> str | None:
    """Read the fixed selector version without treating arbitrary files as state."""
    program_files = os.environ.get("ProgramW6432") or os.environ.get("ProgramFiles")
    if not program_files:
        return None
    path = Path(program_files) / "Endpoint Platform" / "Agent" / "current.json"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict) or set(payload) not in (
        {"version"},
        {"schema_version", "source_revision", "version"},
    ):
        return None
    version = payload.get("version")
    return version if isinstance(version, str) and _SEMVER.fullmatch(version) else None


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


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    data_root = _data_root()
    _record_in_progress()
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
    if installation_state == "valid":
        installed_version = _installed_runtime_version()
        if installed_version is None:
            return _complete(
                args,
                data_root,
                status="REPAIR_REQUIRED",
                code=EXIT_REPAIR_REQUIRED,
                stage="SETUP",
                detail="LOCAL_RUNTIME_CONFLICT",
            )
        if _is_strictly_newer_version(config.installer_version, installed_version):
            _finish(
                data_root,
                status="STARTED",
                code=EXIT_SUCCESS,
                stage="MSI",
                detail="STARTED",
            )
            try:
                _install_embedded_msi(resources / "EndpointAgent.msi")
            except SetupInstallError as error:
                return _complete(
                    args,
                    data_root,
                    status="INSTALL_FAILED",
                    code=EXIT_INSTALL_FAILED,
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
    transport = HttpsSetupTransport(config.endpoint_origin, config.ca_file)
    _finish(
        data_root, status="STARTED", code=EXIT_SUCCESS, stage="MSI", detail="STARTED"
    )
    try:
        _install_embedded_msi(resources / "EndpointAgent.msi")
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
            status="INSTALL_FAILED",
            code=EXIT_INSTALL_FAILED,
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
