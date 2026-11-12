"""One-time Windows enrollment provisioning without command-line claims."""

from __future__ import annotations

import argparse
import asyncio
import io
import ipaddress
import json
import os
import re
import secrets
import ssl
import sys
import tempfile
from contextlib import AbstractContextManager, nullcontext
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Callable, Protocol, Sequence, TextIO
from urllib.parse import urlsplit
from uuid import UUID

from endpoint_contracts import AgentEnrollmentRequestV1
from pc_agent.core.device_fingerprint import collect_device_fingerprint
from pc_agent.device_credential import read_device_credential
from pc_agent.enrollment_bootstrap import (
    HttpsEnrollmentTransport,
    _derive_hardware_fingerprint,
)
from pc_agent.enrollment_identity import (
    ENROLLMENT_IDENTITY_FILENAME,
    canonical_enrollment_device_id,
    read_enrollment_device_id,
    serialize_enrollment_identity,
)

from .acl import AclAdapter, PyWin32AclAdapter
from . import installer_stdio
from .inventory_setup import INVENTORY_PREFIX, STAGING_ORIGIN, valid_installation_id
from .service_control import PyWin32ServiceControl, ServiceControl
from .update_paths import WindowsUpdatePaths
from .update_transaction import update_transaction


CLAIM_FILENAME = "enrollment-claim"
CREDENTIAL_FILENAME = "device-credential"
ENDPOINT_CA_FILENAME = "endpoint-ca.crt"
ENDPOINT_ORIGIN_FILENAME = "endpoint-origin"
MAX_CLAIM_BYTES = 4096


@dataclass(frozen=True, slots=True)
class EnrollmentDelivery:
    """A server enrollment response; the bearer is intentionally non-repr."""

    device_id: UUID
    device_token: str = field(repr=False)


class EnrollmentClient(Protocol):
    def enroll(
        self, *, claim: str, endpoint_origin: str, ca_file: Path
    ) -> EnrollmentDelivery: ...


@dataclass(frozen=True, slots=True)
class ProvisioningRequest:
    endpoint_origin: str
    ca_file: Path
    data_root: Path
    installation_id: str = "windows-provisioning"

    def validate(self) -> None:
        if not isinstance(self.installation_id, str) or not self.installation_id or len(self.installation_id) > 128:
            raise ValueError("installation identifier is invalid")
        if self.installation_id.startswith(INVENTORY_PREFIX) and (
            self.endpoint_origin != STAGING_ORIGIN or not valid_installation_id(self.installation_id)
        ):
            raise ValueError("inventory enrollment is ineligible")
        parsed = urlsplit(self.endpoint_origin)
        try:
            port = parsed.port
        except ValueError as error:
            raise ValueError("Endpoint origin must be an absolute HTTPS origin") from error
        if (
            parsed.scheme != "https"
            or not _valid_endpoint_host(parsed.hostname)
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
            or (port is not None and not 1 <= port <= 65535)
        ):
            raise ValueError("Endpoint origin must be an absolute HTTPS origin")
        try:
            if not self.ca_file.is_file() or not self.ca_file.read_bytes().strip():
                raise ValueError
            ssl.create_default_context(cafile=str(self.ca_file))
        except (OSError, ssl.SSLError, ValueError) as error:
            raise ValueError("Endpoint CA file is missing or invalid") from error


def _valid_endpoint_host(hostname: str | None) -> bool:
    if not hostname or len(hostname) > 253 or "%" in hostname:
        return False
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        pass
    labels = hostname.split(".")
    return bool(labels) and all(
        re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
        for label in labels
    )


@dataclass(frozen=True, slots=True)
class ProvisioningResult:
    device_id: UUID
    claim_removed: bool
    support_access_status: str = 'unavailable'
    support_access_error: str | None = None


# Only fixed component codes may leave its process boundary. Never forward
# exception strings, stderr, paths, enrollment identity or bearer material.
_SUPPORT_ERROR_CODES = frozenset({
    'support_not_installed','support_install_failed','support_dependency_install_failed',
    'support_dependency_reboot_required','support_process_identity_unavailable',
    'support_process_exit_timeout','support_dependency_firewall_conflict',
    'support_dependency_signature_invalid','support_dependency_changed',
    'support_identity_conflict','support_key_role_conflict','support_key_generation_failed',
    'support_key_read_failed','support_enrollment_unavailable','unsafe_support_acl',
    'unsafe_support_path','invalid_support_origin','support_signature_invalid',
    'support_payload_recovery_required','support_service_not_ready','support_install_busy',
    'support_bundle_invalid','support_bundle_signature_invalid','support_dependency_migration_unsupported'})
_SUPPORT_ERROR_CODES = _SUPPORT_ERROR_CODES | {'support_dependency_recovery_required'}


def safe_support_error_code(value) -> str:
    return value if isinstance(value,str) and value in _SUPPORT_ERROR_CODES else 'support_install_failed'


def install_enrolled_support(data_root: Path) -> dict:
    """Activate the MSI-owned staged helper after enrollment/native acceptance.

    No bearer/claim is passed through arguments. Component readiness is separate
    from enrollment/native success; a missing optional dependency cannot replay
    enrollment or falsify the accepted MSI receipt.
    """
    import json
    import subprocess
    from .update_paths import _native_folder
    expected = _native_folder(0x23)/'Endpoint Platform'/'Agent'
    if Path(data_root).resolve() != expected.resolve():
        return {'installed':False,'error':'support_not_installed'}
    executable = _native_folder(0x26)/'Endpoint Platform'/'Agent'/'EndpointSupportAccess.exe'
    if not executable.is_file():
        return {'installed':False,'error':'support_not_installed'}
    try:
        result = subprocess.run([str(executable),'--install'],shell=False,capture_output=True,
            text=True,timeout=660,creationflags=subprocess.CREATE_NO_WINDOW)
        if not isinstance(result.stdout,str) or len(result.stdout.encode('utf-8'))>4096:
            return {'installed':False,'error':'support_install_failed'}
        value = json.loads(result.stdout)
        if result.returncode==0 and value.get('installed') is True:
            return {'installed':True}
        return {'installed':False,'error':safe_support_error_code(value.get('error'))}
    except Exception:
        return {'installed':False,'error':'support_install_failed'}


class HttpsWindowsEnrollmentClient:
    """Use the existing fixed Endpoint HTTPS enrollment transport."""

    def __init__(self, installation_id: str) -> None:
        self._installation_id = installation_id

    def enroll(
        self, *, claim: str, endpoint_origin: str, ca_file: Path
    ) -> EnrollmentDelivery:
        request = AgentEnrollmentRequestV1(
            schema_version="agent_enrollment_request_v1",
            platform="windows",
            hardware_fingerprint=_derive_hardware_fingerprint(
                collect_device_fingerprint
            ),
            installation_id=self._installation_id,
            delivery_nonce=secrets.token_urlsafe(32),
            requested_at=datetime.now(UTC),
        ).model_dump(mode="json")
        transport = (
            HttpsEnrollmentTransport(allow_redirects=False)
            if self._installation_id.startswith(INVENTORY_PREFIX)
            else HttpsEnrollmentTransport()
        )
        delivery = asyncio.run(
            transport.enroll(
                endpoint_url=endpoint_origin,
                ca_file=ca_file,
                claim=claim,
                request=request,
            )
        )
        return EnrollmentDelivery(delivery.device_id, delivery.device_token)


class WindowsProvisioner:
    """Persist and prove Windows enrollment state before consuming its claim."""

    def __init__(
        self,
        request: ProvisioningRequest,
        *,
        enrollment: EnrollmentClient | None = None,
        service: ServiceControl | None = None,
        acl: AclAdapter | None = None,
        support_installer: Callable[[], dict] | None = None,
        mutation_scope: Callable[[], AbstractContextManager[None]] = nullcontext,
    ) -> None:
        self._request = request
        self._mutation_scope = mutation_scope
        self._enrollment = enrollment or HttpsWindowsEnrollmentClient(
            request.installation_id
        )
        self._service = service or PyWin32ServiceControl()
        self._acl = acl or PyWin32AclAdapter()
        self._support_installer = support_installer or (lambda: install_enrolled_support(self._request.data_root))

    def provision_from_stdin(self, stream: TextIO | None = None) -> ProvisioningResult:
        source = sys.stdin if stream is None else stream
        raw = installer_stdio.read_inherited_pipe(MAX_CLAIM_BYTES) if source is None else source.read(MAX_CLAIM_BYTES + 1)
        return self._provision(_claim_from_text(raw))

    def provision_from_protected_file(self, path: Path) -> ProvisioningResult:
        source = Path(path)
        attributes = getattr(source.lstat(), "st_file_attributes", 0)
        if source.is_symlink() or attributes & 0x400:
            raise ValueError("protected enrollment material must not be a reparse point")
        self._acl.assert_protected_file(source)
        try:
            raw = source.read_text(encoding="ascii")
        except (OSError, UnicodeDecodeError) as error:
            raise ValueError("protected enrollment material is unreadable") from error
        return self._provision(_claim_from_text(raw))

    def _provision(self, claim: str) -> ProvisioningResult:
        self._request.validate()
        data_root = self._request.data_root
        claim_path = data_root / CLAIM_FILENAME
        credential_path = data_root / CREDENTIAL_FILENAME
        identity_path = data_root / ENROLLMENT_IDENTITY_FILENAME
        installed_ca_path = data_root / ENDPOINT_CA_FILENAME
        endpoint_origin_path = data_root / ENDPOINT_ORIGIN_FILENAME
        with self._mutation_scope():
            if os.path.lexists(credential_path) or os.path.lexists(identity_path):
                raise ValueError("an enrollment already exists")
            if valid_installation_id(self._request.installation_id) and (
                os.path.lexists(claim_path) or os.path.lexists(endpoint_origin_path)
            ):
                raise ValueError("an unfinished enrollment already exists")
            self._acl.protect_directory(data_root)
            _atomic_write(claim_path, claim.encode("ascii"))
            self._acl.protect_claim(claim_path)
            delivery = self._enrollment.enroll(
                claim=claim,
                endpoint_origin=self._request.endpoint_origin,
                ca_file=self._request.ca_file,
            )
            device_id = canonical_enrollment_device_id(delivery.device_id)
            token = _credential_bytes(delivery.device_token)
            _atomic_write(installed_ca_path, self._request.ca_file.read_bytes())
            self._acl.protect_credential(installed_ca_path)
            _atomic_write(
                endpoint_origin_path, (self._request.endpoint_origin + "\n").encode("ascii")
            )
            self._acl.protect_credential(endpoint_origin_path)
            _atomic_write(credential_path, token)
            self._acl.protect_credential(credential_path)
            _atomic_write(identity_path, serialize_enrollment_identity(device_id))
            # The claim remains intact unless both durable records can be read back.
            if (
                read_device_credential(credential_path) != delivery.device_token
                or read_enrollment_device_id(identity_path) != device_id
            ):
                raise RuntimeError("permanent enrollment credential proof failed")
        try:
            from .installation_notification import sync_enrolled_installation
            if sync_enrolled_installation(data_root) not in {'delivered', 'not_applicable'}:
                raise RuntimeError('installation_event_pending')
            support = self._support_installer()
            support_status = 'installed' if support.get('installed') is True else 'unavailable'
            support_error = None if support_status=='installed' else safe_support_error_code(support.get('error'))
        except Exception:
            support_status = 'unavailable'
            support_error = 'support_install_failed'
        self._service.start()
        claim_path.unlink()
        _flush_directory(data_root)
        return ProvisioningResult(device_id=device_id, claim_removed=True,support_access_status=support_status,
            support_access_error=support_error)


def _claim_from_text(raw: str) -> str:
    claim = raw.strip()
    if (
        not claim
        or len(raw.encode("utf-8")) > MAX_CLAIM_BYTES
        or not claim.isascii()
        or any(ord(character) < 33 or ord(character) > 126 for character in claim)
    ):
        raise ValueError("enrollment material is invalid")
    return claim


def _credential_bytes(token: str) -> bytes:
    encoded = token.encode("ascii")
    if read_device_credential_from_bytes(encoded) != token:
        raise ValueError("enrollment response credential is invalid")
    return encoded


def read_device_credential_from_bytes(value: bytes) -> str:
    """Validate a bearer without persisting or printing it during response parsing."""
    if len(value) != 43 or not all(
        chr(item).isalnum() or chr(item) in "_-" for item in value
    ):
        raise ValueError("invalid device credential")
    return value.decode("ascii")


def _atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        _flush_directory(path.parent)
    finally:
        if temporary.exists():
            temporary.unlink()


def _flush_directory(path: Path) -> None:
    """Persist rename/unlink metadata before irreversible claim consumption."""
    if os.name == "nt":
        try:
            import win32con  # type: ignore[import-not-found]
            import win32file  # type: ignore[import-not-found]
        except ImportError as error:
            raise OSError("pywin32 is required for Windows directory durability") from error
        handle = win32file.CreateFile(
            str(path),
            win32con.GENERIC_READ | win32con.GENERIC_WRITE,
            win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
            None,
            win32con.OPEN_EXISTING,
            win32con.FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
        try:
            win32file.FlushFileBuffers(handle)
        finally:
            handle.Close()
        return
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="endpoint-agent-provision.exe")
    parser.add_argument("--endpoint-origin", required=True)
    parser.add_argument("--ca-file", required=True)
    parser.add_argument("--data-dir", required=True)
    identity = parser.add_mutually_exclusive_group(required=True)
    identity.add_argument("--installation-id")
    identity.add_argument("--inventory-stdin", action="store_true")
    parser.add_argument("--material-file")
    return parser


def _read_inventory_material() -> tuple[str, str]:
    max_bytes = MAX_CLAIM_BYTES + 256
    raw = installer_stdio.read_inherited_pipe(max_bytes) if sys.stdin is None else sys.stdin.read(max_bytes + 1)
    if len(raw) > max_bytes or not raw.isascii():
        raise ValueError("invalid inventory enrollment material")
    payload = json.loads(raw)
    if (
        not isinstance(payload, dict)
        or payload.keys() != {"installation_id", "claim"}
        or not valid_installation_id(payload["installation_id"])
        or not isinstance(payload["claim"], str)
        or not payload["claim"].startswith("ic_")
    ):
        raise ValueError("invalid inventory enrollment material")
    return payload["installation_id"], _claim_from_text(payload["claim"])


def _report_provisioning(message: str, *, error: bool = False) -> None:
    stream = sys.stderr if error else sys.stdout
    if stream is not None:
        print(message, file=stream)
    else:
        try:
            installer_stdio.write_inherited_pipe((message + "\n").encode("ascii"), handle_number=-12 if error else -11)
        except OSError:
            pass


def main(argv: Sequence[str] | None = None) -> int:
    from pc_agent.platform.windows.installation_notification import notification_main
    notification = notification_main(argv)
    if notification is not None:
        return notification
    args = _parser().parse_args(argv)
    try:
        installation_id = args.installation_id
        inventory_claim = None
        if args.inventory_stdin:
            if args.endpoint_origin != STAGING_ORIGIN or args.material_file:
                raise ValueError("inventory enrollment is ineligible")
            installation_id, inventory_claim = _read_inventory_material()
        elif installation_id.startswith(INVENTORY_PREFIX):
            raise ValueError("inventory enrollment material requires stdin")
        request = ProvisioningRequest(
            endpoint_origin=args.endpoint_origin,
            ca_file=Path(args.ca_file),
            data_root=Path(args.data_dir),
            installation_id=installation_id,
        )
        paths = WindowsUpdatePaths(pending_path=request.data_root / "updates" / "pending_update.json")
        provisioner = WindowsProvisioner(request, mutation_scope=lambda: update_transaction(paths))
        if inventory_claim is not None:
            result = provisioner.provision_from_stdin(io.StringIO(inventory_claim))
        elif args.material_file:
            result = provisioner.provision_from_protected_file(Path(args.material_file))
        else:
            result = provisioner.provision_from_stdin()
    except Exception as error:
        # Keep diagnostics bounded to a class name: transport and filesystem
        # exceptions may otherwise contain claims, tokens, or local paths.
        _report_provisioning(f"Windows provisioning failed: {type(error).__name__}", error=True)
        return 1
    _report_provisioning(json.dumps({
        "support_access_status": result.support_access_status,
        "support_access_error": result.support_access_error,
    }))
    return 0


__all__ = [
    "EnrollmentDelivery",
    "HttpsWindowsEnrollmentClient",
    "ProvisioningRequest",
    "ProvisioningResult",
    "WindowsProvisioner",
    "main",
]
