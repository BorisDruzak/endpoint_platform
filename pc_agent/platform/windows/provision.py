"""One-time Windows enrollment provisioning without command-line claims."""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import os
import re
import secrets
import ssl
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol, Sequence, TextIO
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
from .service_control import PyWin32ServiceControl, ServiceControl


CLAIM_FILENAME = "enrollment-claim"
CREDENTIAL_FILENAME = "device-credential"
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
        if not self.installation_id or len(self.installation_id) > 128:
            raise ValueError("installation identifier is invalid")


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
        delivery = asyncio.run(
            HttpsEnrollmentTransport().enroll(
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
    ) -> None:
        self._request = request
        self._enrollment = enrollment or HttpsWindowsEnrollmentClient(
            request.installation_id
        )
        self._service = service or PyWin32ServiceControl()
        self._acl = acl or PyWin32AclAdapter()

    def provision_from_stdin(self, stream: TextIO | None = None) -> ProvisioningResult:
        raw = (sys.stdin if stream is None else stream).read(MAX_CLAIM_BYTES + 1)
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
        _atomic_write(credential_path, token)
        self._acl.protect_credential(credential_path)
        _atomic_write(identity_path, serialize_enrollment_identity(device_id))
        # The claim remains intact unless both durable records can be read back.
        if (
            read_device_credential(credential_path) != delivery.device_token
            or read_enrollment_device_id(identity_path) != device_id
        ):
            raise RuntimeError("permanent enrollment credential proof failed")
        self._service.start()
        claim_path.unlink()
        _flush_directory(data_root)
        return ProvisioningResult(device_id=device_id, claim_removed=True)


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
    parser.add_argument("--installation-id", required=True)
    parser.add_argument("--material-file")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    request = ProvisioningRequest(
        endpoint_origin=args.endpoint_origin,
        ca_file=Path(args.ca_file),
        data_root=Path(args.data_dir),
        installation_id=args.installation_id,
    )
    provisioner = WindowsProvisioner(request)
    try:
        if args.material_file:
            provisioner.provision_from_protected_file(Path(args.material_file))
        else:
            provisioner.provision_from_stdin()
    except Exception:
        # Do not serialize a claim, credential, or raw server error to stdout.
        return 1
    return 0


__all__ = [
    "EnrollmentDelivery",
    "HttpsWindowsEnrollmentClient",
    "ProvisioningRequest",
    "ProvisioningResult",
    "WindowsProvisioner",
    "main",
]
