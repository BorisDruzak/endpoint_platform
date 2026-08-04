"""Linux/systemd first-boot exchange of a one-time Endpoint install claim.

This module is deliberately inert until the Linux service bootstrap explicitly
calls :func:`bootstrap_enrollment`.  It never reads a claim from the process
environment, configuration, command line, or legacy agent token stores.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import secrets
import ssl
import stat
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, Protocol
from urllib.parse import urlsplit
from uuid import UUID

import aiohttp
from endpoint_contracts import AgentEnrollmentDeliveryV1, AgentEnrollmentRequestV1
from endpoint_contracts.identity import normalize_hardware_fingerprint
from pydantic import ValidationError

from pc_agent.enrollment_identity import (
    EnrollmentIdentityError,
    canonical_enrollment_device_id,
    read_enrollment_device_id,
    serialize_enrollment_identity,
)


SYSTEMD_CLAIM_CREDENTIAL_NAME = "endpoint-enrollment-claim"
# Task 15 used this LoadCredential name.  It remains an explicit, temporary
# integration seam; callers must opt in through BootstrapConfig rather than
# reading an environment-provided pathname.
_TOKEN_LENGTH = 43
_FINGERPRINT_CONTEXT = b"endpoint-agent-bootstrap-fingerprint-v1\0"
_HANDOFF_SCHEMA_VERSION = "endpoint_claim_removal_request_v1"
PERMANENT_CREDENTIAL_PATH = Path("/var/lib/endpoint-agent/device-credential")
ENROLLMENT_IDENTITY_PATH = Path("/var/lib/endpoint-agent/enrollment-identity.json")
HANDOFF_REQUEST_PATH = Path("/var/lib/endpoint-agent/claim-removal-request.json")


class EnrollmentTransportUnavailable(Exception):
    """The Gateway could not be reached or gave a transient response."""


class EnrollmentTemporaryFailure(EnrollmentTransportUnavailable):
    """A caller-friendly alias for a retryable first-boot failure."""


class EnrollmentRejected(Exception):
    """The one-time claim was invalid, expired, replayed, or misbound."""


@dataclass(frozen=True)
class EnrollmentDelivery:
    """Minimal secret-bearing response kept only in process memory."""

    device_id: UUID
    device_token: str = field(repr=False)


@dataclass(frozen=True)
class EnrollmentOutcome:
    """Credential-free first-boot result suitable for service status handling."""

    status: Literal[
        "enrolled",
        "already_enrolled",
        "temporary_failure",
        "denied",
        "credential_invalid",
        "persistence_failed",
        "handoff_pending",
    ]
    device_id: str | None = None


@dataclass(frozen=True)
class BootstrapConfig:
    """Non-secret service configuration for the claim-only enrollment path."""

    endpoint_url: str
    ca_file: Path
    installation_id: str
    # These fields exist only to make the deployment boundary explicit.  They
    # are deliberately validated against the fixed production locations below:
    # an unprivileged process must never select a root-finalizer path.
    credential_path: Path = PERMANENT_CREDENTIAL_PATH
    identity_path: Path = ENROLLMENT_IDENTITY_PATH
    handoff_request_path: Path = HANDOFF_REQUEST_PATH
    service_uid: int | None = None
    service_gid: int | None = None
    claim_credential_name: str = SYSTEMD_CLAIM_CREDENTIAL_NAME
    retry_attempts: int = 3

    def validate(self) -> None:
        parsed = urlsplit(self.endpoint_url)
        if (
            not self.endpoint_url.startswith("https://")
            or parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("Endpoint bootstrap requires an explicit HTTPS URL")
        try:
            _require_safe_regular_path(self.ca_file)
        except OSError as error:
            raise ValueError("Endpoint bootstrap requires a safe CA file") from error
        if not self.ca_file.is_file():
            raise ValueError("Endpoint bootstrap requires a CA file")
        if not (
            isinstance(self.installation_id, str)
            and self.installation_id
            and self.installation_id == self.installation_id.strip()
            and self.installation_id.isascii()
            and len(self.installation_id) <= 128
            and all(32 <= ord(character) <= 126 for character in self.installation_id)
        ):
            raise ValueError("Installation session must be bounded printable ASCII")
        if self.claim_credential_name != SYSTEMD_CLAIM_CREDENTIAL_NAME:
            raise ValueError("Unknown systemd enrollment claim credential")
        if not 1 <= self.retry_attempts <= 3:
            raise ValueError("Enrollment retry budget must be between 1 and 3")
        if (
            self.credential_path != PERMANENT_CREDENTIAL_PATH
            or self.identity_path != ENROLLMENT_IDENTITY_PATH
            or self.handoff_request_path != HANDOFF_REQUEST_PATH
        ):
            raise ValueError(
                "Credential and claim-removal handoff paths must use fixed production locations"
            )


class EnrollmentTransport(Protocol):
    async def enroll(
        self,
        *,
        endpoint_url: str,
        ca_file: Path,
        claim: str,
        request: dict[str, object],
    ) -> EnrollmentDelivery: ...


class ClaimRemovalHandoff(Protocol):
    def request_removal(
        self,
        *,
        claim_credential_name: str,
        credential_path: Path,
        device_id: UUID,
        credential_sha256: str,
    ) -> bool: ...


class HttpsEnrollmentTransport:
    """The existing HTTPS enrollment route with mandatory local CA trust."""

    async def enroll(
        self,
        *,
        endpoint_url: str,
        ca_file: Path,
        claim: str,
        request: dict[str, object],
    ) -> EnrollmentDelivery:
        try:
            ssl_context = ssl.create_default_context(cafile=str(ca_file))
            timeout = aiohttp.ClientTimeout(total=15)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(
                    f"{endpoint_url.rstrip('/')}/agent/v1/enroll",
                    headers={"Authorization": f"Bearer {claim}"},
                    json=request,
                    ssl=ssl_context,
                ) as response:
                    raw = await response.text()
                    if response.status in {401, 403, 409, 422}:
                        raise EnrollmentRejected("Enrollment denied")
                    if response.status not in {200, 201}:
                        raise EnrollmentTemporaryFailure()
        except EnrollmentRejected:
            raise
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError, ssl.SSLError):
            raise EnrollmentTemporaryFailure() from None

        try:
            payload = json.loads(raw)
            if not isinstance(payload, dict):
                raise ValueError("Enrollment response must be an object")
            delivery = AgentEnrollmentDeliveryV1.model_validate(payload)
        except (json.JSONDecodeError, TypeError, ValidationError, ValueError):
            raise EnrollmentRejected("Enrollment denied") from None
        return EnrollmentDelivery(
            device_id=delivery.device_id,
            device_token=delivery.device_token,
        )


class FileClaimRemovalHandoff:
    """Request, but never perform, the root-owned claim-source removal.

    The file contains no claim or permanent credential.  The root controller
    validates the permanent credential independently before removing its own
    root-owned source (Task 15's ``--finalize-handoff`` path).
    """

    def __init__(self, *, uid: int, gid: int) -> None:
        self._uid = uid
        self._gid = gid

    def request_removal(
        self,
        *,
        claim_credential_name: str,
        credential_path: Path,
        device_id: UUID,
        credential_sha256: str,
    ) -> bool:
        if (
            claim_credential_name != SYSTEMD_CLAIM_CREDENTIAL_NAME
            or credential_path != PERMANENT_CREDENTIAL_PATH
            or not _is_sha256_hex(credential_sha256)
        ):
            return False
        payload = json.dumps(
            {
                "schema_version": _HANDOFF_SCHEMA_VERSION,
                "claim_credential_name": claim_credential_name,
                "credential_path": str(credential_path),
                "device_id": str(device_id),
                "credential_sha256": credential_sha256,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        try:
            _atomic_secret_write(
                HANDOFF_REQUEST_PATH, payload, uid=self._uid, gid=self._gid
            )
        except OSError:
            return False
        return _verify_owned_mode(HANDOFF_REQUEST_PATH, uid=self._uid, gid=self._gid)


async def bootstrap_enrollment(
    credentials_dir: Path,
    config: BootstrapConfig,
    probe: Callable[[], object],
    *,
    transport: EnrollmentTransport | None = None,
    handoff: ClaimRemovalHandoff | None = None,
    sleep: Callable[[float], Awaitable[object]] = asyncio.sleep,
) -> EnrollmentOutcome:
    """Exchange the systemd-only install claim once and persist its credential.

    A pre-existing, verified permanent credential wins before any credential
    directory is accessed.  Terminal enrollment rejection never retries;
    only transport/Gateway unavailability uses the bounded retry loop.
    """
    try:
        config.validate()
        uid, gid = _service_identity(config)
    except (OSError, ValueError):
        return EnrollmentOutcome("credential_invalid")

    existing = _existing_credential_state(config.credential_path, uid=uid, gid=gid)
    existing_identity = _existing_enrollment_identity_state(
        config.identity_path, uid=uid, gid=gid
    )
    if existing == "valid" and existing_identity == "valid":
        return EnrollmentOutcome("already_enrolled")
    if existing != "missing" or existing_identity != "missing":
        return EnrollmentOutcome("credential_invalid")

    try:
        claim = _read_systemd_claim(Path(credentials_dir), config.claim_credential_name)
        hardware_fingerprint = _derive_hardware_fingerprint(probe)
        request = AgentEnrollmentRequestV1(
            schema_version="agent_enrollment_request_v1",
            platform="linux",
            hardware_fingerprint=hardware_fingerprint,
            installation_id=config.installation_id,
            delivery_nonce=secrets.token_urlsafe(32),
            requested_at=datetime.now(UTC),
        ).model_dump(mode="json")
    except (OSError, TypeError, ValueError, ValidationError):
        return EnrollmentOutcome("denied")

    selected_transport = transport or HttpsEnrollmentTransport()
    delivery: EnrollmentDelivery | None = None
    for attempt in range(config.retry_attempts):
        try:
            delivery = await selected_transport.enroll(
                endpoint_url=config.endpoint_url,
                ca_file=config.ca_file,
                claim=claim,
                request=request,
            )
            break
        except EnrollmentRejected:
            return EnrollmentOutcome("denied")
        except EnrollmentTransportUnavailable:
            if attempt + 1 == config.retry_attempts:
                return EnrollmentOutcome("temporary_failure")
            await sleep(float(attempt + 1))
        except Exception:
            return EnrollmentOutcome("temporary_failure")

    if delivery is None:
        return EnrollmentOutcome("temporary_failure")
    try:
        device_id = canonical_enrollment_device_id(delivery.device_id)
        identity_payload = serialize_enrollment_identity(device_id)
    except EnrollmentIdentityError:
        return EnrollmentOutcome("denied")
    if not _is_opaque_device_token(delivery.device_token):
        return EnrollmentOutcome("denied")
    try:
        _atomic_secret_write(
            config.credential_path,
            delivery.device_token.encode("ascii"),
            uid=uid,
            gid=gid,
        )
        _atomic_secret_write(
            config.identity_path,
            identity_payload,
            uid=uid,
            gid=gid,
        )
    except OSError:
        _discard_unverified_new_credential(
            config.credential_path,
            delivery.device_token,
            uid=uid,
            gid=gid,
        )
        _discard_unverified_new_identity(
            config.identity_path,
            identity_payload,
            uid=uid,
            gid=gid,
        )
        return EnrollmentOutcome("persistence_failed")
    if (
        not _verified_credential_matches(
            config.credential_path,
            delivery.device_token,
            uid=uid,
            gid=gid,
        )
        or not _verified_enrollment_identity_matches(
            config.identity_path,
            device_id,
            uid=uid,
            gid=gid,
        )
    ):
        _discard_unverified_new_credential(
            config.credential_path,
            delivery.device_token,
            uid=uid,
            gid=gid,
        )
        _discard_unverified_new_identity(
            config.identity_path,
            identity_payload,
            uid=uid,
            gid=gid,
        )
        return EnrollmentOutcome("persistence_failed")

    selected_handoff = handoff or FileClaimRemovalHandoff(uid=uid, gid=gid)
    if not selected_handoff.request_removal(
        claim_credential_name=config.claim_credential_name,
        credential_path=config.credential_path,
        device_id=device_id,
        credential_sha256=hashlib.sha256(
            delivery.device_token.encode("ascii")
        ).hexdigest(),
    ):
        return EnrollmentOutcome("handoff_pending", str(device_id))
    return EnrollmentOutcome("enrolled", str(device_id))


def _service_identity(config: BootstrapConfig) -> tuple[int, int]:
    uid = (
        getattr(os, "getuid", lambda: 0)()
        if config.service_uid is None
        else config.service_uid
    )
    gid = (
        getattr(os, "getgid", lambda: 0)()
        if config.service_gid is None
        else config.service_gid
    )
    if (
        not isinstance(uid, int)
        or isinstance(uid, bool)
        or not isinstance(gid, int)
        or isinstance(gid, bool)
        or uid < 0
        or gid < 0
    ):
        raise ValueError("Service identity must be numeric")
    return uid, gid


def _read_systemd_claim(credentials_dir: Path, credential_name: str) -> str:
    _require_safe_directory(credentials_dir)
    path = credentials_dir / credential_name
    raw = _read_regular_bytes(path, maximum_bytes=512)
    if not raw:
        raise ValueError("Invalid systemd claim credential")
    if len(raw) > 512:
        raise ValueError("Invalid systemd claim credential")
    try:
        claim = raw.decode("ascii")
    except UnicodeDecodeError as error:
        raise ValueError("Invalid systemd claim credential") from error
    if claim != claim.strip() or not claim.startswith("ic_"):
        raise ValueError("Invalid systemd claim credential")
    return claim


def _derive_hardware_fingerprint(probe: Callable[[], object]) -> str:
    observed = probe()
    if isinstance(observed, str):
        return normalize_hardware_fingerprint(observed)
    canonical = json.dumps(
        observed,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode("utf-8")
    return normalize_hardware_fingerprint(
        "sha256:" + hashlib.sha256(_FINGERPRINT_CONTEXT + canonical).hexdigest()
    )


def _is_opaque_device_token(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == _TOKEN_LENGTH
        and value.isascii()
        and all(character.isalnum() or character in "_-" for character in value)
    )


def _existing_credential_state(
    path: Path, *, uid: int, gid: int
) -> Literal["missing", "valid", "invalid"]:
    try:
        _require_safe_parent_path(path)
    except OSError:
        return "invalid"
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return "missing"
    except OSError:
        return "invalid"
    if not stat.S_ISREG(metadata.st_mode) or not _verify_owned_mode(
        path, uid=uid, gid=gid
    ):
        return "invalid"
    try:
        token = _read_regular_bytes(path, maximum_bytes=_TOKEN_LENGTH).decode("ascii")
    except (OSError, UnicodeDecodeError):
        return "invalid"
    return "valid" if _is_opaque_device_token(token) else "invalid"


def _existing_enrollment_identity_state(
    path: Path, *, uid: int, gid: int
) -> Literal["missing", "valid", "invalid"]:
    try:
        _require_safe_parent_path(path)
    except OSError:
        return "invalid"
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return "missing"
    except OSError:
        return "invalid"
    if not stat.S_ISREG(metadata.st_mode) or not _verify_owned_mode(
        path, uid=uid, gid=gid
    ):
        return "invalid"
    try:
        read_enrollment_device_id(path)
    except EnrollmentIdentityError:
        return "invalid"
    return "valid"


def _verified_credential_matches(
    path: Path, expected: str, *, uid: int, gid: int
) -> bool:
    if _existing_credential_state(path, uid=uid, gid=gid) != "valid":
        return False
    try:
        return (
            _read_regular_bytes(path, maximum_bytes=_TOKEN_LENGTH).decode("ascii")
            == expected
        )
    except (OSError, UnicodeDecodeError):
        return False


def _verified_enrollment_identity_matches(
    path: Path, expected: UUID, *, uid: int, gid: int
) -> bool:
    if _existing_enrollment_identity_state(path, uid=uid, gid=gid) != "valid":
        return False
    try:
        return read_enrollment_device_id(path) == expected
    except EnrollmentIdentityError:
        return False


def _discard_unverified_new_credential(
    path: Path, expected: str, *, uid: int, gid: int
) -> None:
    """Remove only the exact new token we just wrote, never a raced-in file."""
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode):
            return
        if os.name != "nt" and (metadata.st_uid != uid or metadata.st_gid != gid):
            return
        if (
            _read_regular_bytes(path, maximum_bytes=_TOKEN_LENGTH).decode("ascii")
            != expected
        ):
            return
        path.unlink()
        _fsync_directory(path.parent)
    except (OSError, UnicodeDecodeError):
        return


def _discard_unverified_new_identity(
    path: Path, expected: bytes, *, uid: int, gid: int
) -> None:
    """Remove only the exact identity payload from this enrollment attempt."""
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode):
            return
        if os.name != "nt" and (metadata.st_uid != uid or metadata.st_gid != gid):
            return
        if _read_regular_bytes(path, maximum_bytes=len(expected)) != expected:
            return
        path.unlink()
        _fsync_directory(path.parent)
    except OSError:
        return


def _verify_owned_mode(path: Path, *, uid: int, gid: int) -> bool:
    try:
        _require_safe_regular_path(path)
        metadata = path.lstat()
    except OSError:
        return False
    if not stat.S_ISREG(metadata.st_mode):
        return False
    # This module is deployed only by Linux/systemd.  Windows does not expose
    # POSIX ownership/mode bits through Python, so the pure unit boundary can
    # exercise its state machine there without pretending that it verifies
    # Linux file ownership.
    if os.name == "nt":
        return True
    return (
        stat.S_IMODE(metadata.st_mode) == 0o600
        and metadata.st_uid == uid
        and metadata.st_gid == gid
    )


def _atomic_secret_write(path: Path, payload: bytes, *, uid: int, gid: int) -> None:
    _require_safe_parent_path(path)
    if path.exists() or path.is_symlink():
        _require_safe_regular_path(path)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    try:
        os.fchmod(descriptor, 0o600)
        if hasattr(os, "fchown"):
            os.fchown(descriptor, uid, gid)
        with os.fdopen(descriptor, "wb", closefd=True) as output:
            descriptor = -1
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    except Exception:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _fsync_directory(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _is_sha256_hex(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _require_safe_directory(path: Path) -> None:
    _require_safe_path_components(path, include_leaf=True)
    try:
        metadata = path.lstat()
    except OSError:
        raise
    if not stat.S_ISDIR(metadata.st_mode):
        raise OSError("Expected a directory")


def _require_safe_parent_path(path: Path) -> None:
    _require_safe_path_components(path, include_leaf=False)


def _require_safe_regular_path(path: Path) -> None:
    _require_safe_parent_path(path)
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode):
        raise OSError("Expected a regular file")


def _read_regular_bytes(path: Path, *, maximum_bytes: int) -> bytes:
    _require_safe_regular_path(path)
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size < 0
            or metadata.st_size > maximum_bytes
        ):
            raise OSError("Security-sensitive file has an invalid size")
        chunks: list[bytes] = []
        remaining = maximum_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 4096))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > maximum_bytes:
            raise OSError("Security-sensitive file has an invalid size")
        return raw
    finally:
        os.close(descriptor)


def _require_safe_path_components(path: Path, *, include_leaf: bool) -> None:
    """Reject symlinks and non-directories in each existing parent component.

    ``O_NOFOLLOW`` protects the final descriptor.  Checking every component as
    well prevents the writes and reads in this module from traversing an
    attacker-controlled parent before that descriptor is opened.
    """
    if not path.is_absolute():
        raise OSError("Security-sensitive path must be absolute")
    parts = path.parts
    if not parts:
        raise OSError("Security-sensitive path is empty")
    current = Path(parts[0])
    limit = len(parts) if include_leaf else len(parts) - 1
    for component in parts[1:limit]:
        current = current / component
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            raise OSError("Security-sensitive parent is missing") from None
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise OSError("Security-sensitive path traverses an unsafe parent")
