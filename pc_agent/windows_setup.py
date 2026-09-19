"""Capability-bound universal Windows Setup enrollment orchestration."""

from __future__ import annotations

import secrets
import json
import ssl
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
from uuid import UUID, uuid4

from endpoint_contracts.identity import normalize_hardware_fingerprint


_POLL_INTERVAL_SECONDS = 5
_MAX_POLL_DURATION = timedelta(minutes=30)
_TERMINAL_DENIAL_STATUSES = frozenset({"denied", "expired", "failed", "cancelled"})
_AWAITING_STATUSES = frozenset({"waiting_approval", "review_required"})
_APPROVED_STATUSES = frozenset({"auto_approved", "approved"})
_COMPLETION_AWAITING_STATUSES = frozenset(
    {"claim_issued", "enrolling", "device_registered", "waiting_wss"}
)


class SetupTransport(Protocol):
    """Public request transport; no campaign or credential authority exists here."""

    def create_request(self, body: dict[str, object]) -> dict[str, object]: ...

    def request_status(self, request_id: UUID, capability: str) -> dict[str, object]: ...

    def request_claim(self, request_id: UUID, proof: dict[str, str]) -> dict[str, object]: ...

    def request_verification(self, request_id: UUID, capability: str) -> dict[str, object]: ...


class SetupTransportError(RuntimeError):
    """Bounded transport failure that deliberately omits server response bodies."""


class HttpsSetupTransport:
    """Strict public HTTPS client for the unauthenticated setup request flow."""

    def __init__(self, endpoint_origin: str, ca_file: Path) -> None:
        self._endpoint_origin = endpoint_origin.rstrip("/")
        self._ssl_context = ssl.create_default_context(cafile=str(ca_file))

    def create_request(self, body: dict[str, object]) -> dict[str, object]:
        return self._post("/api/v1/enrollment/requests", body)

    def request_status(self, request_id: UUID, capability: str) -> dict[str, object]:
        return self._post(
            f"/api/v1/enrollment/requests/{request_id}/status",
            {"request_capability": capability},
        )

    def request_claim(self, request_id: UUID, proof: dict[str, str]) -> dict[str, object]:
        return self._post(f"/api/v1/enrollment/requests/{request_id}/claim", proof)

    def request_verification(self, request_id: UUID, capability: str) -> dict[str, object]:
        return self._post(
            f"/api/v1/enrollment/requests/{request_id}/verify",
            {"request_capability": capability},
        )

    def _post(self, path: str, payload: dict[str, object]) -> dict[str, object]:
        request = Request(
            f"{self._endpoint_origin}{path}",
            data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlopen(request, context=self._ssl_context, timeout=15) as response:
                raw = response.read(65_537)
        except (HTTPError, URLError, TimeoutError, OSError, ssl.SSLError) as error:
            raise SetupTransportError("Windows Setup enrollment transport failed") from error
        if len(raw) > 65_536:
            raise SetupTransportError("Windows Setup enrollment response is too large")
        try:
            decoded = json.loads(raw)
        except (TypeError, ValueError) as error:
            raise SetupTransportError("Windows Setup enrollment response is invalid") from error
        if not isinstance(decoded, dict):
            raise SetupTransportError("Windows Setup enrollment response is invalid")
        return decoded


@dataclass(frozen=True, slots=True)
class SetupConfig:
    """Only public setup configuration; enrollment authority remains server-side."""

    endpoint_origin: str
    ca_file: Path
    installer_version: str
    installer_release_id: str

    def validate(self) -> None:
        parsed = urlsplit(self.endpoint_origin)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("Setup requires an absolute HTTPS endpoint origin")
        if not self.installer_version or len(self.installer_version) > 128:
            raise ValueError("installer version is invalid")
        if not self.installer_release_id or len(self.installer_release_id) > 128:
            raise ValueError("installer release is invalid")


@dataclass(frozen=True, slots=True)
class SetupOutcome:
    """Credential-free result suitable for bounded setup diagnostics."""

    status: Literal[
        "provisioned",
        "waiting_approval",
        "review_required",
        "denied",
        "expired",
        "timed_out",
    ]
    request_id: UUID | None = None
    reason: str | None = None


@dataclass(slots=True)
class UniversalWindowsSetup:
    """Run one universal AUTO/MANUAL request flow without selecting campaigns."""

    config: SetupConfig
    transport: SetupTransport
    provision_claim: Callable[[str], object] = field(repr=False)
    fingerprint_probe: Callable[[], str] = field(repr=False)
    inventory_probe: Callable[[], dict[str, object]] = field(repr=False)
    capability_factory: Callable[[], str] = field(
        default=lambda: secrets.token_urlsafe(32), repr=False
    )
    installation_id_factory: Callable[[], str] = field(
        default=lambda: f"win-{uuid4()}", repr=False
    )
    clock: Callable[[], datetime] = field(default=lambda: datetime.now(UTC), repr=False)
    sleep: Callable[[float], None] = field(default=time.sleep, repr=False)

    def run(self) -> SetupOutcome:
        """Request, poll if needed, obtain one claim, and hand it to stdin provision."""
        self.config.validate()
        capability = self.capability_factory()
        if len(capability) != 43 or not capability.isascii():
            raise ValueError("setup capability must be a 43-character ASCII secret")
        installation_id = self.installation_id_factory()
        if not installation_id or len(installation_id) > 128:
            raise ValueError("setup installation ID is invalid")
        hardware_fingerprint = normalize_hardware_fingerprint(self.fingerprint_probe())
        body = {
            "schema_version": "pre_enrollment_request_create_v1",
            "platform": "windows",
            "installation_id": installation_id,
            "hardware_fingerprint": hardware_fingerprint,
            "request_capability": capability,
            "installer_version": self.config.installer_version,
            "installer_release_id": self.config.installer_release_id,
            "requested_at": self.clock().astimezone(UTC).isoformat(),
            **_bounded_inventory(self.inventory_probe()),
        }
        response = self.transport.create_request(body)
        request_id = _request_id(response)
        state = _state(response)
        deadline = self.clock().astimezone(UTC) + _MAX_POLL_DURATION
        if state == "review_required":
            return SetupOutcome("review_required", request_id=request_id, reason=_reason(response))
        while state in _AWAITING_STATUSES:
            if self.clock().astimezone(UTC) >= deadline:
                return SetupOutcome("timed_out", request_id=request_id)
            self.sleep(_POLL_INTERVAL_SECONDS)
            state_response = self.transport.request_status(request_id, capability)
            response = state_response
            state = _state(response)
        if state in _TERMINAL_DENIAL_STATUSES:
            if state == "expired":
                return SetupOutcome("expired", request_id=request_id, reason=_reason(response))
            return SetupOutcome("denied", request_id=request_id, reason=_reason(response))
        if state not in _APPROVED_STATUSES:
            return SetupOutcome("waiting_approval", request_id=request_id, reason=_reason(response))
        claim_response = self.transport.request_claim(
            request_id,
            {
                "request_capability": capability,
                "installation_id": installation_id,
                "hardware_fingerprint": hardware_fingerprint,
            },
        )
        claim = claim_response.get("claim")
        if not isinstance(claim, str) or not claim.startswith("ic_"):
            raise ValueError("setup received an invalid enrollment claim")
        self.provision_claim(claim)
        while True:
            completion_response = self.transport.request_verification(request_id, capability)
            completion_state = _state(completion_response)
            if completion_state == "completed":
                return SetupOutcome("provisioned", request_id=request_id)
            if completion_state in _TERMINAL_DENIAL_STATUSES:
                return SetupOutcome(
                    "denied", request_id=request_id, reason=_reason(completion_response)
                )
            if completion_state not in _COMPLETION_AWAITING_STATUSES:
                raise ValueError("setup received an invalid completion status")
            if self.clock().astimezone(UTC) >= deadline:
                return SetupOutcome("timed_out", request_id=request_id, reason="WAITING_WSS")
            self.sleep(_POLL_INTERVAL_SECONDS)


def _request_id(payload: dict[str, object]) -> UUID:
    value = payload.get("request_id")
    try:
        return UUID(str(value))
    except (TypeError, ValueError, AttributeError) as error:
        raise ValueError("setup received an invalid enrollment request ID") from error


def _state(payload: dict[str, object]) -> str:
    value = payload.get("status")
    if not isinstance(value, str) or len(value) > 32:
        raise ValueError("setup received an invalid enrollment status")
    return value


def _reason(payload: dict[str, object]) -> str | None:
    value = payload.get("reason")
    return value if isinstance(value, str) and len(value) <= 128 else None


def _bounded_inventory(observed: dict[str, object]) -> dict[str, object]:
    hostname = observed.get("hostname")
    if not isinstance(hostname, str) or not hostname or len(hostname) > 256:
        raise ValueError("setup inventory hostname is invalid")
    macs = observed.get("macs", [])
    if not isinstance(macs, list) or len(macs) > 32 or not all(
        isinstance(value, str) and len(value) == 12 and value.isalnum()
        for value in macs
    ):
        raise ValueError("setup inventory MAC addresses are invalid")
    return {"hostname": hostname, "macs": [value.lower() for value in macs]}


__all__ = [
    "HttpsSetupTransport",
    "SetupConfig",
    "SetupOutcome",
    "SetupTransport",
    "SetupTransportError",
    "UniversalWindowsSetup",
]
