"""Narrow, TLS-verifying client for one-time provisioning install claims.

This module deliberately does not share the safe Device Context client.  Its
only result is secret-bearing, its only request is claim issuance, and it
never retries a POST because a duplicate request could create a second claim.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
import re
from typing import Final
from urllib.parse import urlsplit
from uuid import UUID

import httpx
from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    ValidationError,
)

from .errors import (
    EndpointPlatformConfigurationError,
    EndpointPlatformInvalidRequest,
    EndpointPlatformMalformedResponse,
    EndpointPlatformResponseError,
    EndpointPlatformUnavailable,
)


_MAX_INSTALL_SESSION_LENGTH: Final = 128
_MAX_HARDWARE_FINGERPRINT_LENGTH: Final = 256
_MAX_TOKEN_LENGTH: Final = 4096
_CLAIM_PATTERN: Final = r"^ic_[0-9a-f]{32}\.[A-Za-z0-9_-]{43}$"
_HARDWARE_FINGERPRINT_PATTERN: Final = re.compile(
    r"^sha256:[a-z0-9][a-z0-9._-]{1,248}$",
    re.ASCII,
)


@dataclass(frozen=True, slots=True, repr=False)
class InstallClaim:
    """Show-once install claim that cannot appear in ordinary output.

    The exact value is intentionally available only through
    :meth:`get_secret_value` for the caller that writes the root-managed
    systemd credential source.  It must never be interpolated into logs.
    """

    _secret: SecretStr = field(repr=False)
    expires_at: datetime
    install_session_id: str

    def get_secret_value(self) -> str:
        """Return the claim only to the narrowly authorized writer."""

        return self._secret.get_secret_value()

    def __repr__(self) -> str:
        return "InstallClaim(<redacted>)"

    def __str__(self) -> str:
        return "<redacted InstallClaim>"


class _InstallClaimResponse(BaseModel):
    """Private strict parser; errors must never expose its input payload."""

    model_config = ConfigDict(extra="forbid")

    claim: str = Field(min_length=79, max_length=79, pattern=_CLAIM_PATTERN)
    expires_at: AwareDatetime
    install_session_id: str = Field(
        min_length=1, max_length=_MAX_INSTALL_SESSION_LENGTH
    )


class EndpointProvisioningClient:
    """Fixed provisioning client authenticated by a dedicated token file."""

    def __init__(
        self,
        base_url: str,
        *,
        provisioning_token_file: str | Path,
        ca_file: str | Path,
        timeout_seconds: float = 5.0,
    ) -> None:
        parsed = urlsplit(base_url)
        if (
            parsed.scheme != "https"
            or not parsed.netloc
            or parsed.username is not None
            or parsed.password is not None
            or timeout_seconds <= 0
        ):
            raise EndpointPlatformConfigurationError()
        token = self._read_provisioning_token(Path(provisioning_token_file))
        ca_bundle = Path(ca_file)
        if not ca_bundle.is_file():
            raise EndpointPlatformConfigurationError()
        try:
            self._http = httpx.Client(
                base_url=base_url.rstrip("/"),
                headers={
                    "Accept": "application/json",
                    "Authorization": f"Bearer {token}",
                },
                verify=str(ca_bundle),
                timeout=timeout_seconds,
                follow_redirects=False,
            )
        except (OSError, ValueError, httpx.HTTPError):
            raise EndpointPlatformConfigurationError() from None

    @staticmethod
    def _read_provisioning_token(path: Path) -> str:
        try:
            token = path.read_text(encoding="utf-8").strip()
        except (OSError, UnicodeError):
            raise EndpointPlatformConfigurationError() from None
        if not token or len(token) > _MAX_TOKEN_LENGTH:
            raise EndpointPlatformConfigurationError()
        return token

    def close(self) -> None:
        """Close the owned HTTP connection pool."""

        self._http.close()

    def __enter__(self) -> "EndpointProvisioningClient":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def issue_install_claim(
        self,
        install_session_id: str,
        hardware_fingerprint: str,
        campaign_id: UUID,
    ) -> InstallClaim:
        """Issue one hardware-bound claim without retrying or exposing bodies."""

        try:
            normalized_session = _normalize_install_session_id(install_session_id)
            normalized_fingerprint = _normalize_hardware_fingerprint(
                hardware_fingerprint
            )
            if not isinstance(campaign_id, UUID):
                raise ValueError("campaign ID must be UUID")
        except ValueError:
            raise EndpointPlatformInvalidRequest() from None

        try:
            response = self._http.request(
                "POST",
                "/api/v1/provisioning/install-claims",
                json={
                    "install_session_id": normalized_session,
                    "hardware_fingerprint": normalized_fingerprint,
                    "campaign_id": str(campaign_id),
                },
            )
        except httpx.RequestError:
            raise EndpointPlatformUnavailable() from None
        if response.status_code < 200 or response.status_code >= 300:
            raise EndpointPlatformResponseError(response.status_code)
        try:
            parsed = _InstallClaimResponse.model_validate(response.json())
            session = _normalize_install_session_id(parsed.install_session_id)
            if session != normalized_session:
                raise ValueError("response install session does not match request")
            if parsed.expires_at <= datetime.now(UTC):
                raise ValueError("response claim is expired")
            return InstallClaim(
                _secret=SecretStr(parsed.claim),
                expires_at=parsed.expires_at,
                install_session_id=session,
            )
        except (TypeError, ValueError, ValidationError):
            raise EndpointPlatformMalformedResponse() from None


def _normalize_install_session_id(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > _MAX_INSTALL_SESSION_LENGTH
        or value != value.strip()
        or not value.isascii()
        or any(not 32 <= ord(character) <= 126 for character in value)
    ):
        raise ValueError("invalid install session")
    return value


def _normalize_hardware_fingerprint(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("invalid hardware fingerprint")
    canonical = value.lower()
    if (
        not 8 <= len(canonical) <= _MAX_HARDWARE_FINGERPRINT_LENGTH
        or not _HARDWARE_FINGERPRINT_PATTERN.fullmatch(canonical)
    ):
        raise ValueError("invalid hardware fingerprint")
    return canonical


__all__ = ["EndpointProvisioningClient", "InstallClaim"]
