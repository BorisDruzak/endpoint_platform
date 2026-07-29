"""TLS-verifying client for Endpoint Platform's safe service API."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID

import httpx
from pydantic import ValidationError

from .errors import (
    EndpointPlatformConfigurationError,
    EndpointPlatformInvalidRequest,
    EndpointPlatformMalformedResponse,
    EndpointPlatformNotFound,
    EndpointPlatformResponseError,
    EndpointPlatformUnavailable,
)
from .models import (
    BaselineHistory,
    Collection,
    CollectionDetails,
    ContextComparison,
    ContextSnapshot,
    Device,
    DeviceContext,
    SafeContextProfile,
    is_safe_profile,
)
from ._contracts import DeviceContextDiffV1


_READ_ATTEMPTS = 3
_TRANSIENT_STATUS_CODES = frozenset((502, 503, 504))
_MAX_BASELINE_HISTORY_LIMIT = 100


class EndpointPlatformClient:
    """Scoped HTTP client that only understands safe Device Context projections."""

    def __init__(
        self,
        base_url: str,
        *,
        token_file: str | Path,
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
        token = self._read_token(Path(token_file))
        bundle = Path(ca_file)
        if not bundle.is_file():
            raise EndpointPlatformConfigurationError()
        try:
            self._http = httpx.Client(
                base_url=base_url.rstrip("/"),
                headers={"Accept": "application/json", "Authorization": f"Bearer {token}"},
                verify=str(bundle),
                timeout=timeout_seconds,
                follow_redirects=False,
            )
        except (OSError, ValueError, httpx.HTTPError):
            raise EndpointPlatformConfigurationError() from None

    @staticmethod
    def _read_token(path: Path) -> str:
        try:
            token = path.read_text(encoding="utf-8").strip()
        except (OSError, UnicodeError):
            raise EndpointPlatformConfigurationError() from None
        if not token or len(token) > 4096:
            raise EndpointPlatformConfigurationError()
        return token

    def close(self) -> None:
        """Close the owned HTTP connection pool."""

        self._http.close()

    def __enter__(self) -> "EndpointPlatformClient":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def list_devices(self) -> list[Device]:
        data = self._get("/api/v1/devices")
        return self._validate(data, lambda value: _DeviceListResponse.model_validate(value)).data

    def get_device(self, device_id: UUID) -> Device:
        """Return one service-visible identity through the devices.read boundary."""

        for device in self.list_devices():
            if device.id == device_id:
                return device
        raise EndpointPlatformNotFound()

    def get_latest_context(self, device_id: UUID, profile: SafeContextProfile) -> ContextSnapshot | None:
        """Return the latest current safe snapshot for one allowed profile."""

        self._require_safe_profile(profile)
        data = self._get(f"/api/v1/devices/{device_id}/context")
        context = self._validate(
            data,
            lambda value: _DataResponse[DeviceContext](
                data=DeviceContext.model_validate(value["data"])
            ),
        )
        matching = [snapshot for snapshot in context.data.snapshots if snapshot.profile == profile]
        return max(matching, key=lambda snapshot: snapshot.collected_at, default=None)

    def list_baseline_history(self, device_id: UUID, *, limit: int = 50) -> list[ContextSnapshot]:
        """Return at most 100 newest-first baseline snapshots for one device."""
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= _MAX_BASELINE_HISTORY_LIMIT:
            raise EndpointPlatformInvalidRequest()
        data = self._get(
            f"/api/v1/devices/{device_id}/context/snapshots",
            params={"profile": "baseline_v1", "limit": str(limit)},
        )
        return self._validate(
            data,
            lambda value: _DataResponse[BaselineHistory](
                data=BaselineHistory.model_validate(value["data"])
            ),
        ).data.snapshots

    def request_collection(
        self,
        device_id: UUID,
        profile: SafeContextProfile,
        idempotency_key: str,
    ) -> Collection:
        self._require_safe_profile(profile)
        if not self._valid_idempotency_key(idempotency_key):
            raise EndpointPlatformInvalidRequest()
        data = self._request(
            "POST",
            f"/api/v1/devices/{device_id}/context/collections",
            json={"profile": profile},
            headers={"Idempotency-Key": idempotency_key},
            retry=False,
        )
        return self._validate(data, lambda value: _DataResponse[Collection](data=Collection.model_validate(value["data"]))).data

    def get_collection(self, collection_id: UUID) -> CollectionDetails:
        """Read safe lifecycle data and, if complete, its normalized snapshot."""

        data = self._get(f"/api/v1/context/collections/{collection_id}")
        return self._validate(
            data,
            lambda value: _DataResponse[CollectionDetails](
                data=CollectionDetails.model_validate(value["data"])
            ),
        ).data

    def compare_context(
        self,
        device_id: UUID,
        from_snapshot_id: UUID,
        to_snapshot_id: UUID,
    ) -> ContextComparison:
        """Compare two baseline snapshots using only the fixed safe diff contract."""

        if from_snapshot_id == to_snapshot_id:
            raise EndpointPlatformInvalidRequest()

        data = self._get(
            f"/api/v1/devices/{device_id}/context/snapshots/compare",
            params={
                "before_snapshot_id": str(from_snapshot_id),
                "after_snapshot_id": str(to_snapshot_id),
            },
        )
        comparison = self._validate(
            data,
            lambda value: _DataResponse[DeviceContextDiffV1](
                data=DeviceContextDiffV1.model_validate(value["data"])
            ),
        ).data
        return ContextComparison(comparison=comparison)

    def _get(self, path: str, **kwargs: object) -> object:
        return self._request("GET", path, retry=True, **kwargs)

    def _request(
        self,
        method: str,
        path: str,
        *,
        retry: bool,
        json: object | None = None,
        headers: dict[str, str] | None = None,
        params: dict[str, str] | None = None,
    ) -> object:
        attempts = _READ_ATTEMPTS if retry and method == "GET" else 1
        for attempt in range(attempts):
            try:
                response = self._http.request(method, path, json=json, headers=headers, params=params)
            except httpx.RequestError:
                if attempt + 1 < attempts:
                    continue
                raise EndpointPlatformUnavailable() from None
            if response.status_code in _TRANSIENT_STATUS_CODES and attempt + 1 < attempts:
                continue
            if response.status_code < 200 or response.status_code >= 300:
                raise EndpointPlatformResponseError(response.status_code)
            try:
                return response.json()
            except ValueError:
                raise EndpointPlatformMalformedResponse() from None
        raise EndpointPlatformUnavailable()

    @staticmethod
    def _validate(value: object, parser: Callable[[object], Any]) -> Any:
        try:
            return parser(value)
        except (KeyError, TypeError, ValidationError, ValueError):
            raise EndpointPlatformMalformedResponse() from None

    @staticmethod
    def _require_safe_profile(profile: object) -> None:
        if not is_safe_profile(profile):
            raise EndpointPlatformInvalidRequest()

    @staticmethod
    def _valid_idempotency_key(value: str) -> bool:
        return (
            bool(value)
            and len(value) <= 128
            and value == value.strip()
            and value.isascii()
            and all(32 <= ord(character) <= 126 for character in value)
        )


class _DataResponse[T]:
    """Private parsed wrapper used to keep endpoint envelope handling centralized."""

    def __init__(self, *, data: T) -> None:
        self.data = data


class _DeviceListResponse:
    def __init__(self, *, data: list[Device]) -> None:
        self.data = data

    @classmethod
    def model_validate(cls, value: object) -> "_DeviceListResponse":
        if not isinstance(value, dict) or set(value) != {"data"} or not isinstance(value["data"], list):
            raise ValueError("invalid safe response envelope")
        return cls(data=[Device.model_validate(item) for item in value["data"]])
