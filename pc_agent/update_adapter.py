"""Strict, device-bearer client for Endpoint Platform update recommendations."""

from __future__ import annotations

import json
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Literal, Protocol
from urllib.parse import urlsplit

import aiohttp
from endpoint_contracts import AgentUpdateRecommendationV1
from pydantic import ValidationError


UpdatePlatform = Literal["windows_amd64", "linux_amd64"]
UpdateChannel = Literal["stable", "canary"]

_LOWERCASE_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_SEMVER = re.compile(
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)


class _Response(Protocol):
    status: int

    async def text(self) -> str: ...

    async def __aenter__(self) -> _Response: ...

    async def __aexit__(self, *args: object) -> object: ...


class _Session(Protocol):
    def get(self, url: str, *, headers: dict[str, str]) -> _Response: ...


@dataclass(frozen=True)
class EndpointRecommendation:
    operation_id: str
    version: str
    platform: UpdatePlatform
    channel: UpdateChannel
    artifact_url: str
    artifact_name: str
    archive_type: Literal["zip", "tar.gz"]
    sha256: str
    size: int
    reason: str | None


@dataclass(frozen=True)
class RecommendationResult:
    source: Literal["endpoint", "legacy", "none"]
    recommendation: EndpointRecommendation | None
    unavailable: bool
    safe_error: str | None


class EndpointUpdateAdapter:
    """Fetch only strict Endpoint Platform recommendation contracts.

    The caller owns lifecycle handoff and any eligible legacy fallback.  Raw
    response data is deliberately never exposed or logged by this boundary.
    """

    def __init__(
        self,
        *,
        api_url: str,
        bearer_token: Callable[[], str | None],
        session: _Session,
        legacy_fetch: Callable[[], Awaitable[object]] | None = None,
    ) -> None:
        self._api_url = api_url.rstrip("/")
        self._bearer_token = bearer_token
        self._session = session
        self._legacy_fetch = legacy_fetch

    async def fetch_recommendation(
        self, *, platform: UpdatePlatform, channel: UpdateChannel
    ) -> RecommendationResult:
        if platform not in {"windows_amd64", "linux_amd64"} or channel not in {
            "stable",
            "canary",
        }:
            return RecommendationResult(
                "endpoint", None, False, "endpoint_contract_invalid"
            )

        bearer = self._bearer_token()
        if not isinstance(bearer, str) or not bearer:
            return RecommendationResult(
                "endpoint", None, False, "endpoint_auth_missing"
            )

        url = (
            f"{self._api_url}/agent/v1/updates/recommendation"
            f"?platform={platform}&channel={channel}"
        )
        try:
            async with self._session.get(
                url, headers={"Authorization": f"Bearer {bearer}"}
            ) as response:
                if response.status == 204:
                    return RecommendationResult("endpoint", None, False, None)
                if response.status != 200:
                    return RecommendationResult(
                        "endpoint", None, False, "endpoint_unavailable"
                    )
                raw_body = await response.text()
        except (aiohttp.ClientConnectionError, TimeoutError):
            return RecommendationResult("endpoint", None, True, "endpoint_unavailable")

        recommendation = _parse_recommendation(
            raw_body, platform=platform, channel=channel
        )
        if recommendation is None:
            return RecommendationResult(
                "endpoint", None, False, "endpoint_contract_invalid"
            )
        return RecommendationResult("endpoint", recommendation, False, None)


def _parse_recommendation(
    raw_body: str, *, platform: UpdatePlatform, channel: UpdateChannel
) -> EndpointRecommendation | None:
    try:
        payload = json.loads(raw_body)
        if not isinstance(payload, dict):
            return None
        _validate_wire_form(payload, platform=platform, channel=channel)
        model = AgentUpdateRecommendationV1.model_validate(payload)
    except (json.JSONDecodeError, TypeError, ValidationError, ValueError):
        return None

    return EndpointRecommendation(
        operation_id=str(model.operation_id),
        version=model.version,
        platform=model.platform,
        channel=model.channel,
        artifact_url=str(model.artifact_url),
        artifact_name=model.artifact_name,
        archive_type=model.archive_type,
        sha256=model.sha256,
        size=model.size,
        reason=model.reason,
    )


def _validate_wire_form(
    payload: dict[str, Any], *, platform: UpdatePlatform, channel: UpdateChannel
) -> None:
    operation_id = payload.get("operation_id")
    version = payload.get("version")
    artifact_url = payload.get("artifact_url")
    if not isinstance(operation_id, str) or not _LOWERCASE_UUID.fullmatch(operation_id):
        raise ValueError("operation_id")
    if not isinstance(version, str) or not _SEMVER.fullmatch(version):
        raise ValueError("version")
    if payload.get("platform") != platform or payload.get("channel") != channel:
        raise ValueError("target")
    if not isinstance(artifact_url, str):
        raise ValueError("artifact_url")
    parsed = urlsplit(artifact_url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("artifact_url")
