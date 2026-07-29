"""Strict, device-bearer client for Endpoint Platform update recommendations."""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal, Protocol
from urllib.parse import urlsplit
from uuid import uuid4

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
    def post(
        self, url: str, *, headers: dict[str, str], json: dict[str, object]
    ) -> _Response: ...


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
    legacy_result: object | None = None


_ACKNOWLEDGEMENT_STATUSES = {"requested", "scheduled"}
_TERMINAL_STATUSES = {"applied", "failed", "rolled_back"}
_SAFE_CODES = {
    "launcher_apply_failed",
    "launcher_rolled_back",
    "post_restart_handshake_confirmed",
}
_STATE_FIELDS = {
    "operation_id",
    "assigned_version",
    "rollback_version",
    "scheduled_ack_delivered_at",
}


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
        data_root: Path | None = None,
    ) -> None:
        self._api_url = api_url.rstrip("/")
        self._bearer_token = bearer_token
        self._session = session
        self._legacy_fetch = legacy_fetch
        self._data_root = Path(data_root) if data_root is not None else None

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
        received_primary_response = False
        try:
            async with self._session.get(
                url, headers={"Authorization": f"Bearer {bearer}"}
            ) as response:
                received_primary_response = True
                if response.status == 204:
                    return RecommendationResult("endpoint", None, False, None)
                if response.status in {404, 501}:
                    return await self._fetch_legacy()
                if response.status != 200:
                    return RecommendationResult(
                        "endpoint", None, False, "endpoint_unavailable"
                    )
                raw_body = await response.text()
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            if received_primary_response:
                return RecommendationResult(
                    "endpoint", None, False, "endpoint_unavailable"
                )
            if isinstance(exc, (aiohttp.ClientConnectionError, asyncio.TimeoutError)):
                return await self._fetch_legacy()
            return RecommendationResult("endpoint", None, False, "endpoint_unavailable")

        recommendation = _parse_recommendation(
            raw_body, platform=platform, channel=channel
        )
        if recommendation is None:
            return RecommendationResult(
                "endpoint", None, False, "endpoint_contract_invalid"
            )
        return RecommendationResult("endpoint", recommendation, False, None)

    async def acknowledge(self, operation_id: str, status: str) -> bool:
        if status not in _ACKNOWLEDGEMENT_STATUSES or not _is_operation_id(
            operation_id
        ):
            return False
        bearer = self._bearer_token()
        if not isinstance(bearer, str) or not bearer:
            return False
        try:
            async with self._session.post(
                f"{self._api_url}/agent/v1/updates/{operation_id}/ack",
                headers={"Authorization": f"Bearer {bearer}"},
                json={"schema_version": "agent_update_ack_v1", "status": status},
            ) as response:
                return response.status == 204
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return False

    async def record_scheduled_handoff(
        self,
        operation_id: str,
        *,
        assigned_version: str,
        rollback_version: str,
    ) -> bool:
        if (
            self._data_root is None
            or not _is_operation_id(operation_id)
            or not _SEMVER.fullmatch(assigned_version)
            or not _SEMVER.fullmatch(rollback_version)
        ):
            return False
        records = self._load_update_state()
        existing = next(
            (record for record in records if record["operation_id"] == operation_id),
            None,
        )
        if existing is None:
            records.append(
                {
                    "operation_id": operation_id,
                    "assigned_version": assigned_version,
                    "rollback_version": rollback_version,
                    "scheduled_ack_delivered_at": None,
                }
            )
            self._write_update_state(records)
        elif (
            existing["assigned_version"] != assigned_version
            or existing["rollback_version"] != rollback_version
        ):
            return False
        return await self.retry_scheduled_acknowledgement(operation_id)

    async def retry_scheduled_acknowledgement(self, operation_id: str) -> bool:
        if self._data_root is None or not _is_operation_id(operation_id):
            return False
        records = self._load_update_state()
        record = next(
            (
                candidate
                for candidate in records
                if candidate["operation_id"] == operation_id
            ),
            None,
        )
        if record is None:
            return False
        if record["scheduled_ack_delivered_at"] is not None:
            return True
        if not await self.acknowledge(operation_id, "scheduled"):
            return False
        record["scheduled_ack_delivered_at"] = datetime.now(timezone.utc).isoformat()
        self._write_update_state(records)
        return True

    async def report_terminal(
        self,
        operation_id: str,
        *,
        status: str,
        reported_version: str,
        safe_code: str | None,
    ) -> bool:
        if (
            status not in _TERMINAL_STATUSES
            or not _is_operation_id(operation_id)
            or not _SEMVER.fullmatch(reported_version)
            or safe_code not in _SAFE_CODES
            or self._data_root is None
        ):
            return False
        bearer = self._bearer_token()
        if not isinstance(bearer, str) or not bearer:
            return False
        record = self._load_or_create_report(
            operation_id, status, reported_version, safe_code
        )
        if record["delivered_at"] is not None:
            return True
        payload = {
            "schema_version": "agent_update_report_v1",
            "report_key": record["report_key"],
            "status": status,
            "reported_version": reported_version,
            "safe_code": safe_code,
        }
        try:
            async with self._session.post(
                f"{self._api_url}/agent/v1/updates/{operation_id}/reports",
                headers={"Authorization": f"Bearer {bearer}"},
                json=payload,
            ) as response:
                if response.status != 200:
                    return False
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return False
        record["delivered_at"] = datetime.now(timezone.utc).isoformat()
        self._write_report_journal(self._load_report_journal_with(record))
        return True

    async def _fetch_legacy(self) -> RecommendationResult:
        if self._legacy_fetch is None:
            return RecommendationResult("endpoint", None, True, "endpoint_unavailable")
        try:
            legacy_result = await self._legacy_fetch()
        except Exception:
            return RecommendationResult("endpoint", None, True, "endpoint_unavailable")
        return RecommendationResult(
            "legacy", None, False, "endpoint_unavailable", legacy_result
        )

    def _report_journal_path(self) -> Path:
        assert self._data_root is not None
        return self._data_root / "updates" / "endpoint_update_reports.json"

    def _update_state_path(self) -> Path:
        assert self._data_root is not None
        return self._data_root / "updates" / "endpoint_update_state.json"

    def _load_update_state(self) -> list[dict[str, str | None]]:
        assert self._data_root is not None
        return load_endpoint_update_handoffs(self._data_root)

    def _write_update_state(self, records: list[dict[str, str | None]]) -> None:
        path = self._update_state_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f"{path.name}.{uuid4().hex}.tmp")
        temporary.write_text(
            json.dumps(records[-100:], ensure_ascii=False), encoding="utf-8"
        )
        temporary.replace(path)

    def _load_or_create_report(
        self, operation_id: str, status: str, reported_version: str, safe_code: str
    ) -> dict[str, str | None]:
        journal = self._load_report_journal()
        for record in journal:
            if all(
                record[key] == value
                for key, value in {
                    "operation_id": operation_id,
                    "status": status,
                    "reported_version": reported_version,
                    "safe_code": safe_code,
                }.items()
            ):
                return record
        record: dict[str, str | None] = {
            "operation_id": operation_id,
            "report_key": uuid4().hex,
            "status": status,
            "reported_version": reported_version,
            "safe_code": safe_code,
            "delivered_at": None,
        }
        journal.append(record)
        self._write_report_journal(journal)
        return record

    def _load_report_journal_with(
        self, changed: dict[str, str | None]
    ) -> list[dict[str, str | None]]:
        journal = self._load_report_journal()
        for index, record in enumerate(journal):
            if record["report_key"] == changed["report_key"]:
                journal[index] = changed
                return journal
        return [*journal, changed]

    def _load_report_journal(self) -> list[dict[str, str | None]]:
        path = self._report_journal_path()
        try:
            raw = json.loads(path.read_text(encoding="utf-8")) if path.exists() else []
        except (OSError, json.JSONDecodeError):
            return []
        fields = {
            "operation_id",
            "report_key",
            "status",
            "reported_version",
            "safe_code",
            "delivered_at",
        }
        return (
            [
                {key: item[key] for key in fields}
                for item in raw
                if isinstance(item, dict)
                and set(item) == fields
                and all(
                    isinstance(item.get(key), str) or item.get(key) is None
                    for key in fields
                )
            ]
            if isinstance(raw, list)
            else []
        )

    def _write_report_journal(self, journal: list[dict[str, str | None]]) -> None:
        path = self._report_journal_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f"{path.name}.{uuid4().hex}.tmp")
        temporary.write_text(json.dumps(journal, ensure_ascii=False), encoding="utf-8")
        temporary.replace(path)


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
        not artifact_url.startswith("https://")
        or parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("artifact_url")


def _is_operation_id(value: str) -> bool:
    return bool(_LOWERCASE_UUID.fullmatch(value))


def load_endpoint_update_handoffs(
    data_root: Path,
) -> list[dict[str, str | None]]:
    path = Path(data_root) / "updates" / "endpoint_update_state.json"
    try:
        raw = json.loads(path.read_text(encoding="utf-8")) if path.exists() else []
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(raw, list):
        return []
    records: list[dict[str, str | None]] = []
    for item in raw:
        if (
            not isinstance(item, dict)
            or set(item) != _STATE_FIELDS
            or not isinstance(item.get("operation_id"), str)
            or not _is_operation_id(item["operation_id"])
            or not isinstance(item.get("assigned_version"), str)
            or not _SEMVER.fullmatch(item["assigned_version"])
            or not isinstance(item.get("rollback_version"), str)
            or not _SEMVER.fullmatch(item["rollback_version"])
            or (
                item.get("scheduled_ack_delivered_at") is not None
                and not isinstance(item.get("scheduled_ack_delivered_at"), str)
            )
        ):
            continue
        records.append({key: item[key] for key in _STATE_FIELDS})
    return records
