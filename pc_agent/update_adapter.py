"""Strict, device-bearer client for Endpoint Platform update recommendations."""

from __future__ import annotations

import asyncio
import json
import os
import re
import ssl
from ipaddress import ip_address
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal, Protocol
from urllib.parse import urlsplit
from uuid import uuid4

import aiohttp
from endpoint_contracts import AgentUpdateRecommendationV1
from endpoint_contracts.device_binding import DeviceBindingChallengeV1
from pydantic import ValidationError
from pc_agent.transport.base import GatewayCredentialRejected, GatewayTerminalError
from pc_agent.platform.windows.acl import PyWin32AclAdapter, preserve_state_file_permissions
from pc_agent.platform.windows.durable_state import write_json_atomic
from pc_agent.platform.windows.update_paths import WindowsUpdatePaths
from pc_agent.platform.windows.update_transaction import update_transaction, UpdateInProgress
from pc_agent.platform.windows import durable_state


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
    content: aiohttp.StreamReader

    async def text(self) -> str: ...

    async def __aenter__(self) -> _Response: ...

    async def __aexit__(self, *args: object) -> object: ...


class _Session(Protocol):
    def get(self, url: str, *, headers: dict[str, str]) -> _Response: ...
    def post(
        self, url: str, *, headers: dict[str, str], json: dict[str, object],
        allow_redirects: bool = True,
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


def _defer_busy_update(method):
    """Do not block the connection event loop behind Setup's MSI transaction."""
    from functools import wraps
    @wraps(method)
    async def deferred(*args, **kwargs):
        try:
            return await method(*args, **kwargs)
        except UpdateInProgress:
            return False
    return deferred


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
        strict_recovery: bool = False,
    ) -> None:
        self._strict_recovery = strict_recovery
        if strict_recovery:
            from pc_agent.transport.http_pull import validate_endpoint_origin
            validate_endpoint_origin(api_url)
            try:
                ip_address(urlsplit(api_url).hostname or "")
            except ValueError:
                pass
            else:
                raise ValueError("Endpoint recovery requires its configured hostname")
            if legacy_fetch is not None:
                raise ValueError("Endpoint recovery cannot use legacy fallback")
        self._api_url = api_url.rstrip("/")
        self._bearer_token = bearer_token
        self._session = session
        self._legacy_fetch = legacy_fetch
        self._data_root = Path(data_root) if data_root is not None else None
        if self._strict_recovery and self._data_root is not None:
            self._load_report_journal()
            self._load_update_state()

    async def create_device_binding_challenge(self) -> DeviceBindingChallengeV1:
        """Reuse the device session for a fixed, credential-safe possession API."""
        from pc_agent.platform.windows.device_binding import (
            BindingUnavailable, MAX_CHALLENGE_BYTES, parse_challenge,
        )
        from pc_agent.transport.http_pull import validate_endpoint_origin
        try:
            validate_endpoint_origin(self._api_url)
            bearer = self._bearer_token()
            if not isinstance(bearer, str) or not bearer:
                raise BindingUnavailable()
            async with self._session.post(
                f"{self._api_url}/api/v1/device-binding/challenges",
                headers={"Authorization": f"Bearer {bearer}"},
                json={"purpose":"helpdesk_device_binding"},
                allow_redirects=False,
            ) as response:
                if response.status != 200:
                    raise BindingUnavailable()
                body = bytearray()
                async for chunk in response.content.iter_chunked(512):
                    body.extend(chunk)
                    if len(body) > MAX_CHALLENGE_BYTES:
                        raise BindingUnavailable()
                return parse_challenge(json.loads(body))
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError, TypeError):
            raise BindingUnavailable() from None

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
            if self._strict_recovery:
                raise GatewayCredentialRejected("Endpoint update credential missing")
            return RecommendationResult(
                "endpoint", None, False, "endpoint_auth_missing"
            )

        if self._strict_recovery and self._data_root is not None:
            self._load_report_journal()
            self._load_update_state()

        url = (
            f"{self._api_url}/agent/v1/updates/recommendation"
            f"?platform={platform}&channel={channel}"
        )
        received_primary_response = False
        try:
            async with self._session.get(
                url, headers={"Authorization": f"Bearer {bearer}"},
                **({"allow_redirects": False} if self._strict_recovery else {}),
            ) as response:
                self._require_recovery_response(response.status)
                received_primary_response = True
                if response.status == 204:
                    return RecommendationResult("endpoint", None, False, None)
                if response.status in {404, 501}:
                    return await self._fetch_legacy()
                if response.status != 200:
                    return RecommendationResult(
                        "endpoint", None, self._strict_recovery, "endpoint_unavailable"
                    )
                raw_body = await response.text()
        except (aiohttp.ClientConnectorCertificateError, aiohttp.ClientConnectorSSLError, ssl.SSLError) as exc:
            if self._strict_recovery:
                raise GatewayTerminalError("Endpoint update TLS trust failed") from exc
            return RecommendationResult("endpoint", None, False, "endpoint_unavailable")
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
                **({"allow_redirects": False} if self._strict_recovery else {}),
            ) as response:
                self._require_recovery_response(response.status)
                return response.status == 204
        except (aiohttp.ClientConnectorCertificateError, aiohttp.ClientConnectorSSLError, ssl.SSLError) as exc:
            if self._strict_recovery:
                raise GatewayTerminalError("Endpoint update TLS trust failed") from exc
            return False
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return False

    @_defer_busy_update
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
        with self._journal_transaction():
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

    @_defer_busy_update
    async def retry_scheduled_acknowledgement(self, operation_id: str) -> bool:
        if self._data_root is None or not _is_operation_id(operation_id):
            return False
        with self._journal_transaction():
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
            # A visible record may come from a replacement whose parent flush
            # failed. Its operation metadata must be durable before HTTP yields.
            durable_state.flush_directory(self._update_state_path().parent)
            if record["scheduled_ack_delivered_at"] is not None:
                return True
        if not await self.acknowledge(operation_id, "scheduled"):
            return False
        # HTTP may yield to other processes; reload, bind identity, then merge.
        with self._journal_transaction():
            expected = (record["assigned_version"], record["rollback_version"])
            records = self._load_update_state()
            record = next((candidate for candidate in records if candidate["operation_id"] == operation_id), None)
            if record is None or (record["assigned_version"], record["rollback_version"]) != expected:
                return False
            if record["scheduled_ack_delivered_at"] is not None:
                durable_state.flush_directory(self._update_state_path().parent)
                return True
            record["scheduled_ack_delivered_at"] = datetime.now(timezone.utc).isoformat()
            self._write_update_state(records)
        return True

    @_defer_busy_update
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
        with self._journal_transaction():
            record = self._load_or_create_report(
                operation_id, status, reported_version, safe_code
            )
            # Retry must durably retain the idempotency key before sending it,
            # including when the preceding write left an undelivered visible leaf.
            durable_state.flush_directory(self._report_journal_path().parent)
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
                **({"allow_redirects": False} if self._strict_recovery else {}),
            ) as response:
                self._require_recovery_response(response.status)
                if response.status != 200:
                    return False
        except (aiohttp.ClientConnectorCertificateError, aiohttp.ClientConnectorSSLError, ssl.SSLError) as exc:
            if self._strict_recovery:
                raise GatewayTerminalError("Endpoint update TLS trust failed") from exc
            return False
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return False
        with self._journal_transaction():
            journal = self._load_report_journal()
            current = next((item for item in journal if item["report_key"] == record["report_key"]), None)
            if current is None or any(current[key] != record[key] for key in
                ("operation_id", "status", "reported_version", "safe_code")):
                return False
            current["delivered_at"] = current["delivered_at"] or datetime.now(timezone.utc).isoformat()
            self._write_report_journal(journal)
        return True

    def _require_recovery_response(self, status: int) -> None:
        if not self._strict_recovery:
            return
        if status in {401, 403}:
            raise GatewayCredentialRejected("Endpoint update credential rejected")
        if 300 <= status < 400:
            raise GatewayTerminalError("Endpoint update redirect rejected")

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

    def _journal_transaction(self):
        assert self._data_root is not None
        # Paths bind POSIX journals; Windows always uses the canonical fixed mutex.
        return update_transaction(WindowsUpdatePaths(pending_path=self._data_root / "updates" / "pending_update.json"), timeout_ms=0)

    def _report_journal_path(self) -> Path:
        assert self._data_root is not None
        return self._data_root / "updates" / "endpoint_update_reports.json"

    def _update_state_path(self) -> Path:
        assert self._data_root is not None
        return self._data_root / "updates" / "endpoint_update_state.json"

    def _load_update_state(self) -> list[dict[str, str | None]]:
        assert self._data_root is not None
        return load_endpoint_update_handoffs(self._data_root, strict=self._strict_recovery)

    def _write_update_state(self, records: list[dict[str, str | None]]) -> None:
        self._write_journal(self._update_state_path(), records[-100:], max_bytes=256 * 1024)

    def _write_journal(self, path: Path, records: object, *, max_bytes: int) -> None:
        assert self._data_root is not None
        # This online owner provisions the protected directory before asking
        # the primitive to publish. No worker imports this adapter.
        # Validate the existing owner root before creating/protecting any child.
        for directory in [self._data_root.absolute(), *self._data_root.absolute().parents]:
            details = directory.lstat()
            if directory.is_symlink() or getattr(details, "st_file_attributes", 0) & 0x400:
                raise ValueError("update journal root contains a reparse point")
            if not directory.is_dir():
                raise ValueError("update journal root is not a directory")
        if path.parent.exists():
            details = path.parent.lstat()
            if path.parent.is_symlink() or getattr(details, "st_file_attributes", 0) & 0x400:
                raise ValueError("update journal directory is a reparse point")
        if os.name == "nt":
            acl = PyWin32AclAdapter()
            acl.protect_directory(path.parent)
            protect = acl.protect_update_path
        else:
            path.parent.mkdir(exist_ok=True)
            protect = (lambda temporary: preserve_state_file_permissions(path, temporary)) if path.exists() else None
        # Also persists newly provisioned updates/ and finishes a prior failed
        # parent flush even when that directory is already visible on retry.
        durable_state.flush_directory(self._data_root)
        write_json_atomic(path, records, trusted_root=self._data_root / "updates",
            max_bytes=max_bytes, protect=protect)

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
            if self._strict_recovery:
                raise ValueError("Endpoint recovery report journal is unreadable") from None
            return []
        fields = {
            "operation_id",
            "report_key",
            "status",
            "reported_version",
            "safe_code",
            "delivered_at",
        }
        if self._strict_recovery and (
            not isinstance(raw, list)
            or any(
                not isinstance(item, dict)
                or set(item) != fields
                or not _valid_report_record(item)
                for item in raw
            )
            or len({item["report_key"] for item in raw}) != len(raw)
            or len({(item["operation_id"], item["status"], item["reported_version"], item["safe_code"])
                    for item in raw}) != len(raw)
        ):
            raise ValueError("Endpoint recovery report journal is invalid")
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
        self._write_journal(self._report_journal_path(), journal, max_bytes=4 * 1024 * 1024)


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
    if payload.get("platform") != platform or payload.get("channel") not in {"stable", "canary"}:
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


def _valid_delivery_time(value: object) -> bool:
    if value is None:
        return True
    if not isinstance(value, str):
        return False
    try:
        return datetime.fromisoformat(value).tzinfo is not None
    except ValueError:
        return False


def _valid_report_record(item: dict[str, object]) -> bool:
    codes = {"failed": "launcher_apply_failed", "rolled_back": "launcher_rolled_back",
             "applied": "post_restart_handshake_confirmed"}
    return (
        isinstance(item["operation_id"], str) and _is_operation_id(item["operation_id"])
        and isinstance(item["report_key"], str)
        and re.fullmatch(r"[0-9a-f]{32}", item["report_key"]) is not None
        and isinstance(item["reported_version"], str)
        and _SEMVER.fullmatch(item["reported_version"]) is not None
        and isinstance(item["status"], str) and item["status"] in codes
        and item["safe_code"] == codes[item["status"]]
        and _valid_delivery_time(item["delivered_at"])
    )


def load_endpoint_update_handoffs(
    data_root: Path,
    *, strict: bool = False,
) -> list[dict[str, str | None]]:
    path = Path(data_root) / "updates" / "endpoint_update_state.json"
    try:
        raw = json.loads(path.read_text(encoding="utf-8")) if path.exists() else []
    except (OSError, json.JSONDecodeError):
        if strict:
            raise ValueError("Endpoint recovery handoff journal is unreadable") from None
        return []
    if not isinstance(raw, list):
        if strict:
            raise ValueError("Endpoint recovery handoff journal is invalid")
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
            or (strict and not _valid_delivery_time(item.get("scheduled_ack_delivered_at")))
            or (strict and any(record["operation_id"] == item.get("operation_id") for record in records))
        ):
            if strict:
                raise ValueError("Endpoint recovery handoff journal contains an invalid record")
            continue
        records.append({key: item[key] for key in _STATE_FIELDS})
    return records
