"""Security-focused tests for scoped service credentials."""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import secrets
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from ipaddress import ip_network
from pathlib import Path
from types import SimpleNamespace
from typing import AsyncIterator
from uuid import uuid4

import pytest
from fastapi import HTTPException
from sqlalchemy import select
from starlette.requests import Request

from endpoint_server.auth.scopes import require_service_scope
from endpoint_server.auth.service_tokens import (
    SERVICE_TOKEN_BYTES,
    ServiceCredentialSummary,
    create_service_credential,
    revoke_service_credential,
    service_credential_is_active,
    service_credential_summary,
)
from endpoint_server.config import Settings
from endpoint_server.db.models import ServiceClient, ServiceCredential


class _ServiceAuthSession:
    def __init__(
        self,
        *,
        client: ServiceClient | None = None,
        credential: ServiceCredential | None = None,
    ) -> None:
        self.client = client
        self.credential = credential
        self.added: list[object] = []
        self.commit_calls = 0

    async def scalar(self, statement: object) -> object | None:
        entity = statement.column_descriptions[0]["entity"]
        if entity is ServiceCredential:
            return self.credential
        if entity is ServiceClient:
            return self.client
        raise AssertionError(f"unexpected query entity: {entity}")

    def add(self, value: object) -> None:
        self.added.append(value)

    async def commit(self) -> None:
        self.commit_calls += 1


class _ServiceAuthSessionProvider:
    def __init__(self, session: _ServiceAuthSession) -> None:
        self.session = session

    @asynccontextmanager
    async def __call__(self) -> AsyncIterator[_ServiceAuthSession]:
        yield self.session


def _settings(service_token_pepper: bytes) -> Settings:
    return Settings(
        database_url="postgresql+asyncpg://endpoint:password@db/endpoint",
        public_base_url="https://endpoint.sosnadmin.local",
        device_token_pepper=b"device-pepper",
        service_token_pepper=service_token_pepper,
        session_secret=b"session-secret",
        allowed_agent_cidrs=(ip_network("10.20.0.0/16"),),
        allowed_admin_cidrs=(ip_network("192.168.100.0/24"),),
        artifact_root=Path("artifacts"),
    )


def _service_client(*, disabled: bool = False) -> ServiceClient:
    return ServiceClient(
        id=uuid4(),
        client_identifier=f"backup-{uuid4().hex}",
        display_name="Backup automation",
        disabled_at=datetime.now(UTC) if disabled else None,
    )


def _request(
    provider: _ServiceAuthSessionProvider,
    service_token_pepper: bytes,
    token: str,
) -> Request:
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/service/protected",
            "headers": [
                (b"authorization", f"Bearer {token}".encode("ascii")),
            ],
            "app": SimpleNamespace(
                state=SimpleNamespace(
                    settings=_settings(service_token_pepper),
                    session_provider=provider,
                )
            ),
        }
    )


def _decode_urlsafe(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


@pytest.mark.asyncio
async def test_creation_shows_token_once_and_persists_only_prefix_hmac_and_scopes(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Persisting or logging raw bearer material would expose the service account."""
    pepper = secrets.token_bytes(32)
    client = _service_client()
    session = _ServiceAuthSession(client=client)
    expires_at = datetime(2026, 7, 30, 10, tzinfo=UTC)

    with caplog.at_level(logging.DEBUG):
        issued = await create_service_credential(
            session,
            client.id,
            pepper,
            scopes=("devices:read", "commands:create"),
            expires_at=expires_at,
            now=datetime(2026, 7, 29, 10, tzinfo=UTC),
        )

    public_prefix, raw_material = issued.token.split(".", 1)
    assert public_prefix == issued.record.token_prefix
    assert issued.record.credential_identifier == public_prefix.removeprefix("svc_")
    assert len(_decode_urlsafe(raw_material)) == SERVICE_TOKEN_BYTES == 32
    assert issued.record.secret_digest == hmac.new(
        pepper,
        issued.token.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()
    assert issued.record.scopes == ["commands:create", "devices:read"]
    assert issued.record.expires_at == expires_at
    assert session.added == [issued.record]
    assert session.commit_calls == 1

    summary = service_credential_summary(issued.record)
    assert isinstance(summary, ServiceCredentialSummary)
    assert summary.credential_identifier == issued.record.credential_identifier
    assert summary.scopes == ("commands:create", "devices:read")
    assert not hasattr(summary, "token")
    assert not hasattr(summary, "secret_digest")
    assert issued.token not in repr(issued)
    assert issued.token not in repr(issued.record)
    assert issued.token not in repr(summary)
    assert issued.token not in caplog.text
    persisted_text = " ".join(
        str(value) for value in vars(issued.record).values()
    )
    assert issued.token not in persisted_text
    assert raw_material not in persisted_text
    assert raw_material not in caplog.text


@pytest.mark.asyncio
async def test_random_material_and_public_identifier_change_per_credential() -> None:
    """Reusing either token component could let one issuance replace another."""
    client = _service_client()
    pepper = secrets.token_bytes(32)

    first = await create_service_credential(
        _ServiceAuthSession(client=client),
        client.id,
        pepper,
        scopes=("devices:read",),
    )
    second = await create_service_credential(
        _ServiceAuthSession(client=client),
        client.id,
        pepper,
        scopes=("devices:read",),
    )

    assert first.token != second.token
    assert first.record.credential_identifier != second.record.credential_identifier
    assert first.record.token_prefix != second.record.token_prefix
    assert first.record.secret_digest != second.record.secret_digest


@pytest.mark.asyncio
async def test_creation_rejects_a_string_in_place_of_a_scope_collection() -> None:
    """Treating one scope string as an iterable would persist per-character grants."""
    client = _service_client()

    with pytest.raises(ValueError, match="scope collection"):
        await create_service_credential(
            _ServiceAuthSession(client=client),
            client.id,
            secrets.token_bytes(32),
            scopes="devices:read",
        )


def test_expired_and_revoked_credentials_are_inactive() -> None:
    """An expiry boundary or revocation must immediately disable the bearer token."""
    now = datetime(2026, 7, 29, 10, tzinfo=UTC)
    credential = ServiceCredential(
        service_client_id=uuid4(),
        credential_identifier=secrets.token_hex(16),
        token_prefix=f"svc_{secrets.token_hex(16)}",
        secret_digest=secrets.token_hex(32),
        scopes=["devices:read"],
        expires_at=now + timedelta(minutes=30),
        revoked_at=None,
    )

    assert service_credential_is_active(credential, now=now)
    assert not service_credential_is_active(
        credential,
        now=now + timedelta(minutes=30),
    )

    revoked_at = now + timedelta(minutes=1)
    revoke_service_credential(credential, now=revoked_at)
    assert credential.revoked_at == revoked_at
    assert not service_credential_is_active(credential, now=revoked_at)


@pytest.mark.asyncio
async def test_require_service_scope_allows_only_exact_scope_membership() -> None:
    """Prefix, substring, and wildcard matching would silently widen authorization."""
    pepper = secrets.token_bytes(32)
    client = _service_client()
    session = _ServiceAuthSession(client=client)
    issued = await create_service_credential(
        session,
        client.id,
        pepper,
        scopes=("devices:read", "commands:create:own"),
    )
    provider = _ServiceAuthSessionProvider(
        _ServiceAuthSession(client=client, credential=issued.record)
    )
    request = _request(provider, pepper, issued.token)

    principal = await require_service_scope("devices:read")(request)
    assert principal.client.id == client.id
    assert principal.credential is issued.record

    for scope in ("devices", "devices:", "commands:create", "*"):
        with pytest.raises(HTTPException) as denied:
            await require_service_scope(scope)(request)
        assert denied.value.status_code == 403


@pytest.mark.asyncio
async def test_require_service_scope_rejects_wrong_revoked_expired_or_disabled_token() -> None:
    """Every invalid credential or client state must fail closed at the dependency."""
    pepper = secrets.token_bytes(32)
    client = _service_client()
    issued = await create_service_credential(
        _ServiceAuthSession(client=client),
        client.id,
        pepper,
        scopes=("devices:read",),
    )
    session = _ServiceAuthSession(client=client, credential=issued.record)
    provider = _ServiceAuthSessionProvider(session)
    dependency = require_service_scope("devices:read")

    wrong_token = f"{issued.record.token_prefix}.{secrets.token_urlsafe(32)}"
    with pytest.raises(HTTPException) as wrong:
        await dependency(_request(provider, pepper, wrong_token))
    assert wrong.value.status_code == 401

    issued.record.revoked_at = datetime.now(UTC)
    with pytest.raises(HTTPException) as revoked:
        await dependency(_request(provider, pepper, issued.token))
    assert revoked.value.status_code == 401

    issued.record.revoked_at = None
    issued.record.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    with pytest.raises(HTTPException) as expired:
        await dependency(_request(provider, pepper, issued.token))
    assert expired.value.status_code == 401

    issued.record.expires_at = None
    client.disabled_at = datetime.now(UTC)
    with pytest.raises(HTTPException) as disabled:
        await dependency(_request(provider, pepper, issued.token))
    assert disabled.value.status_code == 401


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "authorization",
    [
        "",
        "Basic value",
        "bearer value",
        "Bearer",
        "Bearer not-a-service-token",
        "Bearer svc_invalid.!invalid!",
    ],
)
async def test_require_service_scope_rejects_missing_or_malformed_bearer(
    authorization: str,
) -> None:
    """Malformed attacker input must return 401 without reaching credential storage."""
    provider = _ServiceAuthSessionProvider(_ServiceAuthSession())
    request = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/service/protected",
            "headers": (
                [(b"authorization", authorization.encode("ascii"))]
                if authorization
                else []
            ),
            "app": SimpleNamespace(
                state=SimpleNamespace(
                    settings=_settings(secrets.token_bytes(32)),
                    session_provider=provider,
                )
            ),
        }
    )

    with pytest.raises(HTTPException) as rejected:
        await require_service_scope("devices:read")(request)

    assert rejected.value.status_code == 401


def test_service_credential_schema_has_prefix_and_exact_scope_storage() -> None:
    """Dropping either persistence field would prevent secure lookup or authorization."""
    columns = ServiceCredential.__table__.columns

    assert frozenset(
        {"service_client_id", "credential_identifier"}
    ) in {
        frozenset(column.name for column in constraint.columns)
        for constraint in ServiceCredential.__table__.constraints
    }
    assert columns["token_prefix"].unique
    assert not columns["secret_digest"].nullable
    assert not columns["scopes"].nullable
    assert select(ServiceCredential).where(
        ServiceCredential.token_prefix == "svc_public"
    ) is not None
