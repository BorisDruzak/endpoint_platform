"""Security-focused tests for local administrator authentication."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import io
import os
import secrets
from contextlib import asynccontextmanager
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from ipaddress import ip_network
from pathlib import Path
from types import SimpleNamespace
from typing import AsyncIterator
from uuid import uuid4

import asyncpg
import pytest
from alembic import command
from alembic.config import Config
from fastapi import HTTPException
from httpx import ASGITransport, AsyncClient
from sqlalchemy import func, select
from sqlalchemy.engine import make_url
from starlette.requests import Request
from starlette.responses import Response

from endpoint_server.auth.admin_sessions import (
    ADMIN_SESSION_COOKIE,
    SESSION_TOKEN_BYTES,
    AdminPrincipal,
    issue_admin_session,
    require_admin,
    revoke_admin_session,
    session_is_active,
    set_admin_session_cookie,
)
from endpoint_server.auth.bootstrap_admin import (
    bootstrap_first_admin,
    parse_arguments,
    read_interactive_password,
)
from endpoint_server.auth.csrf import (
    CSRF_HEADER,
    enforce_csrf,
)
from endpoint_server.auth.passwords import hash_password, verify_password
from endpoint_server.config import Settings
from endpoint_server.db.models import AdminSession, AdminUser, AuditEvent
from endpoint_server.db.session import create_session_provider
from endpoint_server.main import create_app


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


class _InteractiveInput(io.StringIO):
    def isatty(self) -> bool:
        return True


class _BootstrapSession:
    def __init__(
        self, existing_admins: int = 0, *, fail_audit: bool = False
    ) -> None:
        self.existing_admins = existing_admins
        self.fail_audit = fail_audit
        self.added: list[object] = []
        self.commit_calls = 0
        self.rollback_calls = 0
        self.events: list[str] = []

    async def execute(
        self, statement: object, parameters: object | None = None
    ) -> object:
        self.events.append("lock")
        return object()

    async def scalar(self, statement: object) -> int:
        self.events.append("count")
        return self.existing_admins

    def add(self, value: object) -> None:
        if self.fail_audit and isinstance(value, AuditEvent):
            raise RuntimeError("injected audit failure")
        self.events.append("add")
        self.added.append(value)

    async def commit(self) -> None:
        self.events.append("commit")
        self.commit_calls += 1

    async def rollback(self) -> None:
        self.events.append("rollback")
        self.rollback_calls += 1
        self.added.clear()


class _AuthSession:
    def __init__(
        self,
        *,
        user: AdminUser | None = None,
        admin_session: AdminSession | None = None,
        fail_audit: bool = False,
    ) -> None:
        self.user = user
        self.admin_session = admin_session
        self.fail_audit = fail_audit
        self.added: list[object] = []
        self.commit_calls = 0
        self.rollback_calls = 0
        self._original_revoked_at = (
            admin_session.revoked_at if admin_session is not None else None
        )

    async def scalar(self, statement: object) -> object | None:
        entity = statement.column_descriptions[0]["entity"]
        if entity is AdminSession:
            return self.admin_session
        if entity is AdminUser:
            return self.user
        raise AssertionError(f"unexpected query entity: {entity}")

    def add(self, value: object) -> None:
        if self.fail_audit and isinstance(value, AuditEvent):
            raise RuntimeError("injected audit failure")
        self.added.append(value)

    async def commit(self) -> None:
        self.commit_calls += 1

    async def rollback(self) -> None:
        self.rollback_calls += 1
        self.added.clear()
        if self.admin_session is not None:
            self.admin_session.revoked_at = self._original_revoked_at

    async def merge(self, value: object) -> object:
        return value


class _AuthSessionProvider:
    def __init__(self, session: _AuthSession) -> None:
        self.session = session

    @asynccontextmanager
    async def __call__(self) -> AsyncIterator[_AuthSession]:
        yield self.session


def _decode_urlsafe(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _request(method: str, *, csrf_header: str | None = None) -> Request:
    headers = []
    if csrf_header is not None:
        headers.append(
            (CSRF_HEADER.lower().encode("ascii"), csrf_header.encode("latin-1"))
        )
    return Request(
        {
            "type": "http",
            "method": method,
            "path": "/admin/protected",
            "headers": headers,
        }
    )


def _settings(session_secret: bytes) -> Settings:
    return Settings(
        database_url="postgresql+asyncpg://endpoint:password@db/endpoint",
        public_base_url="https://endpoint.sosnadmin.local",
        device_token_pepper=b"device-pepper",
        service_token_pepper=b"service-pepper",
        session_secret=session_secret,
        allowed_agent_cidrs=(ip_network("10.20.0.0/16"),),
        allowed_admin_cidrs=(ip_network("192.168.100.0/24"),),
        artifact_root=Path("artifacts"),
    )


def _admin_user(password: str) -> AdminUser:
    return AdminUser(
        id=uuid4(),
        username="first-admin",
        password_digest=hash_password(password),
        disabled_at=None,
    )


def _postgres_admin_url() -> str:
    url = os.environ.get("ENDPOINT_TEST_POSTGRES_URL")
    if not url:
        pytest.skip(
            "set ENDPOINT_TEST_POSTGRES_URL to a disposable local PostgreSQL server"
        )
    parsed = make_url(url)
    if parsed.host not in {"127.0.0.1", "localhost", "::1"}:
        pytest.fail("authentication tests may only use a loopback PostgreSQL server")
    return parsed.set(drivername="postgresql").render_as_string(
        hide_password=False
    )


async def _execute_postgres(database_url: str, statement: str) -> None:
    connection = await asyncpg.connect(database_url)
    try:
        await connection.execute(statement)
    finally:
        await connection.close()


@pytest.fixture
def auth_database_url() -> Iterator[str]:
    admin_url = _postgres_admin_url()
    database_name = f"endpoint_admin_auth_{uuid4().hex}"
    asyncio.run(_execute_postgres(admin_url, f'CREATE DATABASE "{database_name}"'))
    database_url = (
        make_url(admin_url)
        .set(drivername="postgresql+asyncpg", database=database_name)
        .render_as_string(hide_password=False)
    )
    config = Config(REPOSITORY_ROOT / "alembic.ini")
    config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    try:
        command.upgrade(config, "head")
        yield database_url
    finally:
        asyncio.run(
            _execute_postgres(
                admin_url,
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                f"WHERE datname = '{database_name}' AND pid <> pg_backend_pid()",
            )
        )
        asyncio.run(_execute_postgres(admin_url, f'DROP DATABASE "{database_name}"'))


def test_password_digest_uses_argon2id_and_verifies_without_retaining_password() -> None:
    """Replacing Argon2id or accepting a wrong password would weaken stored credentials."""
    password = secrets.token_urlsafe(24)

    digest = hash_password(password)

    assert digest.startswith("$argon2id$")
    assert password not in digest
    assert verify_password(digest, password)
    assert not verify_password(digest, password + "-wrong")
    assert not verify_password("not-an-argon2-digest", password)


def test_bootstrap_password_reader_requires_a_terminal_and_confirmation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A redirected password source could expose bootstrap credentials to automation."""
    password = secrets.token_urlsafe(24)
    entered = iter((password, password))
    monkeypatch.setattr("sys.stdin", _InteractiveInput())
    monkeypatch.setattr(
        "endpoint_server.auth.bootstrap_admin.getpass.getpass",
        lambda prompt: next(entered),
    )

    assert read_interactive_password() == password

    monkeypatch.setattr("sys.stdin", io.StringIO(password))
    with pytest.raises(RuntimeError, match="interactive terminal"):
        read_interactive_password()


@pytest.mark.parametrize(
    ("case", "expected_message"),
    [
        ("empty", "must not be empty"),
        ("mismatch", "does not match"),
    ],
)
def test_bootstrap_rejects_empty_or_mismatched_password_confirmation(
    monkeypatch: pytest.MonkeyPatch,
    case: str,
    expected_message: str,
) -> None:
    """Empty or mistyped confirmation must not create a bootstrap credential."""
    entered_passwords = (
        ("", "")
        if case == "empty"
        else (secrets.token_urlsafe(24), secrets.token_urlsafe(24))
    )
    entered = iter(entered_passwords)
    monkeypatch.setattr("sys.stdin", _InteractiveInput())
    monkeypatch.setattr(
        "endpoint_server.auth.bootstrap_admin.getpass.getpass",
        lambda prompt: next(entered),
    )

    with pytest.raises(RuntimeError, match=expected_message):
        read_interactive_password()


def test_bootstrap_cli_has_no_password_argument(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Accepting a positional or option password would expose it in process listings."""
    arguments = parse_arguments(["first-admin"])
    assert arguments.username == "first-admin"

    supplied_password = secrets.token_urlsafe(12)
    with pytest.raises(SystemExit):
        parse_arguments(["first-admin", supplied_password])
    with pytest.raises(SystemExit):
        parse_arguments(["first-admin", "--password", supplied_password])
    assert supplied_password not in capsys.readouterr().err


@pytest.mark.asyncio
async def test_bootstrap_stores_only_an_argon2id_digest_for_the_first_admin() -> None:
    """Persisting the raw bootstrap password would compromise the first administrator."""
    session = _BootstrapSession()
    password = secrets.token_urlsafe(24)

    user = await bootstrap_first_admin(
        session,
        "first-admin",
        password,
        request_id="bootstrap-request",
    )

    assert len(session.added) == 2
    assert session.added[0] is user
    audit = session.added[1]
    assert isinstance(audit, AuditEvent)
    assert audit.actor_kind == "system"
    assert audit.actor_identifier == "bootstrap-cli"
    assert audit.action == "admin.created"
    assert audit.object_kind == "admin_user"
    assert audit.object_identifier == str(user.id)
    assert audit.request_id == "bootstrap-request"
    assert audit.details == {"username": "first-admin"}
    assert session.commit_calls == 1
    assert session.rollback_calls == 0
    assert isinstance(user, AdminUser)
    assert user.username == "first-admin"
    assert user.password_digest.startswith("$argon2id$")
    assert password not in user.password_digest
    assert verify_password(user.password_digest, password)
    assert session.events == ["lock", "count", "add", "add", "commit"]

    occupied_session = _BootstrapSession(existing_admins=1)
    with pytest.raises(RuntimeError, match="already exists"):
        await bootstrap_first_admin(
            occupied_session,
            "second-admin",
            password,
            request_id="occupied-request",
        )
    assert occupied_session.added == []


@pytest.mark.asyncio
async def test_bootstrap_rolls_back_admin_when_audit_append_fails() -> None:
    """An administrator must not persist if its required audit row cannot be added."""
    session = _BootstrapSession(fail_audit=True)

    with pytest.raises(RuntimeError, match="injected audit failure"):
        await bootstrap_first_admin(
            session,
            "first-admin",
            secrets.token_urlsafe(24),
            request_id="bootstrap-failure",
        )

    assert session.added == []
    assert session.commit_calls == 0
    assert session.rollback_calls == 1


@pytest.mark.asyncio
async def test_concurrent_bootstrap_creates_exactly_one_first_admin(
    auth_database_url: str,
) -> None:
    """Different concurrent usernames must not both pass the first-admin check."""
    usernames = [f"first-admin-{index}" for index in range(4)]

    async def attempt(username: str) -> str | None:
        provider = create_session_provider(auth_database_url)
        try:
            async with provider() as session:
                try:
                    user = await bootstrap_first_admin(
                        session,
                        username,
                        secrets.token_urlsafe(24),
                        request_id=f"bootstrap-{username}",
                    )
                except RuntimeError:
                    return None
                return user.username
        finally:
            await provider.close()

    results = await asyncio.gather(*(attempt(username) for username in usernames))

    provider = create_session_provider(auth_database_url)
    try:
        async with provider() as session:
            persisted_count = await session.scalar(select(func.count(AdminUser.id)))
    finally:
        await provider.close()

    assert sum(result is not None for result in results) == 1
    assert persisted_count == 1


def test_issued_session_uses_32_random_bytes_and_persists_only_hmac_digest() -> None:
    """Storing the bearer token itself would turn a database leak into session takeover."""
    session_secret = secrets.token_bytes(32)
    now = datetime(2026, 7, 29, 10, tzinfo=UTC)
    issued = issue_admin_session(
        uuid4(),
        session_secret,
        now=now,
        lifetime=timedelta(hours=2),
    )

    assert len(_decode_urlsafe(issued.token)) == SESSION_TOKEN_BYTES == 32
    expected_digest = hmac.new(
        session_secret, issued.token.encode("ascii"), hashlib.sha256
    ).hexdigest()
    assert issued.record.session_digest == expected_digest
    assert issued.token not in repr(issued.record)
    assert issued.token not in issued.record.session_digest
    assert issued.record.expires_at == now + timedelta(hours=2)
    assert issued.csrf_token != issued.token


def test_session_expiration_and_revocation_are_fail_closed() -> None:
    """Expired or revoked bearer cookies must never authenticate an administrator."""
    now = datetime(2026, 7, 29, 10, tzinfo=UTC)
    issued = issue_admin_session(
        uuid4(),
        secrets.token_bytes(32),
        now=now,
        lifetime=timedelta(minutes=30),
    )

    assert session_is_active(issued.record, now=now)
    assert not session_is_active(
        issued.record, now=now + timedelta(minutes=30)
    )

    revoked_at = now + timedelta(minutes=1)
    revoke_admin_session(issued.record, now=revoked_at)
    assert issued.record.revoked_at == revoked_at
    assert not session_is_active(issued.record, now=revoked_at)


def test_session_cookie_is_secure_http_only_and_strict() -> None:
    """Relaxing any cookie attribute would expose the administrator bearer token."""
    response = Response()
    expires_at = datetime.now(UTC) + timedelta(hours=1)

    set_admin_session_cookie(response, "opaque-session", expires_at)

    cookie = response.headers["set-cookie"]
    assert cookie.startswith(f"{ADMIN_SESSION_COOKIE}=opaque-session;")
    assert "HttpOnly" in cookie
    assert "Secure" in cookie
    assert "SameSite=strict" in cookie
    assert "Path=/" in cookie


@pytest.mark.asyncio
async def test_unsafe_methods_require_matching_per_session_csrf_token() -> None:
    """A missing or mismatched CSRF header must not authorize state changes."""
    token = secrets.token_urlsafe(32)
    session_secret = secrets.token_bytes(32)

    with pytest.raises(HTTPException) as missing:
        enforce_csrf(_request("POST"), token, session_secret)
    assert missing.value.status_code == 403

    with pytest.raises(HTTPException) as mismatch:
        enforce_csrf(
            _request("DELETE", csrf_header=secrets.token_urlsafe(32)),
            token,
            session_secret,
        )
    assert mismatch.value.status_code == 403

    from endpoint_server.auth.csrf import csrf_token_for_session

    csrf_token = csrf_token_for_session(token, session_secret)
    enforce_csrf(_request("PATCH", csrf_header=csrf_token), token, session_secret)
    enforce_csrf(_request("GET"), token, session_secret)


@pytest.mark.parametrize(
    "malformed_header",
    [
        "é" * 43,
        "A" * 42,
        "A" * 44,
        "!" * 43,
        "A=" + "A" * 41,
    ],
)
def test_malformed_csrf_header_is_rejected_without_server_error(
    malformed_header: str,
) -> None:
    """Malformed attacker-controlled header text must fail closed instead of raising."""
    with pytest.raises(HTTPException) as rejected:
        enforce_csrf(
            _request("POST", csrf_header=malformed_header),
            secrets.token_urlsafe(32),
            secrets.token_bytes(32),
        )

    assert rejected.value.status_code == 403


@pytest.mark.asyncio
async def test_login_persists_only_digest_and_sets_protected_cookie() -> None:
    """A successful login must not persist or return the bearer token outside its cookie."""
    password = secrets.token_urlsafe(24)
    user = _admin_user(password)
    session = _AuthSession(user=user)
    app = create_app(
        _settings(secrets.token_bytes(32)),
        session_provider=_AuthSessionProvider(session),
    )

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="https://endpoint.sosnadmin.local",
    ) as client:
        response = await client.post(
            "/api/admin/session",
            json={"username": user.username, "password": password},
            headers={"X-Request-ID": "login-request"},
        )

    assert response.status_code == 201
    assert set(response.json()) == {"csrf_token"}
    cookie = response.headers["set-cookie"]
    raw_token = cookie.split("=", 1)[1].split(";", 1)[0]
    assert len(_decode_urlsafe(raw_token)) == 32
    assert "HttpOnly" in cookie
    assert "Secure" in cookie
    assert "SameSite=strict" in cookie
    assert session.commit_calls == 1
    assert len(session.added) == 2
    record, audit = session.added
    assert isinstance(record, AdminSession)
    assert isinstance(audit, AuditEvent)
    assert audit.actor_kind == "admin"
    assert audit.actor_identifier == str(user.id)
    assert audit.action == "admin_session.created"
    assert audit.object_kind == "admin_session"
    assert audit.object_identifier == str(record.id)
    assert audit.request_id == "login-request"
    assert audit.details == {"username": "first-admin"}
    assert record.session_digest != raw_token
    assert raw_token not in record.session_digest
    assert raw_token not in response.text


@pytest.mark.asyncio
async def test_login_rolls_back_session_when_audit_append_fails() -> None:
    """A login session must not persist without its attributed audit event."""
    password = secrets.token_urlsafe(24)
    user = _admin_user(password)
    session = _AuthSession(user=user, fail_audit=True)
    app = create_app(
        _settings(secrets.token_bytes(32)),
        session_provider=_AuthSessionProvider(session),
    )

    with pytest.raises(RuntimeError, match="injected audit failure"):
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="https://endpoint.sosnadmin.local",
        ) as client:
            await client.post(
                "/api/admin/session",
                json={"username": user.username, "password": password},
                headers={"X-Request-ID": "login-failure"},
            )

    assert session.added == []
    assert session.commit_calls == 0
    assert session.rollback_calls == 1


@pytest.mark.asyncio
async def test_disabled_admin_cannot_login() -> None:
    """A disabled account returned by a stale or permissive query must still be denied."""
    password = secrets.token_urlsafe(24)
    user = _admin_user(password)
    user.disabled_at = datetime.now(UTC)
    session = _AuthSession(user=user)
    app = create_app(
        _settings(secrets.token_bytes(32)),
        session_provider=_AuthSessionProvider(session),
    )

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="https://endpoint.sosnadmin.local",
    ) as client:
        response = await client.post(
            "/api/admin/session",
            json={"username": user.username, "password": password},
        )

    assert response.status_code == 401
    assert session.added == []
    assert session.commit_calls == 0


@pytest.mark.asyncio
async def test_validation_error_does_not_reflect_malformed_password_input() -> None:
    """FastAPI's 422 payload must not echo malformed secret-bearing field input."""
    secret_marker = f"validation-leak-{secrets.token_urlsafe(16)}"
    app = create_app(
        _settings(secrets.token_bytes(32)),
        session_provider=_AuthSessionProvider(_AuthSession()),
    )

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="https://endpoint.sosnadmin.local",
    ) as client:
        response = await client.post(
            "/api/admin/session",
            json={"username": "first-admin", "password": [secret_marker]},
        )

    assert response.status_code == 422
    assert secret_marker not in response.text
    assert all("input" not in error for error in response.json()["detail"])


@pytest.mark.asyncio
async def test_require_admin_checks_cookie_state_user_state_and_csrf() -> None:
    """Bypassing any session, user, or CSRF check would authorize an invalid request."""
    session_secret = secrets.token_bytes(32)
    issued = issue_admin_session(uuid4(), session_secret)
    user = AdminUser(
        id=issued.record.admin_user_id,
        username="first-admin",
        password_digest=hash_password(secrets.token_urlsafe(24)),
        disabled_at=None,
    )
    provider = _AuthSessionProvider(
        _AuthSession(user=user, admin_session=issued.record)
    )
    csrf = issued.csrf_token

    def protected_request(
        method: str,
        *,
        token: str = issued.token,
        csrf_header: str | None = None,
    ) -> Request:
        headers = [(b"cookie", f"{ADMIN_SESSION_COOKIE}={token}".encode("ascii"))]
        if csrf_header is not None:
            headers.append((CSRF_HEADER.encode("ascii"), csrf_header.encode("ascii")))
        return Request(
            {
                "type": "http",
                "method": method,
                "path": "/protected",
                "headers": headers,
                "app": SimpleNamespace(
                    state=SimpleNamespace(
                        settings=_settings(session_secret),
                        session_provider=provider,
                    )
                ),
            }
        )

    principal = await require_admin(protected_request("GET"))
    assert isinstance(principal, AdminPrincipal)
    assert principal.user.id == user.id

    with pytest.raises(HTTPException) as missing_csrf:
        await require_admin(protected_request("POST"))
    assert missing_csrf.value.status_code == 403

    principal = await require_admin(
        protected_request("POST", csrf_header=csrf)
    )
    assert principal.session.id == issued.record.id

    issued.record.revoked_at = datetime.now(UTC)
    with pytest.raises(HTTPException) as revoked:
        await require_admin(protected_request("GET"))
    assert revoked.value.status_code == 401

    issued.record.revoked_at = None
    user.disabled_at = datetime.now(UTC)
    with pytest.raises(HTTPException) as disabled:
        await require_admin(protected_request("GET"))
    assert disabled.value.status_code == 401

    with pytest.raises(HTTPException) as malformed:
        await require_admin(protected_request("GET", token="not-valid"))
    assert malformed.value.status_code == 401


@pytest.mark.asyncio
async def test_require_admin_rejects_expired_session() -> None:
    """An expired record returned from storage must fail at the dependency boundary."""
    session_secret = secrets.token_bytes(32)
    expired = issue_admin_session(
        uuid4(),
        session_secret,
        now=datetime.now(UTC) - timedelta(hours=2),
        lifetime=timedelta(hours=1),
    )
    user = AdminUser(
        id=expired.record.admin_user_id,
        username="first-admin",
        password_digest=hash_password(secrets.token_urlsafe(24)),
        disabled_at=None,
    )
    provider = _AuthSessionProvider(
        _AuthSession(user=user, admin_session=expired.record)
    )
    request = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/protected",
            "headers": [
                (
                    b"cookie",
                    f"{ADMIN_SESSION_COOKIE}={expired.token}".encode("ascii"),
                )
            ],
            "app": SimpleNamespace(
                state=SimpleNamespace(
                    settings=_settings(session_secret),
                    session_provider=provider,
                )
            ),
        }
    )

    with pytest.raises(HTTPException) as rejected:
        await require_admin(request)
    assert rejected.value.status_code == 401


@pytest.mark.asyncio
async def test_logout_requires_csrf_and_persists_session_revocation() -> None:
    """A logout that only clears the browser cookie would leave a stolen token active."""
    session_secret = secrets.token_bytes(32)
    user = _admin_user(secrets.token_urlsafe(24))
    issued = issue_admin_session(user.id, session_secret)
    session = _AuthSession(user=user, admin_session=issued.record)
    app = create_app(
        _settings(session_secret),
        session_provider=_AuthSessionProvider(session),
    )

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="https://endpoint.sosnadmin.local",
    ) as client:
        client.cookies.set(ADMIN_SESSION_COOKIE, issued.token)
        denied = await client.delete("/api/admin/session")
        response = await client.delete(
            "/api/admin/session",
            headers={
                CSRF_HEADER: issued.csrf_token,
                "X-Request-ID": "logout-request",
            },
        )

    assert denied.status_code == 403
    assert response.status_code == 204
    assert issued.record.revoked_at is not None
    assert session.commit_calls == 1
    assert session.rollback_calls == 0
    assert len(session.added) == 1
    audit = session.added[0]
    assert isinstance(audit, AuditEvent)
    assert audit.actor_kind == "admin"
    assert audit.actor_identifier == str(user.id)
    assert audit.action == "admin_session.revoked"
    assert audit.object_kind == "admin_session"
    assert audit.object_identifier == str(issued.record.id)
    assert audit.request_id == "logout-request"
    assert audit.details == {}
    cookie = response.headers["set-cookie"]
    assert f"{ADMIN_SESSION_COOKIE}=" in cookie
    assert "Max-Age=0" in cookie
    assert "HttpOnly" in cookie
    assert "Secure" in cookie
    assert "SameSite=strict" in cookie


@pytest.mark.asyncio
async def test_logout_rolls_back_revocation_when_audit_append_fails() -> None:
    """A session must remain active if its revocation audit event cannot be added."""
    session_secret = secrets.token_bytes(32)
    user = _admin_user(secrets.token_urlsafe(24))
    issued = issue_admin_session(user.id, session_secret)
    session = _AuthSession(
        user=user,
        admin_session=issued.record,
        fail_audit=True,
    )
    app = create_app(
        _settings(session_secret),
        session_provider=_AuthSessionProvider(session),
    )

    with pytest.raises(RuntimeError, match="injected audit failure"):
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="https://endpoint.sosnadmin.local",
        ) as client:
            client.cookies.set(ADMIN_SESSION_COOKIE, issued.token)
            await client.delete(
                "/api/admin/session",
                headers={
                    CSRF_HEADER: issued.csrf_token,
                    "X-Request-ID": "logout-failure",
                },
            )

    assert issued.record.revoked_at is None
    assert session.added == []
    assert session.commit_calls == 0
    assert session.rollback_calls == 1
