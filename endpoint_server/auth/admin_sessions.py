"""Opaque administrator sessions."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field, SecretStr
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from endpoint_server.audit.request_ids import audit_request_id
from endpoint_server.audit.service import append_audit_event
from endpoint_server.db.models import AdminSession, AdminUser

from .csrf import csrf_token_for_session, enforce_csrf
from .passwords import hash_password, verify_password


ADMIN_SESSION_COOKIE = "endpoint_admin_session"
ADMIN_UPDATE_SCOPE = "updates:write"
SESSION_TOKEN_BYTES = 32
DEFAULT_SESSION_LIFETIME = timedelta(hours=8)
router = APIRouter(prefix="/api/admin", tags=["admin-authentication"])
_DUMMY_PASSWORD_DIGEST = hash_password(secrets.token_urlsafe(32))


@dataclass(frozen=True, slots=True)
class IssuedAdminSession:
    """Raw one-time session material paired with its persistence record."""

    token: str = field(repr=False)
    csrf_token: str = field(repr=False)
    record: AdminSession


@dataclass(frozen=True, slots=True)
class AdminPrincipal:
    """Authenticated administrator and the session that authorized the request."""

    user: AdminUser
    session: AdminSession


class AdminLoginRequest(BaseModel):
    """Validated JSON credentials for the local administrator login."""

    username: str = Field(min_length=1, max_length=128)
    password: SecretStr


def normalize_admin_scopes(scopes: Iterable[str]) -> list[str]:
    """Return sorted exact persisted grants, rejecting ambiguous scope input."""
    if isinstance(scopes, (str, bytes)):
        raise ValueError("admin scopes must be provided as a scope collection")
    normalized: list[str] = []
    for scope in scopes:
        if (
            not isinstance(scope, str)
            or not scope
            or scope != scope.strip()
            or not scope.isascii()
            or len(scope) > 128
            or any(ord(character) < 32 or ord(character) > 126 for character in scope)
        ):
            raise ValueError("admin scopes must be non-empty printable ASCII")
        normalized.append(scope)
    return sorted(set(normalized))


def _unauthorized() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid administrator session",
    )


def _is_opaque_session_token(value: str) -> bool:
    try:
        decoded = base64.b64decode(
            value + "=" * (-len(value) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, UnicodeEncodeError):
        return False
    return len(decoded) == SESSION_TOKEN_BYTES


async def local_password_policy(session,user,settings,*,record=None):
    """Migrated identities need OIDC, or a newly issued bounded emergency session."""
    oidc=getattr(settings,'oidc',None)
    migrated=getattr(user,'sso_migrated_at',None) is not None
    if not migrated and oidc is not None and oidc.enabled:
        from endpoint_server.db.models.identity import ConfirmedIdentity
        migrated=await session.scalar(select(ConfirmedIdentity.id).where(ConfirmedIdentity.admin_user_id==user.id)) is not None
    if not migrated and (record is None or record.auth_method!='breakglass'):
        return True,False
    now=datetime.now(UTC)
    until=getattr(oidc,'breakglass_until',None)
    allowed=(user.username in getattr(oidc,'breakglass_usernames',()) and until is not None and until.tzinfo is not None and now<until)
    if record is not None:
        allowed=allowed and record.auth_method=='breakglass' and record.expires_at<=until
    return bool(allowed),bool(allowed)


async def _load_admin_principal(
    session: AsyncSession,
    session_token: str,
    session_secret: bytes,
    *,
    now: datetime | None = None,
    request: Request | None = None,
    commit_revalidation: bool = True,
) -> AdminPrincipal | None:
    if not _is_opaque_session_token(session_token):
        return None
    record = await session.scalar(
        select(AdminSession).where(
            AdminSession.session_digest == session_digest(session_token, session_secret)
        )
    )
    if record is None or record.revoked_at is not None or record.expires_at.tzinfo is None or (record.auth_method!='oidc' and not session_is_active(record,now=now)):
        return None
    user = await session.scalar(
        select(AdminUser).where(AdminUser.id == record.admin_user_id)
    )
    if user is None or user.disabled_at is not None:
        return None
    if record.auth_method == 'oidc':
        if request is None:
            return None
        from endpoint_server.db.models.identity import ConfirmedIdentity, UpstreamSession
        from endpoint_server.auth.oidc import revalidate_upstream
        upstream = await session.scalar(select(UpstreamSession).where(UpstreamSession.admin_session_id == record.id))
        identity = await session.scalar(select(ConfirmedIdentity).where(ConfirmedIdentity.id == upstream.identity_id)) if upstream else None
        if identity is None or identity.admin_user_id != user.id:
            return None
        await revalidate_upstream(request,session,identity,upstream,'admin',commit=commit_revalidation)
    else:
        allowed,_=await local_password_policy(session,user,request.app.state.settings if request else None,record=record)
        if not allowed:
            return None
    return AdminPrincipal(user=user, session=record)


async def require_admin(request: Request) -> AdminPrincipal:
    """Authenticate the admin cookie and enforce CSRF for unsafe methods."""
    session_token = request.cookies.get(ADMIN_SESSION_COOKIE, "")
    if not session_token:
        raise _unauthorized()
    async with request.app.state.session_provider() as session:
        principal = await _load_admin_principal(
            session,
            session_token,
            request.app.state.settings.session_secret,
            request=request,
        )
    if principal is None:
        raise _unauthorized()
    enforce_csrf(
        request,
        session_token,
        request.app.state.settings.session_secret,
    )
    return principal


async def require_local_logout(request:Request)->AdminPrincipal:
    """Logout revokes local authority even when upstream/identity is unavailable."""
    raw=request.cookies.get(ADMIN_SESSION_COOKIE,'')
    if not _is_opaque_session_token(raw):
        raise _unauthorized()
    enforce_csrf(request,raw,request.app.state.settings.session_secret)
    async with request.app.state.session_provider() as session:
        record=await session.scalar(select(AdminSession).where(AdminSession.session_digest==session_digest(raw,request.app.state.settings.session_secret)))
        if record is None:
            raise _unauthorized()
        user=await session.scalar(select(AdminUser).where(AdminUser.id==record.admin_user_id))
        if user is None:
            raise _unauthorized()
    return AdminPrincipal(user,record)


async def require_admin_update_scope(
    request: Request,
    principal: AdminPrincipal = Depends(require_admin),
) -> AdminPrincipal:
    """Require an interactive session whose persisted user owns update writes."""
    del request
    try:
        normalized_scopes = normalize_admin_scopes(principal.user.scopes)
    except (TypeError, ValueError) as error:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Update administration scope is required",
        ) from error
    if (
        principal.user.scopes != normalized_scopes
        or ADMIN_UPDATE_SCOPE not in normalized_scopes
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Update administration scope is required",
        )
    return principal


async def load_update_admin_in_transaction(request: Request, session: AsyncSession) -> AdminPrincipal:
    """Load real cookie authority inside the cancellation supervisor's fresh session."""
    token = request.cookies.get(ADMIN_SESSION_COOKIE, "")
    principal = await _load_admin_principal(session, token, request.app.state.settings.session_secret, request=request, commit_revalidation=False)
    if principal is None:
        raise _unauthorized()
    enforce_csrf(request, token, request.app.state.settings.session_secret)
    return await require_admin_update_scope(request, principal=principal)


async def revalidate_update_admin_in_transaction(
    request: Request, session: AsyncSession, principal: AdminPrincipal, operation_budget,
) -> None:
    """Lock current user then session after domain waits, holding authority to commit."""
    operation_budget.check()
    user_id, session_id = principal.user.id, principal.session.id
    user = await session.scalar(select(AdminUser).where(AdminUser.id == user_id)
        .with_for_update().execution_options(populate_existing=True))
    record = await session.scalar(select(AdminSession).where(AdminSession.id == session_id)
        .with_for_update().execution_options(populate_existing=True))
    token = request.cookies.get(ADMIN_SESSION_COOKIE, "")
    secret = request.app.state.settings.session_secret
    if (user is None or user.disabled_at is not None or record is None
            or record.admin_user_id != user_id or not session_is_active(record)
            or not _is_opaque_session_token(token)
            or not hmac.compare_digest(record.session_digest, session_digest(token, secret))):
        raise _unauthorized()
    enforce_csrf(request, token, secret)
    if record.auth_method == 'oidc':
        reloaded = await _load_admin_principal(session,token,secret,request=request,commit_revalidation=False)
        if reloaded is None:
            raise _unauthorized()
    await require_admin_update_scope(request, principal=AdminPrincipal(user=user, session=record))
    operation_budget.check()


def session_digest(session_token: str, session_secret: bytes) -> str:
    """Return the HMAC-SHA256 value used for session lookup."""
    if not session_token or not session_secret:
        raise ValueError("session token and secret must not be empty")
    return hmac.new(
        session_secret, session_token.encode("ascii"), hashlib.sha256
    ).hexdigest()


def issue_admin_session(
    admin_user_id: UUID,
    session_secret: bytes,
    *,
    now: datetime | None = None,
    lifetime: timedelta = DEFAULT_SESSION_LIFETIME,
) -> IssuedAdminSession:
    """Create 32-byte opaque session material and an HMAC-only DB record."""
    issued_at = now or datetime.now(UTC)
    if issued_at.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    if lifetime <= timedelta(0):
        raise ValueError("session lifetime must be positive")

    raw_bytes = secrets.token_bytes(SESSION_TOKEN_BYTES)
    token = base64.urlsafe_b64encode(raw_bytes).rstrip(b"=").decode("ascii")
    record = AdminSession(
        id=uuid4(),
        admin_user_id=admin_user_id,
        session_digest=session_digest(token, session_secret),
        expires_at=issued_at + lifetime,
        revoked_at=None,
    )
    return IssuedAdminSession(
        token=token,
        csrf_token=csrf_token_for_session(token, session_secret),
        record=record,
    )


def session_is_active(record: AdminSession, *, now: datetime | None = None) -> bool:
    """Return whether a session is unrevoked and strictly before expiry."""
    checked_at = now or datetime.now(UTC)
    if checked_at.tzinfo is None or record.expires_at.tzinfo is None:
        return False
    return record.revoked_at is None and checked_at < record.expires_at


def revoke_admin_session(record: AdminSession, *, now: datetime | None = None) -> None:
    """Revoke a session while retaining its first revocation timestamp."""
    revoked_at = now or datetime.now(UTC)
    if revoked_at.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    if record.revoked_at is None:
        record.revoked_at = revoked_at


def set_admin_session_cookie(
    response: Response, session_token: str, expires_at: datetime
) -> None:
    """Set the opaque bearer token with strict browser protections."""
    if expires_at.tzinfo is None:
        raise ValueError("cookie expiry must be timezone-aware")
    max_age = max(0, int((expires_at - datetime.now(UTC)).total_seconds()))
    response.set_cookie(
        key=ADMIN_SESSION_COOKIE,
        value=session_token,
        max_age=max_age,
        expires=expires_at,
        path="/",
        secure=True,
        httponly=True,
        samesite="strict",
    )


@router.post("/session", status_code=status.HTTP_201_CREATED)
async def login_admin(
    credentials: AdminLoginRequest, request: Request, response: Response
) -> dict[str, str]:
    """Verify local credentials and issue an opaque administrator session."""
    async with request.app.state.session_provider() as session:
        user = await session.scalar(
            select(AdminUser).where(
                AdminUser.username == credentials.username,
                AdminUser.disabled_at.is_(None),
            )
        )
        password = credentials.password.get_secret_value()
        digest = user.password_digest if user is not None else _DUMMY_PASSWORD_DIGEST
        password_valid = verify_password(digest, password)
        if user is None or user.disabled_at is not None or not password_valid:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password",
            )
        allowed,emergency=await local_password_policy(session,user,request.app.state.settings)
        if not allowed:
            raise _unauthorized()
        lifetime=DEFAULT_SESSION_LIFETIME
        if emergency:
            lifetime=min(timedelta(hours=1),request.app.state.settings.oidc.breakglass_until-datetime.now(UTC))
        issued = issue_admin_session(
            user.id,
            request.app.state.settings.session_secret,
            lifetime=lifetime,
        )
        if emergency:
            issued.record.auth_method='breakglass'
        session.add(issued.record)
        try:
            await append_audit_event(
                session,
                actor_kind="admin",
                actor_identifier=str(user.id),
                action="admin_breakglass_session.created" if emergency else "admin_session.created",
                object_kind="admin_session",
                object_identifier=str(issued.record.id),
                request_id=audit_request_id(request),
                details={"username": user.username},
            )
            await session.commit()
        except Exception:
            await session.rollback()
            raise

    set_admin_session_cookie(response, issued.token, issued.record.expires_at)
    return {"csrf_token": issued.csrf_token}


@router.delete(
    "/session",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    response_model=None,
)
async def logout_admin(
    request: Request,
    response: Response,
    principal: AdminPrincipal = Depends(require_local_logout),
) -> None:
    """Persistently revoke the current administrator session."""
    async with request.app.state.session_provider() as session:
        managed_record = await session.merge(principal.session)
        revoke_admin_session(managed_record)
        if managed_record.auth_method=='oidc':
            from endpoint_server.db.models.identity import UpstreamSession
            upstream=await session.scalar(select(UpstreamSession).where(UpstreamSession.admin_session_id==managed_record.id).with_for_update())
            if upstream is not None:
                upstream.revoked_at=datetime.now(UTC)
        try:
            await append_audit_event(
                session,
                actor_kind="admin",
                actor_identifier=str(principal.user.id),
                action="admin_session.revoked",
                object_kind="admin_session",
                object_identifier=str(managed_record.id),
                request_id=audit_request_id(request),
                details={},
            )
            await session.commit()
        except Exception:
            await session.rollback()
            raise
    response.delete_cookie(
        ADMIN_SESSION_COOKIE,
        path="/",
        secure=True,
        httponly=True,
        samesite="strict",
    )
