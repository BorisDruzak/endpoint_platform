"""FastAPI authorization dependencies for exact service scopes."""

from __future__ import annotations

import hmac
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from fastapi import HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from endpoint_server.db.models import ServiceClient, ServiceCredential

from .service_tokens import (
    parse_service_token,
    service_credential_is_active,
    service_token_digest,
)


DEVICES_READ_SCOPE = "devices.read"
CONTEXT_READ_SCOPE = "context.read"
CONTEXT_COLLECT_SCOPE = "context.collect"
PROVISIONING_INSTALL_CLAIMS_ISSUE_SCOPE = "provisioning.install-claims.issue"


@dataclass(frozen=True, slots=True)
class ServicePrincipal:
    """Authenticated service client and credential authorizing a request."""

    client: ServiceClient
    credential: ServiceCredential


def _unauthorized() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid service credential",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def _load_service_principal(
    session: AsyncSession,
    token: str,
    service_token_pepper: bytes,
) -> ServicePrincipal | None:
    token_prefix = parse_service_token(token)
    if token_prefix is None:
        return None
    record = await session.scalar(
        select(ServiceCredential).where(ServiceCredential.token_prefix == token_prefix)
    )
    supplied_digest = service_token_digest(token, service_token_pepper)
    if (
        record is None
        or not hmac.compare_digest(record.secret_digest, supplied_digest)
        or not service_credential_is_active(record)
    ):
        return None
    client = await session.scalar(
        select(ServiceClient).where(ServiceClient.id == record.service_client_id)
    )
    if client is None or client.disabled_at is not None:
        return None
    return ServicePrincipal(client=client, credential=record)


def _bearer_token(request: Request) -> str | None:
    authorization = request.headers.get("authorization", "")
    scheme, separator, token = authorization.partition(" ")
    if scheme != "Bearer" or separator != " " or not token or " " in token:
        return None
    return token


def require_service_scope(
    scope: str,
) -> Callable[[Request], Awaitable[ServicePrincipal]]:
    """Build a dependency that requires literal membership of one service scope."""

    async def dependency(request: Request) -> ServicePrincipal:
        token = _bearer_token(request)
        if token is None:
            raise _unauthorized()
        async with request.app.state.session_provider() as session:
            principal = await _load_service_principal(
                session,
                token,
                request.app.state.settings.service_token_pepper,
            )
        if principal is None:
            raise _unauthorized()
        if scope not in principal.credential.scopes:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Required service scope is missing",
            )
        return principal

    return dependency
