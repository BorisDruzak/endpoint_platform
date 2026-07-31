"""Narrow service-credential lifecycle for the dedicated ALT test pilot."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from endpoint_contracts.identity import normalize_install_session_id
from endpoint_server.audit.service import append_audit_event
from endpoint_server.auth.scopes import PROVISIONING_INSTALL_CLAIMS_ISSUE_SCOPE
from endpoint_server.auth.service_tokens import (
    IssuedServiceCredential,
    create_service_credential,
    revoke_service_credential,
)
from endpoint_server.config import Settings
from endpoint_server.db.models import ServiceClient, ServiceCredential


PILOT_SERVICE_CLIENT_IDENTIFIER = "alt-test-pilot"
_PILOT_SERVICE_DISPLAY_NAME = "ALT test pilot"
PILOT_CREDENTIAL_LIFETIME = timedelta(minutes=15)


async def _pilot_service_client(
    session: AsyncSession, *, create: bool
) -> ServiceClient | None:
    client = await session.scalar(
        select(ServiceClient).where(
            ServiceClient.client_identifier == PILOT_SERVICE_CLIENT_IDENTIFIER
        )
    )
    if client is None:
        if not create:
            return None
        client = ServiceClient(
            id=uuid4(),
            client_identifier=PILOT_SERVICE_CLIENT_IDENTIFIER,
            display_name=_PILOT_SERVICE_DISPLAY_NAME,
            disabled_at=None,
        )
        session.add(client)
    if client.disabled_at is not None:
        raise ValueError("test-pilot service client is disabled")
    return client


async def issue_test_pilot_credential(
    session: AsyncSession,
    *,
    settings: Settings,
    installation_id: str,
    actor_id: str,
    request_id: str,
    now: datetime | None = None,
) -> IssuedServiceCredential:
    """Issue the sole service scope needed to make one short install claim."""
    normalized_installation_id = normalize_install_session_id(installation_id)
    issued_at = now or datetime.now(UTC)
    if issued_at.tzinfo is None:
        raise ValueError("credential issuance time must be timezone-aware")
    client = await _pilot_service_client(session, create=True)
    assert client is not None
    issued = await create_service_credential(
        session,
        client.id,
        settings.service_token_pepper,
        actor_kind="admin",
        actor_identifier=actor_id,
        request_id=request_id,
        scopes=(PROVISIONING_INSTALL_CLAIMS_ISSUE_SCOPE,),
        expires_at=issued_at + PILOT_CREDENTIAL_LIFETIME,
        now=issued_at,
        commit=False,
    )
    await append_audit_event(
        session,
        actor_kind="admin",
        actor_identifier=actor_id,
        action="provisioning_test_pilot_credential.issued",
        object_kind="service_credential",
        object_identifier=str(issued.record.id),
        request_id=request_id,
        details={
            "expires_at": issued.record.expires_at,
            "installation_id": normalized_installation_id,
            "scope": PROVISIONING_INSTALL_CLAIMS_ISSUE_SCOPE,
        },
        occurred_at=issued_at,
    )
    return issued


async def revoke_test_pilot_credential(
    session: AsyncSession,
    *,
    credential_id: UUID,
    actor_id: str,
    request_id: str,
    now: datetime | None = None,
) -> bool:
    """Revoke a pilot credential once; repeats are intentionally harmless."""
    client = await _pilot_service_client(session, create=False)
    if client is None:
        return False
    credential = await session.scalar(
        select(ServiceCredential).where(
            ServiceCredential.id == credential_id,
            ServiceCredential.service_client_id == client.id,
        )
    )
    if credential is None or credential.revoked_at is not None:
        return False
    revoked_at = now or datetime.now(UTC)
    revoke_service_credential(credential, now=revoked_at)
    await append_audit_event(
        session,
        actor_kind="admin",
        actor_identifier=actor_id,
        action="provisioning_test_pilot_credential.revoked",
        object_kind="service_credential",
        object_identifier=str(credential.id),
        request_id=request_id,
        details={
            "expires_at": credential.expires_at,
            "scope": PROVISIONING_INSTALL_CLAIMS_ISSUE_SCOPE,
        },
        occurred_at=revoked_at,
    )
    return True


__all__ = [
    "PILOT_CREDENTIAL_LIFETIME",
    "PILOT_SERVICE_CLIENT_IDENTIFIER",
    "issue_test_pilot_credential",
    "revoke_test_pilot_credential",
]
