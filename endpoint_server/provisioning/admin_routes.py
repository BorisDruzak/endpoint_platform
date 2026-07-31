"""Administrator-only creation and revocation of ALT test-pilot credentials."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field, SecretStr

from endpoint_contracts.identity import normalize_install_session_id
from endpoint_server.audit.request_ids import audit_request_id
from endpoint_server.auth.admin_sessions import AdminPrincipal, require_admin

from .pilot_service import (
    issue_test_pilot_credential,
    revoke_test_pilot_credential,
)


router = APIRouter(
    prefix="/api/admin/provisioning/test-pilot",
    tags=["admin-test-pilot-provisioning"],
)


class PilotCredentialRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    install_session_id: str = Field(min_length=1, max_length=128)
    campaign_id: UUID
    hardware_fingerprint: SecretStr = Field(min_length=1, max_length=256)


class PilotCredentialResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    credential_id: UUID
    token: str
    expires_at: datetime


def _invalid() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        detail="Invalid test-pilot provisioning credential",
    )


@router.post(
    "/credentials",
    status_code=status.HTTP_201_CREATED,
    response_model=PilotCredentialResponse,
)
async def create_test_pilot_credential(
    body: PilotCredentialRequest,
    request: Request,
    principal: Annotated[AdminPrincipal, Depends(require_admin)],
) -> PilotCredentialResponse:
    """Show a short-lived single-scope controller bearer exactly once."""
    try:
        installation_id = normalize_install_session_id(body.install_session_id)
    except ValueError as error:
        raise _invalid() from error
    async with request.app.state.session_provider() as session:
        try:
            issued = await issue_test_pilot_credential(
                session,
                settings=request.app.state.settings,
                installation_id=installation_id,
                campaign_id=body.campaign_id,
                hardware_fingerprint=body.hardware_fingerprint.get_secret_value(),
                actor_id=str(principal.user.id),
                request_id=audit_request_id(request),
            )
            await session.commit()
        except ValueError as error:
            await session.rollback()
            raise _invalid() from error
        except Exception:
            await session.rollback()
            raise
    return PilotCredentialResponse(
        credential_id=issued.record.id,
        token=issued.token,
        expires_at=issued.record.expires_at,
    )


@router.post(
    "/credentials/{credential_id}/revoke",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    response_model=None,
)
async def revoke_test_pilot_credential_route(
    credential_id: UUID,
    request: Request,
    principal: Annotated[AdminPrincipal, Depends(require_admin)],
) -> None:
    """Idempotently revoke only credentials owned by the fixed pilot client."""
    async with request.app.state.session_provider() as session:
        try:
            changed = await revoke_test_pilot_credential(
                session,
                credential_id=credential_id,
                actor_id=str(principal.user.id),
                request_id=audit_request_id(request),
            )
            if changed:
                await session.commit()
        except Exception:
            await session.rollback()
            raise
