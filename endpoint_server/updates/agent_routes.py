"""Device-authenticated update recommendation and result routes."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query, Request, Response, status
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict
from sqlalchemy import and_, or_, select

from endpoint_contracts import (
    AgentUpdateAcknowledgementV1,
    AgentUpdateRecommendationV1,
    AgentUpdateReportV1,
)
from endpoint_server.audit.request_ids import audit_request_id
from endpoint_server.db.models import (
    Device,
    DeviceCredential,
    UpdateBuild,
    UpdateRollout,
    UpdateTarget,
)
from endpoint_server.enrollment.credentials import (
    device_credential_accepts_token,
    device_token_digest,
    device_token_matches,
)
from endpoint_server.network import observed_client_address

from .errors import (
    UpdateConflict,
    UpdateError,
    UpdateNotFound,
    UpdateStateError,
    UpdateValidationError,
)
from .service import recommendation_for_device, record_ack, record_report


router = APIRouter(prefix="/agent/v1/updates", tags=["agent-updates"])
_DELIVERABLE_TARGET_STATUSES = ("assigned", "requested", "scheduled")


@dataclass(frozen=True, slots=True)
class DevicePrincipal:
    device: Device
    credential: DeviceCredential


class AgentUpdateRecommendationQuery(BaseModel):
    """Strict compatibility selectors; device identity is never a query field."""

    model_config = ConfigDict(extra="forbid")

    platform: Literal["linux_amd64", "windows_amd64"]
    channel: Literal["stable", "canary"]


def _invalid_credential() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid device credential",
        headers={"WWW-Authenticate": "Bearer"},
    )


def _operation_unavailable() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="Update operation unavailable",
    )


def _bearer_token(request: Request) -> str:
    authorization = request.headers.get("authorization", "")
    scheme, separator, token = authorization.partition(" ")
    if (
        not separator
        or scheme.lower() != "bearer"
        or not token
        or token != token.strip()
        or " " in token
    ):
        raise _invalid_credential()
    return token


def _require_agent_source(request: Request) -> None:
    try:
        source = observed_client_address(request)
    except ValueError as error:
        raise _invalid_credential() from error
    if not any(
        source in network for network in request.app.state.settings.allowed_agent_cidrs
    ):
        raise _invalid_credential()


async def _authenticate_device(session, request: Request) -> DevicePrincipal:
    _require_agent_source(request)
    token = _bearer_token(request)
    pepper = request.app.state.settings.device_token_pepper
    try:
        digest = device_token_digest(token, pepper)
    except ValueError as error:
        raise _invalid_credential() from error
    credentials = (
        await session.scalars(
            select(DeviceCredential)
            .where(
                or_(
                    DeviceCredential.token_digest == digest,
                    DeviceCredential.pending_token_digest == digest,
                )
            )
            .order_by(DeviceCredential.id)
            .limit(2)
        )
    ).all()
    if len(credentials) != 1:
        raise _invalid_credential()
    credential = credentials[0]
    checked_at = datetime.now(UTC)
    if (
        credential is None
        or not (
            device_token_matches(token, credential.token_digest, pepper)
            or (
                credential.pending_token_digest is not None
                and device_token_matches(
                    token,
                    credential.pending_token_digest,
                    pepper,
                )
            )
        )
        or not device_credential_accepts_token(
            credential,
            token,
            pepper,
            now=checked_at,
        )
    ):
        raise _invalid_credential()
    device = await session.scalar(
        select(Device).where(
            Device.id == credential.device_id,
            Device.retired_at.is_(None),
        )
    )
    if device is None:
        raise _invalid_credential()
    return DevicePrincipal(device=device, credential=credential)


async def _revalidate_device_principal(
    session,
    request: Request,
    principal: DevicePrincipal,
) -> None:
    """Lock and recheck one bearer only after update domain state is locked."""
    _require_agent_source(request)
    token = _bearer_token(request)
    pepper = request.app.state.settings.device_token_pepper
    device = await session.scalar(
        select(Device)
        .where(
            Device.id == principal.device.id,
            Device.retired_at.is_(None),
        )
        .execution_options(populate_existing=True)
        .with_for_update()
    )
    credential = await session.scalar(
        select(DeviceCredential)
        .where(
            DeviceCredential.id == principal.credential.id,
            DeviceCredential.device_id == principal.device.id,
        )
        .execution_options(populate_existing=True)
        .with_for_update()
    )
    checked_at = datetime.now(UTC)
    if (
        device is None
        or credential is None
        or not device_credential_accepts_token(
            credential,
            token,
            pepper,
            now=checked_at,
        )
    ):
        raise _invalid_credential()


def _agent_error(error: UpdateError) -> HTTPException:
    if isinstance(error, UpdateConflict):
        return HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Update operation conflicts with current state",
        )
    if isinstance(
        error,
        (UpdateNotFound, UpdateStateError, UpdateValidationError),
    ):
        return _operation_unavailable()
    return _operation_unavailable()


def _artifact_path(root: Path, identifier: str) -> Path | None:
    """Resolve only one controller-owned regular artifact inside the fixed root."""
    if not identifier or Path(identifier).name != identifier:
        return None
    try:
        root_resolved = root.resolve(strict=True)
        artifact = (root_resolved / identifier).resolve(strict=True)
        artifact.relative_to(root_resolved)
    except (OSError, ValueError):
        return None
    if artifact.is_symlink() or not artifact.is_file():
        return None
    return artifact


@router.get("/artifacts/{build_identifier}", response_model=None)
async def download_update_artifact(
    build_identifier: str, request: Request
) -> Response:
    """Deliver one assigned build only to the authenticated assigned device."""
    async with request.app.state.session_provider() as session:
        principal = await _authenticate_device(session, request)
        build = await session.scalar(
            select(UpdateBuild)
            .join(UpdateRollout, UpdateRollout.build_id == UpdateBuild.id)
            .join(UpdateTarget, UpdateTarget.rollout_id == UpdateRollout.id)
            .where(
                and_(
                    UpdateBuild.build_identifier == build_identifier,
                    UpdateTarget.device_id == principal.device.id,
                    UpdateTarget.status.in_(_DELIVERABLE_TARGET_STATUSES),
                    UpdateRollout.status == "active",
                )
            )
            .order_by(UpdateTarget.assigned_at.desc())
        )
        if build is None:
            return Response(status_code=status.HTTP_404_NOT_FOUND)
        artifact = _artifact_path(
            request.app.state.settings.artifact_root, build.artifact_identifier
        )
        if artifact is None or artifact.stat().st_size != build.size:
            return Response(status_code=status.HTTP_404_NOT_FOUND)
    return FileResponse(artifact, media_type="application/gzip")


@router.get(
    "/recommendation",
    response_model=AgentUpdateRecommendationV1,
    responses={status.HTTP_204_NO_CONTENT: {"description": "No assignment"}},
)
async def get_update_recommendation(
    request: Request,
    query: Annotated[AgentUpdateRecommendationQuery, Query()],
) -> AgentUpdateRecommendationV1 | Response:
    """Return only the authenticated device's active compatible assignment."""
    async with request.app.state.session_provider() as session:
        principal = await _authenticate_device(session, request)
        recommendation = await recommendation_for_device(
            session,
            principal.device.id,
            query.platform,
        )
        if recommendation is None or recommendation.channel != query.channel:
            return Response(status_code=status.HTTP_204_NO_CONTENT)
        return recommendation


@router.post(
    "/{operation_id}/ack",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    response_model=None,
)
async def acknowledge_update(
    operation_id: UUID,
    body: AgentUpdateAcknowledgementV1,
    request: Request,
) -> None:
    """Record a monotonic acknowledgement for the authenticated device."""
    async with request.app.state.session_provider() as session:
        try:
            principal = await _authenticate_device(session, request)

            async def revalidate_authorization() -> None:
                await _revalidate_device_principal(session, request, principal)

            await record_ack(
                session,
                device_id=principal.device.id,
                operation_id=operation_id,
                acknowledgement=body,
                request_id=audit_request_id(request),
                authorization_revalidator=revalidate_authorization,
            )
            await session.commit()
        except HTTPException:
            await session.rollback()
            raise
        except UpdateError as error:
            await session.rollback()
            raise _agent_error(error) from error
        except Exception:
            await session.rollback()
            raise


@router.post(
    "/{operation_id}/reports",
    status_code=status.HTTP_200_OK,
    response_class=Response,
    response_model=None,
)
async def report_update_outcome(
    operation_id: UUID,
    body: AgentUpdateReportV1,
    request: Request,
) -> None:
    """Persist one idempotent terminal launcher/handshake outcome."""
    async with request.app.state.session_provider() as session:
        try:
            principal = await _authenticate_device(session, request)

            async def revalidate_authorization() -> None:
                await _revalidate_device_principal(session, request, principal)

            await record_report(
                session,
                device_id=principal.device.id,
                operation_id=operation_id,
                report=body,
                request_id=audit_request_id(request),
                authorization_revalidator=revalidate_authorization,
            )
            await session.commit()
        except HTTPException:
            await session.rollback()
            raise
        except UpdateError as error:
            await session.rollback()
            raise _agent_error(error) from error
        except Exception:
            await session.rollback()
            raise


__all__ = ["router"]
