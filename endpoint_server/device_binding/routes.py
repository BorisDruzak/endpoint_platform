"""Device-authenticated creation and service-scoped possession redemption."""
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, Response, Security
from sqlalchemy import select

from endpoint_contracts.device_binding import (
    DeviceBindingCreateV1, DeviceBindingRedeemV1,
    DeviceBindingChallengeV1, DeviceBindingVerifiedV1, DeviceBindingErrorV1,
)
from endpoint_server.audit.service import append_audit_event
from endpoint_server.auth.scopes import DEVICE_BINDING_REDEEM_SCOPE, ServicePrincipal, require_service_scope
from endpoint_server.db.models import DeviceBindingChallenge
from endpoint_server.updates.agent_routes import _authenticate_device, _revalidate_device_principal
from endpoint_server.operations.routes import service_bearer
from endpoint_server.context.models import ContextCurrent, ContextSnapshot
from endpoint_server.context.projection import snapshot_projection

from .service import ChallengeThrottled, ChallengeUnavailable, consume_budget, create_challenge, redeem_challenge

REDEEM_SCOPE = DEVICE_BINDING_REDEEM_SCOPE
FAILED_REDEEM_LIMIT = 60
router = APIRouter(prefix="/api/v1/device-binding/challenges", tags=["device-binding"])
_ERROR_RESPONSES = {
    code: {"model": DeviceBindingErrorV1, "description": description}
    for code, description in {
        400: "Challenge unavailable",
        401: "Invalid credential",
        403: "Required scope or source policy missing",
        422: "Invalid binding request",
        429: "Challenge request throttled",
    }.items()
}


async def _audit(session, action, *, actor_kind, actor_identifier, object_identifier, device_id):
    await append_audit_event(session, actor_kind=actor_kind, actor_identifier=str(actor_identifier),
        action="device_binding."+action, object_kind="device_binding_challenge",
        object_identifier=str(object_identifier), request_id=uuid4().hex,
        details={"device_id":str(device_id), "purpose":"helpdesk_device_binding"})


async def _device_identity(session, device_id):
    """Select only hostname/platform from validated canonical current context."""
    snapshots = (await session.scalars(select(ContextSnapshot).join(ContextCurrent,
        ContextCurrent.snapshot_id == ContextSnapshot.id).where(
        ContextCurrent.device_id == device_id, ContextSnapshot.device_id == device_id,
        ContextCurrent.profile == ContextSnapshot.profile,
        ContextCurrent.profile.in_(["inventory_v1","baseline_v1"])))).all()
    hostname, platform = None, "unknown"
    for snapshot in sorted(snapshots, key=lambda item:item.profile != "inventory_v1"):
        safe = snapshot_projection(snapshot)
        if safe is None:
            continue
        system = safe["sections"].get("system", {})
        if platform == "unknown" and system.get("platform") in {"windows","linux"}:
            platform = system["platform"]
        candidate = system.get("hostname")
        if hostname is None and isinstance(candidate, str) and 0 < len(candidate) <= 256:
            hostname = candidate
    return DeviceBindingVerifiedV1(device_id=device_id, hostname=hostname, platform=platform)


@router.post("", response_model=DeviceBindingChallengeV1,
    responses=_ERROR_RESPONSES,
    openapi_extra={"security":[{"AgentBearer":[]}]})
async def create(body: DeviceBindingCreateV1, request: Request, response: Response):
    response.headers["Cache-Control"] = "no-store"
    async with request.app.state.session_provider() as session:
        try:
            principal = await _authenticate_device(session, request)
            await consume_budget(session, "create:"+str(principal.device.id), limit=3, window_seconds=600)
            lifecycle_events = []
            result = await create_challenge(session, principal.device.id, request.app.state.settings.device_token_pepper,
                lifecycle_events=lifecycle_events)
            # Domain locks may have waited while another administrator revoked
            # or rotated the credential. Recheck under the existing auth locks.
            await _revalidate_device_principal(session, request, principal)
            for challenge_id, status in lifecycle_events:
                await _audit(session, "challenge_"+status, actor_kind="device",
                    actor_identifier=principal.device.id, object_identifier=challenge_id, device_id=principal.device.id)
            await _audit(session, "challenge_created", actor_kind="device", actor_identifier=principal.device.id,
                object_identifier=result.challenge_id, device_id=principal.device.id)
            await session.commit()
            return result
        except ChallengeThrottled:
            await session.commit()
            raise HTTPException(429, "Challenge request throttled", headers={"Retry-After":"600","Cache-Control":"no-store"}) from None
        except ChallengeUnavailable:
            await session.rollback()
            raise HTTPException(400, "Challenge unavailable", headers={"Cache-Control":"no-store"}) from None


@router.post("/redeem", response_model=DeviceBindingVerifiedV1,
    responses=_ERROR_RESPONSES,
    dependencies=[Security(service_bearer, scopes=[REDEEM_SCOPE])],
    openapi_extra={"x-required-scopes":[REDEEM_SCOPE]})
async def redeem(body: DeviceBindingRedeemV1, request: Request, response: Response,
                 principal: ServicePrincipal = Depends(require_service_scope(REDEEM_SCOPE))):
    response.headers["Cache-Control"] = "no-store"
    async with request.app.state.session_provider() as session:
        try:
            # A durable global bucket bounds distributed credential attacks;
            # per-client budgets survive token rotation and process restarts.
            await consume_budget(session, "redeem:global", limit=30, window_seconds=60)
            await consume_budget(session, "redeem:"+str(principal.client.id), limit=30, window_seconds=60)
            await consume_budget(session, "failed:"+str(principal.client.id), limit=FAILED_REDEEM_LIMIT, window_seconds=600, consume=False)
            device_id = await redeem_challenge(session, body.code, request.app.state.settings.device_token_pepper)
            challenge = await session.scalar(select(DeviceBindingChallenge).where(
                DeviceBindingChallenge.device_id == device_id,
                DeviceBindingChallenge.status == "redeemed").order_by(DeviceBindingChallenge.redeemed_at.desc()).limit(1))
            await _audit(session, "challenge_redeemed", actor_kind="service", actor_identifier=principal.client.id,
                object_identifier=challenge.id, device_id=device_id)
            result = await _device_identity(session, device_id)
            await session.commit()
            return result
        except ChallengeThrottled:
            await session.commit()
            raise HTTPException(429, "Challenge request throttled", headers={"Retry-After":"600","Cache-Control":"no-store"}) from None
        except ChallengeUnavailable as error:
            # Persist failed-attempt budgets and expired lifecycle state.
            await consume_budget(session, "failed:"+str(principal.client.id), limit=FAILED_REDEEM_LIMIT, window_seconds=600)
            if error.expired:
                challenge_id, device_id = error.expired
                await _audit(session, "challenge_expired", actor_kind="service", actor_identifier=principal.client.id,
                    object_identifier=challenge_id, device_id=device_id)
            await session.commit()
            raise HTTPException(400, "Challenge unavailable", headers={"Cache-Control":"no-store"}) from None
