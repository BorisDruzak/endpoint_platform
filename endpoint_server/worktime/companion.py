"""Core-device authenticated delivery; OS account mapping never grants portal access."""
from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Request, Response
from sqlalchemy import exists, or_, select

from endpoint_contracts.worktime_companion import CompanionDeviceActionV1, CompanionDevicePollV1, CompanionReplyV1
from endpoint_server.activity.analytics_math import normalize_login, utc
from endpoint_server.updates.agent_routes import _authenticate_device
from endpoint_server.db.models.identity import ConfirmedIdentity
from .models import ActivityBinding, Explanation, ExplanationRequest, WorkState
from .companion_models import CompanionDelivery
from .domain import TIMEZONE, fully_covered, schedule_windows, union_windows
from .service import schedule_for


router = APIRouter(prefix='/agent/v1/gateway/worktime', tags=['agent-worktime'])


async def _eligible(session, device_id, user_login, now, request_id=None, *, authority_client=None, schedule_gate=True):
    key = normalize_login(user_login, device_id)
    if key is None:
        return key, []
    bindings = list((await session.scalars(select(ActivityBinding).where(
        ActivityBinding.device_id == device_id, ActivityBinding.user_key == key,
        ActivityBinding.valid_from <= now, ActivityBinding.valid_until > now,
    ).limit(129))).all())
    # Overlapping contradictory personnel attribution fails closed.
    people = {row.person_id for row in bindings}
    if len(people) != 1 or len(bindings) > 128:
        return key, []
    person = next(iter(people))
    # Keep the same identity -> WorkState lock ordering as personnel mutations.
    identity = await session.scalar(select(ConfirmedIdentity).where(ConfirmedIdentity.person_id == person).with_for_update())
    if identity is None or identity.state != 'active' or identity.revoked_at is not None or authority_client is None:
        return key, []
    try:
        current = await authority_client.resolve(identity.issuer, identity.subject, identity.ad_object_guid)
        if current.person_id != person:
            return key, []
    except Exception:
        return key, []
    await session.scalar(select(WorkState).where(WorkState.person_id == person).with_for_update())
    if schedule_gate:
        day = now.astimezone(ZoneInfo(TIMEZONE)).date()
        windows = []
        for shift_day in (day-timedelta(days=1), day):
            schedule = await schedule_for(session, person, shift_day)
            if schedule is not None:
                windows.extend(schedule_windows(schedule.definition, day, shift_days=(shift_day,)))
        if not any(start <= now < end for start, end in windows):
            return key, []
    query = select(ExplanationRequest).where(ExplanationRequest.person_id == person,
        ExplanationRequest.ended_at <= now,
        or_(*( (ExplanationRequest.started_at >= binding.valid_from) &
               (ExplanationRequest.ended_at <= binding.valid_until) for binding in bindings)),
        ~exists().where(Explanation.person_id == person, or_(
            Explanation.request_id == ExplanationRequest.id,
            (Explanation.started_at <= ExplanationRequest.started_at) &
            (Explanation.ended_at >= ExplanationRequest.ended_at))))
    if request_id is not None:
        query = query.where(ExplanationRequest.id == request_id)
    else:
        query = query.where(~exists().where(CompanionDelivery.request_id == ExplanationRequest.id,
            or_(CompanionDelivery.status != 'leased', CompanionDelivery.lease_until > now)))
    # At most two bounded pages per call. Persist covered markers so every later
    # call progresses even when a huge historical prefix is covered only by UNION.
    for _page in range(1 if request_id is not None else 2):
        rows = list((await session.scalars(query.order_by(ExplanationRequest.started_at,ExplanationRequest.id).limit(500))).all())
        if not rows:
            return key, []
        start = min(utc(row.started_at) for row in rows)
        end = max(utc(row.ended_at) for row in rows)
        explanations = list((await session.execute(select(Explanation.started_at, Explanation.ended_at).where(
            Explanation.person_id == person, Explanation.started_at < end, Explanation.ended_at > start).limit(20_001))).all())
        if len(explanations) > 20_000:
            return key, []
        covered = union_windows([(utc(a), utc(b)) for a, b in explanations])
        deliveries = {delivery.request_id: delivery for delivery in (await session.scalars(
            select(CompanionDelivery).where(CompanionDelivery.request_id.in_([row.id for row in rows])))).all()}
        eligible = []
        for row in rows:
            if not fully_covered(utc(row.started_at), utc(row.ended_at), covered):
                eligible.append(row)
                continue
            delivery = deliveries.get(row.id)
            if delivery is None:
                delivery = CompanionDelivery(request_id=row.id,device_id=device_id,user_key=key,lease_until=now)
                session.add(delivery)
            delivery.status = 'covered'
        await session.flush()
        if eligible:
            return key, eligible
    return key, []


def _reply(row, origin, delivery):
    from endpoint_server.identity.helpdesk_client import https_origin
    origin = https_origin(origin)
    day = utc(row.started_at).astimezone(ZoneInfo('Asia/Yekaterinburg')).date()
    return CompanionReplyV1(request_id=row.id, lease_id=delivery.lease_id, day=day,
        portal_url=f'{origin.rstrip("/")}/employee?day={day.isoformat()}&request_id={row.id}')


async def poll(session, *, device_id, user_login, origin, now=None, authority_client=None):
    now = now or datetime.now(UTC)
    key, requests = await _eligible(session, device_id, user_login, now, authority_client=authority_client)
    for row in requests:
        delivery = await session.scalar(select(CompanionDelivery).where(CompanionDelivery.request_id == row.id))
        if delivery is None:
            delivery = CompanionDelivery(request_id=row.id, device_id=device_id, user_key=key,
                status='leased', lease_until=now + timedelta(seconds=90))
            session.add(delivery)
        elif delivery.status != 'leased':
            continue
        elif utc(delivery.lease_until) > now:
            continue
        else:
            delivery.device_id, delivery.user_key = device_id, key
            delivery.lease_id = uuid4()
            delivery.lease_until = now + timedelta(seconds=90)
        await session.flush()
        return _reply(row, origin, delivery)
    return CompanionReplyV1()


async def acknowledge(session, *, device_id, body, origin, now=None, authority_client=None):
    now = now or datetime.now(UTC)
    key, requests = await _eligible(session, device_id, body.user_login, now, body.request_id,
        authority_client=authority_client, schedule_gate=body.action == 'present')
    row = next((item for item in requests if item.id == body.request_id), None)
    delivery = await session.scalar(select(CompanionDelivery).where(CompanionDelivery.request_id == body.request_id))
    if (row is None or delivery is None or delivery.device_id != device_id or delivery.user_key != key
            or delivery.lease_id != body.lease_id):
        raise HTTPException(404, 'WorkTime request unavailable')
    if body.action == 'present':
        if delivery.status != 'leased' or utc(delivery.lease_until) <= now:
            raise HTTPException(404, 'WorkTime request unavailable')
        # This accepted presentation is never automatically reassigned. A stale
        # lease can never race another device into presenting the same request.
        delivery.status = 'presented'
        return _reply(row, origin, delivery)
    if body.action == 'failed':
        if delivery.status != 'presented':
            raise HTTPException(404, 'WorkTime request unavailable')
        delivery.status, delivery.lease_until = 'leased', now
        delivery.lease_id = uuid4()
        return CompanionReplyV1()
    if delivery.status not in {'presented','displayed','reason','later'}:
        raise HTTPException(404, 'WorkTime request unavailable')
    if delivery.status == 'presented' or body.action in {'reason', 'later'}:
        delivery.status = body.action
    return _reply(row, origin, delivery) if body.action == 'reason' else CompanionReplyV1()


def _origin(request):
    # Fixed operator configuration; never Host or user-supplied redirect input.
    return request.app.state.settings.public_base_url


@router.post('/next', response_model=CompanionReplyV1)
async def next_notification(body: CompanionDevicePollV1, request: Request, response: Response):
    response.headers['Cache-Control'] = 'no-store'
    if not getattr(request.app.state.settings, 'worktime_enabled', False):
        raise HTTPException(404, 'WorkTime disabled')
    async with request.app.state.session_provider() as session:
        principal = await _authenticate_device(session, request)
        reply = await poll(session, device_id=principal.device.id, user_login=body.user_login, origin=_origin(request),
            authority_client=getattr(request.app.state,'helpdesk_identity_client',None))
        await session.commit()
        return reply


@router.post('/ack', response_model=CompanionReplyV1)
async def notification_action(body: CompanionDeviceActionV1, request: Request, response: Response):
    response.headers['Cache-Control'] = 'no-store'
    if not getattr(request.app.state.settings, 'worktime_enabled', False):
        raise HTTPException(404, 'WorkTime disabled')
    async with request.app.state.session_provider() as session:
        principal = await _authenticate_device(session, request)
        reply = await acknowledge(session, device_id=principal.device.id, body=body, origin=_origin(request),
            authority_client=getattr(request.app.state,'helpdesk_identity_client',None))
        await session.commit()
        return reply
