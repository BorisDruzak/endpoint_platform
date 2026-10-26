"""Transactional personnel operations. Callers own commit/rollback and authorization."""
from datetime import UTC, date, datetime, timedelta
from calendar import monthrange
from bisect import bisect_left
from hashlib import sha256
import json
from types import SimpleNamespace
from uuid import UUID, uuid4, uuid5, NAMESPACE_URL
from zoneinfo import ZoneInfo

from sqlalchemy import delete, or_, select

from endpoint_server.activity.analytics_math import day_bounds, merged_segments
from endpoint_server.activity.analytics_models import ActivityInterval
from .domain import TIMEZONE, STATUSES, fully_covered, next_status, notification_candidates, project_work, schedule_windows, union_windows, utc
from .models import ActivityBinding, Approval, Audit, Category, Correction, Explanation, ExplanationRequest, RetentionPolicy, Schedule, Timesheet, TimesheetDay, WorkEvent, WorkState

DEFAULT_CATEGORIES = [
    dict(code='meeting', label='Совещание', requires_comment=False),
    dict(code='documents', label='Работа с документами', requires_comment=False),
    dict(code='off_pc', label='Работа вне компьютера', requires_comment=False),
    dict(code='lunch', label='Обед', requires_comment=False),
    dict(code='business', label='Служебный выход', requires_comment=False),
    dict(code='personal', label='Личные дела', requires_comment=False),
    dict(code='other', label='Другое', requires_comment=True),
]

MAX_PENDING_CANDIDATES = 20_000
MAX_PENDING_RESULTS = 500
PENDING_PAGE_SIZE = 500


class PersonnelHistoryExpired(ValueError):
    """A retained boundary marker prevents deleted history becoming apparent zeros."""


async def ensure_report_available(session, person_id, start):
    state = await session.get(WorkState,person_id)
    if state and state.records_expired_before and start < utc(state.records_expired_before):
        raise PersonnelHistoryExpired('Personnel history expired under the configured retention policy')


def fingerprint(payload):
    return sha256(json.dumps(payload, sort_keys=True, default=str, ensure_ascii=False).encode()).hexdigest()


def serialize(row):
    return {column.name: (utc(value).isoformat() if isinstance(value, datetime) else value.isoformat() if isinstance(value,date) else str(value) if isinstance(value, UUID) else value)
            for column in row.__table__.columns for value in [getattr(row, column.name)]
            if column.name != 'fingerprint'}


async def lock_person(session, person_id):
    """Identity lock also serializes initial row creation and all person writes."""
    # Identity imports are deferred so pure projections can run independently.
    from endpoint_server.db.models.identity import ConfirmedIdentity
    identity = await session.scalar(select(ConfirmedIdentity).where(ConfirmedIdentity.person_id == person_id).with_for_update())
    if identity is None or identity.state != 'active' or identity.revoked_at is not None:
        raise ValueError('Active confirmed person required')
    state = await session.scalar(select(WorkState).where(WorkState.person_id == person_id).with_for_update())
    if state is None:
        state = WorkState(person_id=person_id, status='ENDED')
        session.add(state)
        await session.flush()
    return state


async def replay(session, model, person_id, key, payload):
    previous = await session.scalar(select(model).where(model.person_id == person_id, model.idempotency_key == key))
    if previous is not None and previous.fingerprint != fingerprint(payload):
        raise ValueError('Idempotency key belongs to a different request')
    return previous


def audit(session, person_id, actor_id, action, record_id, now):
    session.add(Audit(person_id=person_id, actor_id=actor_id, action=action, record_id=record_id, created_at=now))


async def transition(session, person_id, actor_id, action, key, now):
    state = await lock_person(session, person_id)
    payload = dict(action=action)
    previous = await replay(session, WorkEvent, person_id, key, payload)
    if previous:
        return previous
    status = next_status(state.status, action)
    now = utc(now)
    if state.last_event_at is not None and now <= utc(state.last_event_at):
        raise ValueError('Transition time must follow the previous event')
    row = WorkEvent(id=uuid4(), person_id=person_id, actor_id=actor_id, idempotency_key=key,
                    fingerprint=fingerprint(payload), action=action, status=status, occurred_at=now, created_at=now)
    session.add(row)
    state.status, state.last_event_at = status, now
    audit(session, person_id, actor_id, 'transition', row.id, now)
    await session.flush()
    return row


def validate_interval(start, end, now, *, past=True):
    start, end, now = utc(start), utc(end), utc(now)
    if start >= end or end - start > timedelta(days=31) or (past and end > now):
        raise ValueError('Invalid interval: use an ordered past interval of at most 31 days')


async def categories(session):
    rows = (await session.scalars(select(Category).where(Category.enabled.is_(True)).order_by(Category.code))).all()
    configured = {row.code: dict(code=row.code, label=row.label, requires_comment=row.requires_comment) for row in rows}
    all_rows = (await session.scalars(select(Category.code))).all()
    return [configured.get(item['code'], item) for item in DEFAULT_CATEGORIES if item['code'] not in all_rows or item['code'] in configured] + [item for code, item in configured.items() if code not in {d['code'] for d in DEFAULT_CATEGORIES}]


async def explain(session, person_id, actor_id, start, end, code, comment, key, request_id, now):
    await lock_person(session, person_id)
    validate_interval(start, end, now)
    payload = dict(start=utc(start), end=utc(end), code=code, comment=comment, request_id=request_id)
    previous = await replay(session, Explanation, person_id, key, payload)
    if previous:
        return previous
    category = next((item for item in await categories(session) if item['code'] == code), None)
    if category is None or (category['requires_comment'] and not comment.strip()):
        raise ValueError('Select an enabled category and supply its required comment')
    if request_id:
        request = await session.get(ExplanationRequest, request_id)
        if request is None or request.person_id != person_id or utc(request.started_at) != utc(start) or utc(request.ended_at) != utc(end):
            raise ValueError('Explanation does not match the pending interval')
        if await session.scalar(select(Explanation.id).where(Explanation.request_id == request_id)):
            raise ValueError('This request is already explained')
    row = Explanation(id=uuid4(), person_id=person_id, actor_id=actor_id, idempotency_key=key, fingerprint=fingerprint(payload),
        started_at=utc(start), ended_at=utc(end), category_code=code, comment=comment.strip(), request_id=request_id, created_at=now)
    session.add(row)
    audit(session, person_id, actor_id, 'explanation', row.id, now)
    await session.flush()
    return row


async def request_correction(session, person_id, actor_id, start, end, status, reason, key, now):
    await lock_person(session, person_id)
    validate_interval(start, end, now)
    if status not in STATUSES or not reason.strip():
        raise ValueError('Correction requires a valid status and reason')
    payload = dict(start=utc(start), end=utc(end), status=status, reason=reason)
    previous = await replay(session, Correction, person_id, key, payload)
    if previous:
        return previous
    row = Correction(id=uuid4(), person_id=person_id, actor_id=actor_id, idempotency_key=key, fingerprint=fingerprint(payload),
        started_at=utc(start), ended_at=utc(end), status=status, reason=reason.strip(), created_at=now)
    session.add(row)
    audit(session, person_id, actor_id, 'correction_requested', row.id, now)
    await session.flush()
    return row


async def decide_correction(session, correction, actor_id, decision, comment, key, now):
    await lock_person(session, correction.person_id)
    if actor_id in (correction.person_id,correction.actor_id) or decision not in ('approved', 'rejected'):
        raise ValueError('A correction requires an independent authorized reviewer')
    payload = dict(correction_id=correction.id, decision=decision, comment=comment)
    previous = await session.scalar(select(Approval).where(Approval.correction_id == correction.id))
    if previous:
        if previous.idempotency_key != key or previous.fingerprint != fingerprint(payload) or previous.actor_id != actor_id:
            raise ValueError('Correction already has an immutable decision')
        return previous
    if await session.scalar(select(Approval.id).where(Approval.idempotency_key == key)):
        raise ValueError('Idempotency key belongs to another decision')
    row = Approval(id=uuid4(), correction_id=correction.id, actor_id=actor_id, decision=decision, comment=comment.strip(),
        idempotency_key=key, fingerprint=fingerprint(payload), created_at=now)
    session.add(row)
    audit(session, correction.person_id, actor_id, 'correction_' + decision, row.id, now)
    await session.flush()
    return row


async def schedule_for(session, person_id, day):
    return await session.scalar(select(Schedule).where(Schedule.person_id == person_id, Schedule.effective_from <= day)
        .order_by(Schedule.effective_from.desc(), Schedule.created_at.desc(), Schedule.id.desc()).limit(1))


async def personnel_data(session, person_id, start, end):
    await ensure_report_available(session,person_id,start)
    # Fetch one predecessor rather than the person's complete event history.
    before = await session.scalar(select(WorkEvent).where(WorkEvent.person_id == person_id, WorkEvent.occurred_at < start)
        .order_by(WorkEvent.occurred_at.desc()).limit(1))
    events = list((await session.scalars(select(WorkEvent).where(WorkEvent.person_id == person_id,
        WorkEvent.occurred_at >= start, WorkEvent.occurred_at < end).order_by(WorkEvent.occurred_at))).all())
    if before:
        events.insert(0, before)
    explanation_rows = list((await session.scalars(select(Explanation).where(Explanation.person_id == person_id,
        Explanation.started_at < end, Explanation.ended_at > start))).all())
    pairs = list((await session.execute(select(Correction, Approval).outerjoin(Approval, Approval.correction_id == Correction.id)
        .where(Correction.person_id == person_id, Correction.started_at < end, Correction.ended_at > start))).all())
    approved = [SimpleNamespace(id=c.id, started_at=c.started_at, ended_at=c.ended_at, status=c.status, approved_at=a.created_at)
                for c, a in pairs if a and a.decision == 'approved']
    return events, explanation_rows, pairs, approved


async def activity_segments(session, person_id, start, end):
    bindings = list((await session.scalars(select(ActivityBinding).where(ActivityBinding.person_id == person_id,
        ActivityBinding.valid_from < end, ActivityBinding.valid_until > start).limit(129))).all())
    if len(bindings) > 128:
        raise ValueError('Activity day exceeds the safe account mapping limit')
    rows = []
    for binding in bindings:
        # Any conflicting account binding makes this temporal attribution fail closed.
        conflicts = await session.scalar(select(ActivityBinding.id).where(ActivityBinding.device_id == binding.device_id,
            ActivityBinding.user_key == binding.user_key, ActivityBinding.person_id != person_id,
            ActivityBinding.valid_from < min(end, utc(binding.valid_until)),
            ActivityBinding.valid_until > max(start, utc(binding.valid_from))).limit(1))
        if conflicts:
            continue
        left, right = max(start, utc(binding.valid_from)), min(end, utc(binding.valid_until))
        foreign = list((await session.execute(select(ActivityInterval.started_at,ActivityInterval.ended_at).where(
            ActivityInterval.device_id == binding.device_id,
            (ActivityInterval.user_key != binding.user_key) | ActivityInterval.user_key.is_(None),
            ActivityInterval.started_at < right, ActivityInterval.ended_at > left).limit(20_001))).all())
        if len(foreign) > 20_000:
            raise ValueError('Activity day exceeds the safe report size')
        foreign.sort(key=lambda pair: utc(pair[0]))
        foreign_starts, foreign_max_ends = [], []
        for a,b in foreign:
            foreign_starts.append(utc(a))
            foreign_max_ends.append(max(utc(b),foreign_max_ends[-1] if foreign_max_ends else utc(b)))
        observed = list((await session.scalars(select(ActivityInterval).where(ActivityInterval.device_id == binding.device_id,
            ActivityInterval.user_key == binding.user_key, ActivityInterval.started_at < right,
            ActivityInterval.ended_at > left).limit(20_001))).all())
        if len(observed) + len(rows) > 20_000:
            raise ValueError('Activity day exceeds the safe report size')
        for row in observed:
            index = bisect_left(foreign_starts,min(right,utc(row.ended_at)))-1
            if index >= 0 and foreign_max_ends[index] > max(left,utc(row.started_at)):
                continue
            rows.append(SimpleNamespace(started_at=max(left, utc(row.started_at)), ended_at=min(right, utc(row.ended_at)),
                session_state=row.session_state, device_id=row.device_id, process_name=None, application_category=None))
    # Reuse the existing multi-device sweep; do not sum simultaneous devices.
    merged = merged_segments(rows, start, end)
    result, cursor = [], start
    for item in merged:
        left, right = datetime.fromisoformat(item['started_at']), datetime.fromisoformat(item['ended_at'])
        if left > cursor:
            result.append(dict(started_at=cursor.isoformat(), ended_at=left.isoformat(), state='UNKNOWN', seconds=(left-cursor).total_seconds(), attributed=False))
        result.append({key: item[key] for key in ('started_at', 'ended_at', 'state', 'seconds', 'attributed', 'overlap')})
        cursor = right
    if cursor < end:
        result.append(dict(started_at=cursor.isoformat(), ended_at=end.isoformat(), state='UNKNOWN', seconds=(end-cursor).total_seconds(), attributed=False))
    return result


async def pending_requests(session, person_id, *, start=None, end=None):
    """Read genuinely pending rows with bounded, stable, mutation-free paging."""
    if (start is None) != (end is None) or (start is not None and utc(start) >= utc(end)):
        raise ValueError('An ordered pair of queue bounds is required')
    explained = select(Explanation.id).where(Explanation.person_id==person_id,
        Explanation.started_at<=ExplanationRequest.started_at,Explanation.ended_at>=ExplanationRequest.ended_at).correlate(ExplanationRequest).exists()
    query = select(ExplanationRequest).outerjoin(Explanation, Explanation.request_id == ExplanationRequest.id).where(
        ExplanationRequest.person_id == person_id, Explanation.id.is_(None), ~explained)
    if start is not None:
        query = query.where(ExplanationRequest.started_at < utc(end), ExplanationRequest.ended_at > utc(start))
    pending, scanned, cursor, seen_explanations = [], 0, None, set()
    while True:
        page = query
        if cursor is not None:
            page = page.where(or_(ExplanationRequest.started_at > cursor[0],
                (ExplanationRequest.started_at == cursor[0]) & (ExplanationRequest.id > cursor[1])))
        rows = list((await session.scalars(page.order_by(ExplanationRequest.started_at,ExplanationRequest.id)
            .limit(min(PENDING_PAGE_SIZE,MAX_PENDING_CANDIDATES-scanned+1)))).all())
        if not rows:
            return pending
        scanned += len(rows)
        if scanned > MAX_PENDING_CANDIDATES:
            raise ValueError('Explanation queue exceeds the safe history size')
        bounds = min(utc(r.started_at) for r in rows),max(utc(r.ended_at) for r in rows)
        explanations = list((await session.execute(select(Explanation.id,Explanation.started_at,Explanation.ended_at).where(
            Explanation.person_id==person_id,Explanation.started_at<bounds[1],Explanation.ended_at>bounds[0]).limit(20_001))).all())
        seen_explanations.update(identifier for identifier,_,_ in explanations)
        if len(seen_explanations)>20_000:
            raise ValueError('Explanation queue exceeds the safe history size')
        coverage = union_windows([(utc(a),utc(b)) for _,a,b in explanations])
        pending.extend(r for r in rows if not fully_covered(utc(r.started_at),utc(r.ended_at),coverage))
        if len(pending) >= MAX_PENDING_RESULTS:
            return pending[:MAX_PENDING_RESULTS]
        cursor = rows[-1].started_at, rows[-1].id


async def day_report(session, person_id, day, now=None, *, include_activity=True):
    now = utc(now or datetime.now(UTC))
    start, end = day_bounds(day, TIMEZONE)
    events, explanations, pairs, approved = await personnel_data(session, person_id, start, end)
    work, totals = project_work(events, approved, start, end, now)
    schedule = await schedule_for(session, person_id, day)
    scheduled = schedule_windows(schedule.definition, day, shift_days=(day,)) if schedule else []
    yesterday = await schedule_for(session, person_id, day - timedelta(days=1))
    if yesterday:
        scheduled = schedule_windows(yesterday.definition, day, shift_days=(day-timedelta(days=1),)) + scheduled
    scheduled = union_windows(scheduled)
    totals['scheduled_seconds'] = sum(int((b-a).total_seconds()) for a, b in scheduled)
    technical = await activity_segments(session, person_id, start, end) if include_activity else [dict(started_at=start.isoformat(), ended_at=end.isoformat(), state='UNKNOWN', seconds=(end-start).total_seconds(), attributed=False)]
    unknown = sum(item['seconds'] for item in technical if item['state'] == 'UNKNOWN')
    state = await session.get(WorkState, person_id)
    return dict(person_id=str(person_id), day=day.isoformat(), timezone=TIMEZONE, status=state.status if state else 'ENDED',
        work_intervals=work, activity_intervals=technical, totals=totals,
        coverage=dict(state='UNKNOWN' if unknown == 86400 else 'PARTIAL' if unknown else 'MEASURED', measured_seconds=86400-unknown, unknown_seconds=unknown),
        schedule=[dict(started_at=a.isoformat(), ended_at=b.isoformat()) for a,b in scheduled],
        explanations=[serialize(e) for e in explanations],
        corrections=[dict(**serialize(c), decision=a.decision if a else 'pending', approval=serialize(a) if a else None) for c,a in pairs],
        pending_explanations=[dict(**serialize(r), state='pending')
                              for r in await pending_requests(session, person_id,start=start,end=end)])


async def generate_requests(session, person_id, day, now=None):
    """Internal server job, deliberately unavailable to device/browser credentials."""
    now = utc(now or datetime.now(UTC))
    await lock_person(session, person_id)
    reports = []
    for report_day in (day-timedelta(days=1),day):
        try:
            reports.append(await day_report(session,person_id,report_day,now))
        except PersonnelHistoryExpired:
            # Expired evidence cannot justify a new personnel request.
            continue
    scheduled = [(datetime.fromisoformat(i['started_at']), datetime.fromisoformat(i['ended_at'])) for report in reports for i in report['schedule']]
    covered = [(datetime.fromisoformat(i['started_at']), datetime.fromisoformat(i['ended_at'])) for report in reports for i in report['work_intervals'] if i['status'] in ('BREAK','OFF_PC')]
    covered.extend((datetime.fromisoformat(i['started_at']), datetime.fromisoformat(i['ended_at'])) for report in reports for i in report['explanations'])
    policy = await session.scalar(select(RetentionPolicy).order_by(RetentionPolicy.created_at.desc()).limit(1))
    threshold = policy.inactivity_threshold_seconds if policy else 1200
    created = []
    for start, end in notification_candidates([item for report in reports for item in report['activity_intervals']], scheduled, covered, threshold):
        if end > now:
            continue
        existing = await session.scalar(select(ExplanationRequest).where(ExplanationRequest.person_id == person_id,
            ExplanationRequest.started_at < end, ExplanationRequest.ended_at > start).limit(1))
        if existing:
            continue
        row = ExplanationRequest(id=uuid5(NAMESPACE_URL, f'endpoint:worktime:{person_id}:{start.isoformat()}:{end.isoformat()}'),
            person_id=person_id, started_at=start, ended_at=end, source='measured_return', created_at=now)
        session.add(row)
        created.append(row)
    await session.flush()
    return created


async def generate_due_requests(session, *, now=None, batch_size=64):
    """Bounded fair maintenance job; caller commits independently of Activity cleanup."""
    from endpoint_server.db.models.identity import ConfirmedIdentity
    now = utc(now or datetime.now(UTC))
    day = now.astimezone(ZoneInfo(TIMEZONE)).date()
    candidates = list((await session.scalars(select(WorkState.person_id).join(ConfirmedIdentity,
        ConfirmedIdentity.person_id==WorkState.person_id).where(ConfirmedIdentity.state=='active',
        ConfirmedIdentity.revoked_at.is_(None), WorkState.person_id.in_(select(ActivityBinding.person_id).where(
        ActivityBinding.valid_from<now, ActivityBinding.valid_until>now-timedelta(days=2))))
        .order_by(WorkState.notification_checked_at.asc().nullsfirst(),WorkState.person_id).limit(batch_size))).all())
    count = 0
    # Deterministic lock order avoids deadlocks between concurrent maintenance batches.
    for person_id in sorted(candidates):
        state = await lock_person(session,person_id)
        count += len(await generate_requests(session,person_id,day,now))
        state.notification_checked_at = now
    await session.flush()
    return count


async def retain_worktime(session, *, now=None, batch_size=100):
    """Independent bounded personnel cleanup, disabled until policy explicitly sets days.

    Keep boundary event/schedule predecessors and policy/audit references. Activity
    tables are never read or deleted by this personnel-retention operation.
    """
    from endpoint_server.db.models.identity import ConfirmedIdentity
    now = utc(now or datetime.now(UTC))
    policy = await session.scalar(select(RetentionPolicy).order_by(RetentionPolicy.created_at.desc(),RetentionPolicy.id.desc()).limit(1))
    if policy is None or policy.retention_days is None:
        return 0
    cutoff = now-timedelta(days=policy.retention_days)
    people = list((await session.scalars(select(WorkState.person_id)
        .order_by(WorkState.retention_checked_at.asc().nullsfirst(),WorkState.person_id).limit(16))).all())
    deleted = 0
    for person_id in sorted(people):
        if deleted >= batch_size:
            break
        await session.scalar(select(ConfirmedIdentity).where(ConfirmedIdentity.person_id==person_id).with_for_update())
        state = await session.scalar(select(WorkState).where(WorkState.person_id==person_id).with_for_update())
        before = deleted

        async def purge(model, predicate):
            nonlocal deleted
            remaining = batch_size-deleted
            if remaining <= 0:
                return
            ids = list((await session.scalars(select(model.id).where(model.person_id==person_id,predicate)
                .order_by(model.created_at,model.id).limit(remaining))).all())
            if ids:
                await session.execute(delete(model).where(model.id.in_(ids)))
                deleted += len(ids)

        await purge(Explanation,(Explanation.ended_at<cutoff)&(Explanation.created_at<cutoff))
        # Requests with a retained, recently submitted explanation remain intact.
        retained_explanation = select(Explanation.id).where(Explanation.request_id==ExplanationRequest.id).correlate(ExplanationRequest).exists()
        await purge(ExplanationRequest,(ExplanationRequest.ended_at<cutoff)&(ExplanationRequest.created_at<cutoff)&~retained_explanation)

        recent_decision = select(Approval.id).where(Approval.correction_id==Correction.id,Approval.created_at>=cutoff).correlate(Correction).exists()
        correction_ids = list((await session.scalars(select(Correction.id).where(Correction.person_id==person_id,
            Correction.ended_at<cutoff,Correction.created_at<cutoff,~recent_decision).limit(max(0,batch_size-deleted)))).all())
        if correction_ids:
            await session.execute(delete(Approval).where(Approval.correction_id.in_(correction_ids)))
            await session.execute(delete(Correction).where(Correction.id.in_(correction_ids)))
            deleted += len(correction_ids)

        predecessor = await session.scalar(select(WorkEvent.id).where(WorkEvent.person_id==person_id,WorkEvent.occurred_at<cutoff)
            .order_by(WorkEvent.occurred_at.desc()).limit(1))
        await purge(WorkEvent,(WorkEvent.occurred_at<cutoff)&(WorkEvent.id!=predecessor))
        schedule = await schedule_for(session,person_id,cutoff.astimezone(ZoneInfo(TIMEZONE)).date())
        await purge(Schedule,(Schedule.effective_from<cutoff.date())&(Schedule.created_at<cutoff)&(Schedule.id!=schedule.id if schedule else True))
        await purge(ActivityBinding,(ActivityBinding.valid_until<cutoff)&(ActivityBinding.created_at<cutoff))
        if deleted > before:
            audit(session,person_id,policy.actor_id,'personnel_retention',policy.id,now)
            state.records_expired_before = max(cutoff,utc(state.records_expired_before)) if state.records_expired_before else cutoff
        state.retention_checked_at = now
    await session.flush()
    return deleted


def timesheet_metadata(row):
    data = serialize(row)
    data['month'] = row.month.strftime('%Y-%m')
    return data


async def timesheet_document(session, row):
    days = list((await session.scalars(select(TimesheetDay).where(TimesheetDay.timesheet_id==row.id)
        .order_by(TimesheetDay.day))).all())
    return dict(**timesheet_metadata(row),days=[day.payload for day in days])


async def finalize_timesheet(session, person_id, actor_id, month, reason, key, now):
    """Finalize one closed month atomically under the same person serialization lock."""
    now = utc(now)
    await lock_person(session,person_id)
    if actor_id == person_id or not reason.strip():
        raise ValueError('Monthly approval requires an independent reviewer and a reason')
    payload = dict(month=month,reason=reason)
    previous = await replay(session,Timesheet,person_id,key,payload)
    if previous:
        if previous.finalized_by != actor_id:
            raise ValueError('Idempotency key belongs to a different reviewer')
        return previous
    try:
        first = date.fromisoformat(month+'-01')
        count = monthrange(first.year,first.month)[1]
        following = first+timedelta(days=count)
    except (ValueError,OverflowError):
        raise ValueError('Use a valid YYYY-MM calendar month') from None
    start = day_bounds(first,TIMEZONE)[0]
    end = day_bounds(following,TIMEZONE)[0]
    if end > now:
        raise ValueError('Only a closed calendar month can be finalized')
    await ensure_report_available(session,person_id,start)
    pending = await session.scalar(select(Correction.id).outerjoin(Approval,Approval.correction_id==Correction.id)
        .where(Correction.person_id==person_id,Correction.started_at<end,Correction.ended_at>start,Approval.id.is_(None)).limit(1))
    if pending:
        raise ValueError('Resolve pending corrections before finalizing the month')
    source_events = list((await session.scalars(select(WorkEvent).where(WorkEvent.person_id==person_id,
        WorkEvent.occurred_at>=start,WorkEvent.occurred_at<end).order_by(WorkEvent.occurred_at))).all())
    days = []
    for number in range(1,count+1):
        day = date(first.year,first.month,number)
        report = await day_report(session,person_id,day,now,include_activity=False)
        left,right = day_bounds(day,TIMEZONE)
        recorded = [serialize(event) for event in source_events if left<=utc(event.occurred_at)<right]
        approvals = [item['approval'] for item in report['corrections'] if item['approval']]
        days.append({key:report[key] for key in ('day','totals','work_intervals','explanations','corrections','schedule')} |
            dict(events=recorded,approvals=approvals))
    totals = {name:sum(day['totals'][name] for day in days) for name in ('work_seconds','off_pc_seconds','break_seconds','scheduled_seconds')}
    last_version = await session.scalar(select(Timesheet.version).where(Timesheet.person_id==person_id,Timesheet.month==first)
        .order_by(Timesheet.version.desc()).limit(1))
    row = Timesheet(id=uuid4(),person_id=person_id,month=first,version=(last_version or 0)+1,timezone=TIMEZONE,
        finalized_by=actor_id,finalized_at=now,reason=reason.strip(),source_digest=fingerprint(dict(person_id=person_id,
        month=month,timezone=TIMEZONE,days=days,totals=totals)),totals=totals,idempotency_key=key,fingerprint=fingerprint(payload),created_at=now)
    session.add(row)
    await session.flush()
    session.add_all([TimesheetDay(id=uuid4(),timesheet_id=row.id,day=date.fromisoformat(day['day']),payload=day,
        **day['totals'],created_at=now) for day in days])
    audit(session,person_id,actor_id,'month_finalized',row.id,now)
    await session.flush()
    return row
