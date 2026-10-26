"""Employee-cookie WorkTime APIs; no device/service/admin credential fallback."""
from calendar import monthrange
import csv
import io
from contextlib import asynccontextmanager
from datetime import UTC, date, datetime, time
from typing import Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError

from endpoint_server.auth.authorization import authorize_person
from endpoint_server.auth.employee_sessions import EmployeePrincipal, require_employee
from endpoint_server.db.models.identity import ConfirmedIdentity, ScopedRoleGrant
from . import service
from .domain import TIMEZONE, utc
from .models import ActivityBinding, Approval, Category, Correction, RetentionPolicy, Schedule, Timesheet, WorkState


def enabled(request: Request, response: Response):
    response.headers['Cache-Control'] = 'no-store'
    if not getattr(request.app.state.settings, 'worktime_enabled', False):
        raise HTTPException(404, 'WorkTime is disabled')


router = APIRouter(prefix='/api/employee/worktime', tags=['employee-worktime'], dependencies=[Depends(enabled)])


class Input(BaseModel):
    model_config = ConfigDict(extra='forbid', str_max_length=4000)


class Command(Input):
    idempotency_key: UUID


class TransitionInput(Command):
    action: Literal['start','end','break','resume','off_pc']


class IntervalInput(Command):
    started_at: AwareDatetime
    ended_at: AwareDatetime


class ExplanationInput(IntervalInput):
    category_code: str = Field(min_length=1,max_length=40)
    comment: str = ''
    request_id: UUID | None = None


class CorrectionInput(IntervalInput):
    status: Literal['WORKING','BREAK','OFF_PC','ENDED']
    reason: str = Field(min_length=1)


class DecisionInput(Command):
    decision: Literal['approved','rejected']
    comment: str = ''


class FinalizeInput(Command):
    month: str = Field(pattern=r'^\d{4}-\d{2}$')
    reason: str = Field(min_length=1)


class Shift(Input):
    start: str = Field(pattern=r'^\d{2}:\d{2}$')
    end: str = Field(pattern=r'^\d{2}:\d{2}$')

    @field_validator('start','end')
    @classmethod
    def valid_time(cls, value):
        time.fromisoformat(value)
        return value


class ScheduleDefinition(Shift):
    weekdays: list[int] = Field(max_length=7)
    overrides: dict[str, Shift | None] = Field(default_factory=dict, max_length=366)

    @model_validator(mode='after')
    def valid_calendar(self):
        if any(d < 0 or d > 6 for d in self.weekdays) or len(set(self.weekdays)) != len(self.weekdays):
            raise ValueError('Weekdays use unique Monday=0 through Sunday=6')
        for day in self.overrides:
            date.fromisoformat(day)
        return self


class ScheduleInput(Command):
    person_id: UUID
    effective_from: date
    definition: ScheduleDefinition


class CategoryInput(Input):
    code: str = Field(pattern=r'^[a-z][a-z0-9_]{0,39}$')
    label: str = Field(min_length=1,max_length=100)
    requires_comment: bool = False
    enabled: bool = True


class PolicyInput(Input):
    retention_days: int | None = Field(default=None,ge=1,le=36500)
    inactivity_threshold_seconds: int = Field(default=1200,ge=1200,le=86400)
    rationale: str = Field(min_length=1)


class BindingInput(Input):
    person_id: UUID
    device_id: UUID
    user_key: str = Field(min_length=1,max_length=300)
    valid_from: AwareDatetime
    valid_until: AwareDatetime
    proof_reference: str = Field(min_length=1,max_length=256)


@asynccontextmanager
async def transaction(request):
    async with request.app.state.session_provider() as session:
        try:
            yield session
            await session.commit()
        except service.PersonnelHistoryExpired as error:
            await session.rollback()
            raise HTTPException(410,str(error)) from None
        except ValueError as error:
            await session.rollback()
            raise HTTPException(409, str(error)) from None
        except IntegrityError:
            await session.rollback()
            raise HTTPException(409, 'A concurrent request conflicts with an existing record') from None


async def visible_people(session, principal, action='worktime.read'):
    grants = (await session.scalars(select(ScopedRoleGrant).where(ScopedRoleGrant.identity_id == principal.identity.id,
        ScopedRoleGrant.revoked_at.is_(None)))).all()
    roles = {'manager','hr','worktime_admin'} if action == 'worktime.read' else {'hr','worktime_admin','manager'}
    matching = [g for g in grants if g.role in roles and (g.role != 'manager' or g.department_id is not None)]
    query = select(ConfirmedIdentity).where(ConfirmedIdentity.state == 'active', ConfirmedIdentity.revoked_at.is_(None))
    if not any(g.department_id is None for g in matching):
        query = query.where(or_(ConfirmedIdentity.person_id == principal.identity.person_id,
            ConfirmedIdentity.department_id.in_([g.department_id for g in matching if g.department_id])))
    rows = list((await session.scalars(query.order_by(ConfirmedIdentity.person_id).limit(2001))).all())
    if len(rows) > 2000:
        raise HTTPException(422, 'Personnel list exceeds limit; narrow organization scope')
    return rows


async def global_admin(session, principal):
    await authorize_person(session, principal, principal.identity.person_id, 'worktime.admin')
    grant = await session.scalar(select(ScopedRoleGrant).where(ScopedRoleGrant.identity_id == principal.identity.id,
        ScopedRoleGrant.role == 'worktime_admin',ScopedRoleGrant.department_id.is_(None),ScopedRoleGrant.revoked_at.is_(None)))
    if grant is None:
        raise HTTPException(403,'Organization WorkTime administrator required')


@router.get('/categories')
async def get_categories(request: Request, principal: EmployeePrincipal=Depends(require_employee)):
    async with transaction(request) as session:
        await authorize_person(session, principal, principal.identity.person_id, 'worktime.read')
        return {'categories': await service.categories(session)}


@router.post('/categories')
async def configure_category(body: CategoryInput, request: Request, principal: EmployeePrincipal=Depends(require_employee)):
    async with transaction(request) as session:
        await global_admin(session, principal)
        await service.lock_person(session, principal.identity.person_id)
        row = await session.scalar(select(Category).where(Category.code == body.code).with_for_update())
        if row is None:
            row = Category(id=uuid4(),**body.model_dump())
            session.add(row)
        else:
            for key,value in body.model_dump().items():
                setattr(row,key,value)
        service.audit(session,None,principal.identity.person_id,'category_configured',row.id,datetime.now(UTC))
        await session.flush()
        return service.serialize(row)


@router.get('/day')
async def get_day(request: Request, day: date, person_id: UUID | None=None, principal: EmployeePrincipal=Depends(require_employee)):
    target = person_id or principal.identity.person_id
    async with transaction(request) as session:
        await authorize_person(session, principal, target, 'worktime.read')
        return await service.day_report(session, target, day)


async def month_report(request, principal, month, person_id, action):
    target = person_id or principal.identity.person_id
    try:
        first = date.fromisoformat(month + '-01')
    except ValueError:
        raise HTTPException(422,'Use YYYY-MM') from None
    async with transaction(request) as session:
        await authorize_person(session, principal, target, action)
        now = datetime.now(UTC)
        days = [await service.day_report(session,target,date(first.year,first.month,d),now)
                for d in range(1,monthrange(first.year,first.month)[1]+1)]
        return dict(person_id=str(target),month=month,timezone=TIMEZONE,days=days,
            totals={key:sum(day['totals'][key] for day in days) for key in ('work_seconds','off_pc_seconds','break_seconds','scheduled_seconds')})


@router.get('/month')
async def get_month(request: Request, month: str=Query(pattern=r'^\d{4}-\d{2}$'), person_id: UUID | None=None, principal: EmployeePrincipal=Depends(require_employee)):
    return await month_report(request,principal,month,person_id,'worktime.read')


@router.get('/report')
async def get_report(request: Request, month: str=Query(pattern=r'^\d{4}-\d{2}$'), person_id: UUID | None=None, principal: EmployeePrincipal=Depends(require_employee)):
    return await month_report(request,principal,month,person_id,'worktime.hr')


@router.post('/transitions')
async def post_transition(body: TransitionInput, request: Request, principal: EmployeePrincipal=Depends(require_employee)):
    target = principal.identity.person_id
    async with transaction(request) as session:
        await authorize_person(session, principal, target, 'worktime.write')
        row = await service.transition(session,target,target,body.action,body.idempotency_key,datetime.now(UTC))
        return service.serialize(row)


@router.post('/explanations')
async def post_explanation(body: ExplanationInput, request: Request, principal: EmployeePrincipal=Depends(require_employee)):
    target = principal.identity.person_id
    async with transaction(request) as session:
        await authorize_person(session,principal,target,'worktime.write')
        row = await service.explain(session,target,target,body.started_at,body.ended_at,body.category_code,body.comment,body.idempotency_key,body.request_id,datetime.now(UTC))
        return service.serialize(row)


@router.post('/corrections')
async def post_correction(body: CorrectionInput, request: Request, principal: EmployeePrincipal=Depends(require_employee)):
    target = principal.identity.person_id
    async with transaction(request) as session:
        await authorize_person(session,principal,target,'worktime.write')
        row = await service.request_correction(session,target,target,body.started_at,body.ended_at,body.status,body.reason,body.idempotency_key,datetime.now(UTC))
        return dict(**service.serialize(row),decision='pending',approval=None)


@router.post('/people/{person_id}/corrections')
async def hr_correction(person_id: UUID, body: CorrectionInput, request: Request, principal: EmployeePrincipal=Depends(require_employee)):
    async with transaction(request) as session:
        await authorize_person(session,principal,person_id,'worktime.hr')
        row = await service.request_correction(session,person_id,principal.identity.person_id,body.started_at,body.ended_at,
            body.status,body.reason,body.idempotency_key,datetime.now(UTC))
        return dict(**service.serialize(row),decision='pending',approval=None)


@router.post('/corrections/{correction_id}/decision')
async def post_decision(correction_id: UUID, body: DecisionInput, request: Request, principal: EmployeePrincipal=Depends(require_employee)):
    async with transaction(request) as session:
        row = await session.get(Correction,correction_id)
        if row is None:
            raise HTTPException(404,'Correction not found')
        await authorize_person(session,principal,row.person_id,'worktime.approve')
        decision = await service.decide_correction(session,row,principal.identity.person_id,body.decision,body.comment,body.idempotency_key,datetime.now(UTC))
        return service.serialize(decision)


@router.get('/people')
async def get_people(request: Request, principal: EmployeePrincipal=Depends(require_employee)):
    async with transaction(request) as session:
        rows = []
        for candidate in await visible_people(session,principal):
            try:
                rows.append(await authorize_person(session,principal,candidate.person_id,'worktime.read'))
            except HTTPException as error:
                if error.status_code != 403:
                    raise
        states = {s.person_id:s.status for s in (await session.scalars(select(WorkState).where(WorkState.person_id.in_([p.person_id for p in rows])))).all()}
        return {'people':[dict(person_id=str(p.person_id),department_id=str(p.department_id) if p.department_id else None,
            status=states.get(p.person_id,'ENDED')) for p in rows]}


@router.get('/approvals')
async def get_approvals(request: Request, principal: EmployeePrincipal=Depends(require_employee)):
    async with transaction(request) as session:
        targets = []
        for target in await visible_people(session,principal):
            try:
                await authorize_person(session,principal,target.person_id,'worktime.approve')
            except HTTPException as error:
                if error.status_code != 403:
                    raise
            else:
                targets.append(target.person_id)
        rows = (await session.scalars(select(Correction).outerjoin(Approval,Approval.correction_id==Correction.id)
            .where(Correction.person_id.in_(targets),Approval.id.is_(None)).order_by(Correction.created_at).limit(500))).all()
        return {'corrections':[dict(**service.serialize(c),decision='pending',approval=None) for c in rows]}


@router.get('/history')
async def get_history(request: Request, day: date, person_id: UUID | None=None, principal: EmployeePrincipal=Depends(require_employee)):
    target = person_id or principal.identity.person_id
    async with transaction(request) as session:
        await authorize_person(session,principal,target,'worktime.read')
        start,end = service.day_bounds(day,TIMEZONE)
        events,explanations,pairs,_ = await service.personnel_data(session,target,start,end)
        return dict(events=[service.serialize(e) for e in events if start<=utc(e.occurred_at)<end],explanations=[service.serialize(e) for e in explanations],
            corrections=[dict(**service.serialize(c),decision=a.decision if a else 'pending',approval=service.serialize(a) if a else None) for c,a in pairs],
            approvals=[service.serialize(a) for _,a in pairs if a])


@router.get('/pending')
async def get_pending(request: Request, principal: EmployeePrincipal=Depends(require_employee)):
    async with transaction(request) as session:
        await authorize_person(session,principal,principal.identity.person_id,'worktime.read')
        return {'requests':[dict(**service.serialize(r),state='pending') for r in await service.pending_requests(session,principal.identity.person_id)]}


@router.post('/pending/refresh')
async def refresh_pending(request: Request, day: date, principal: EmployeePrincipal=Depends(require_employee)):
    async with transaction(request) as session:
        await authorize_person(session,principal,principal.identity.person_id,'worktime.write')
        await service.generate_requests(session,principal.identity.person_id,day)
        return {'requests':[dict(**service.serialize(r),state='pending') for r in await service.pending_requests(session,principal.identity.person_id)]}


@router.post('/schedules')
async def assign_schedule(body: ScheduleInput, request: Request, principal: EmployeePrincipal=Depends(require_employee)):
    async with transaction(request) as session:
        await authorize_person(session,principal,body.person_id,'worktime.hr')
        await service.lock_person(session,body.person_id)
        payload = body.model_dump(mode='json',exclude={'idempotency_key','person_id'})
        previous = await service.replay(session,Schedule,body.person_id,body.idempotency_key,payload)
        if previous:
            return service.serialize(previous)
        row = Schedule(id=uuid4(),person_id=body.person_id,actor_id=principal.identity.person_id,idempotency_key=body.idempotency_key,
            fingerprint=service.fingerprint(payload),effective_from=body.effective_from,definition=body.definition.model_dump(mode='json'),created_at=datetime.now(UTC))
        session.add(row)
        service.audit(session,body.person_id,principal.identity.person_id,'schedule_assigned',row.id,datetime.now(UTC))
        await session.flush()
        return service.serialize(row)


@router.get('/schedules')
async def get_schedules(request: Request, person_id: UUID | None=None, principal: EmployeePrincipal=Depends(require_employee)):
    target = person_id or principal.identity.person_id
    async with transaction(request) as session:
        await authorize_person(session,principal,target,'worktime.hr')
        rows = (await session.scalars(select(Schedule).where(Schedule.person_id==target)
            .order_by(Schedule.effective_from.desc(),Schedule.created_at.desc()).limit(500))).all()
        return {'schedules':[service.serialize(row) for row in rows]}


@router.post('/policy')
async def configure_policy(body: PolicyInput, request: Request, principal: EmployeePrincipal=Depends(require_employee)):
    async with transaction(request) as session:
        await global_admin(session,principal)
        row = RetentionPolicy(id=uuid4(),actor_id=principal.identity.person_id,**body.model_dump(),created_at=datetime.now(UTC))
        session.add(row)
        service.audit(session,None,principal.identity.person_id,'retention_policy_configured',row.id,datetime.now(UTC))
        await session.flush()
        return dict(**service.serialize(row),automatic_deletion_enabled=row.retention_days is not None)


@router.post('/people/{person_id}/timesheets/finalize')
async def finalize_month(person_id: UUID, body: FinalizeInput, request: Request, principal: EmployeePrincipal=Depends(require_employee)):
    async with transaction(request) as session:
        await authorize_person(session,principal,person_id,'worktime.hr')
        await authorize_person(session,principal,person_id,'worktime.approve')
        row = await service.finalize_timesheet(session,person_id,principal.identity.person_id,body.month,body.reason,
            body.idempotency_key,datetime.now(UTC))
        return await service.timesheet_document(session,row)


@router.get('/timesheets')
async def list_timesheets(request: Request, month: str=Query(pattern=r'^\d{4}-\d{2}$'), person_id: UUID | None=None,
    principal: EmployeePrincipal=Depends(require_employee)):
    target = person_id or principal.identity.person_id
    try:
        first = date.fromisoformat(month+'-01')
    except ValueError:
        raise HTTPException(422,'Use a valid YYYY-MM') from None
    async with transaction(request) as session:
        await authorize_person(session,principal,target,'worktime.read')
        rows = (await session.scalars(select(Timesheet).where(Timesheet.person_id==target,Timesheet.month==first)
            .order_by(Timesheet.version.desc()).limit(500))).all()
        return {'timesheets':[service.timesheet_metadata(row) for row in rows]}


@router.get('/timesheets/{timesheet_id}')
async def read_timesheet(timesheet_id: UUID, request: Request, principal: EmployeePrincipal=Depends(require_employee)):
    async with transaction(request) as session:
        row = await session.get(Timesheet,timesheet_id)
        if row is None:
            raise HTTPException(404,'Finalized timesheet not found')
        await authorize_person(session,principal,row.person_id,'worktime.read')
        return await service.timesheet_document(session,row)


@router.get('/timesheets/{timesheet_id}/export')
async def export_timesheet(timesheet_id: UUID, request: Request, principal: EmployeePrincipal=Depends(require_employee)):
    async with transaction(request) as session:
        row = await session.get(Timesheet,timesheet_id)
        if row is None:
            raise HTTPException(404,'Finalized timesheet not found')
        await authorize_person(session,principal,row.person_id,'worktime.hr')
        document = await service.timesheet_document(session,row)
        output = io.StringIO(newline='')
        writer = csv.writer(output)
        writer.writerow(['person_id','month','version','day','work_seconds','off_pc_seconds','break_seconds',
            'scheduled_seconds','timezone','finalized_by','finalized_at','source_digest'])
        # Only UUIDs, calendar values, fixed timezone and numeric totals enter CSV;
        # free-form reasons/comments cannot become spreadsheet formulas.
        for day in document['days']+[dict(day='TOTAL',totals=document['totals'])]:
            writer.writerow([document['person_id'],document['month'],document['version'],day['day'],
                *(day['totals'][name] for name in ('work_seconds','off_pc_seconds','break_seconds','scheduled_seconds')),
                document['timezone'],document['finalized_by'],document['finalized_at'],document['source_digest']])
        service.audit(session,row.person_id,principal.identity.person_id,'month_exported',row.id,datetime.now(UTC))
        return Response(content='\ufeff'+output.getvalue(),media_type='text/csv; charset=utf-8',headers={
            'Cache-Control':'no-store','Content-Disposition':f'attachment; filename="timesheet-{row.person_id}-{document["month"]}-v{row.version}.csv"'})


@router.post('/activity-bindings')
async def verified_binding(body: BindingInput, request: Request, principal: EmployeePrincipal=Depends(require_employee)):
    from endpoint_server.db.models import Device
    async with transaction(request) as session:
        await authorize_person(session,principal,body.person_id,'worktime.admin')
        await service.lock_person(session,body.person_id)
        device = await session.scalar(select(Device).where(Device.id==body.device_id).with_for_update())
        if device is None or body.valid_until <= body.valid_from or not body.proof_reference.strip():
            raise HTTPException(409,'Verified device, account, evidence and ordered temporal bounds are required')
        conflict = await session.scalar(select(ActivityBinding.id).where(ActivityBinding.device_id==body.device_id,
            ActivityBinding.user_key==body.user_key,ActivityBinding.valid_from<body.valid_until,ActivityBinding.valid_until>body.valid_from))
        if conflict:
            raise HTTPException(409,'An overlapping account mapping already exists')
        row = ActivityBinding(id=uuid4(),verified_by=principal.identity.person_id,**body.model_dump(),created_at=datetime.now(UTC))
        session.add(row)
        service.audit(session,body.person_id,principal.identity.person_id,'activity_binding_verified',row.id,datetime.now(UTC))
        await session.flush()
        # Do not expose OS login, device credentials or evidence references in employee projections.
        return {'id':str(row.id),'person_id':str(row.person_id),'valid_from':row.valid_from.isoformat(),'valid_until':row.valid_until.isoformat()}
