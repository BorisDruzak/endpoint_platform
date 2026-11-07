"""Bounded fleet admission: one device and one transaction per scheduler step."""
from uuid import UUID, uuid4

from sqlalchemy import and_, select, text

from endpoint_server.audit.service import append_audit_event
from endpoint_server.db.models import Device
from .models import SetupFleetPolicy, SetupFleetDecision, SetupAssignment, SetupPreparation, SetupRelease
from .policy import fleet_lock, load_device_facts, evaluate_device, active_chain_devices
from .preparation import request_setup, lock_builds
from .service import now_utc, lock_device


async def owned_job_state(session, decision):
    job = await session.get(SetupAssignment, decision.job_id)
    if job is not None:
        return job.status, job.safe_code
    prep = await session.get(SetupPreparation, decision.job_id)
    if prep is None:
        return 'blocked', 'owned_job_missing'
    if prep.assignment_id:
        job = await session.get(SetupAssignment, prep.assignment_id)
        if job is not None:
            return job.status, job.safe_code
    return prep.status, prep.safe_code


async def pause_on_failure(session, policy, *, now):
    """Observe all unacknowledged owned chains, including earlier targets.

    Switching policy revision/target cannot hide a late native outcome. Manual
    unrelated holds only reserve capacity and do not trip this circuit.
    """
    rows = (await session.scalars(select(SetupFleetDecision).where(
        SetupFleetDecision.policy_id == policy.id,
        SetupFleetDecision.job_id.is_not(None),
        SetupFleetDecision.safe_code != 'fleet_failure_requires_review',
        SetupFleetDecision.status.not_in(('applied', 'already_current', 'cancelled')))
        .order_by(SetupFleetDecision.evaluated_at).limit(500))).all()
    for decision in rows:
        status, _ = await owned_job_state(session, decision)
        if status in ('failed', 'blocked', 'recovery_required', 'rolled_back'):
            policy.enabled, policy.safe_code, policy.updated_at = False, 'fleet_failure_requires_review', now
            policy.revision += 1
            decision.status, decision.safe_code, decision.evaluated_at = status, 'fleet_failure_requires_review', now
            await append_audit_event(session, actor_kind='service', actor_identifier='setup-fleet-worker',
                action='setup_updates.fleet_policy_paused', object_kind='setup_fleet_policy',
                object_identifier=str(policy.id), request_id=f'fleet_{uuid4().hex}', occurred_at=now,
                details={'revision': policy.revision, 'device_id': str(decision.device_id),
                    'job_id': str(decision.job_id), 'safe_code': policy.safe_code})
            await session.flush()
            return True
        decision.status = status
    return False


async def schedule_one(session, *, now=None):
    """Return false when paused/contended; caller commits after each bounded step."""
    now = now_utc(now)
    if session.bind.dialect.name == 'postgresql':
        await session.execute(text("SET LOCAL lock_timeout = '5s'"))
        await session.execute(text("SET LOCAL statement_timeout = '10s'"))
    if not await fleet_lock(session):
        return False
    policy = await session.scalar(select(SetupFleetPolicy).with_for_update()
        .execution_options(populate_existing=True))
    if policy is None or not policy.enabled or policy.release_id is None:
        return False
    if await pause_on_failure(session, policy, now=now):
        return False
    release = await session.get(SetupRelease, policy.release_id)
    if release is None:
        return False
    # Oldest observation first prevents permanently offline devices starving
    # later UUIDs. History remains immutable across revision/target changes.
    query = select(Device.id, SetupFleetDecision).outerjoin(SetupFleetDecision, and_(
        SetupFleetDecision.device_id == Device.id, SetupFleetDecision.policy_id == policy.id,
        SetupFleetDecision.policy_revision == policy.revision,
        SetupFleetDecision.target_sha256 == release.sha256)).where(Device.retired_at.is_(None))
    if policy.scope == 'selected':
        query = query.where(Device.id.in_([UUID(i) for i in policy.device_ids]))
    item = (await session.execute(query.order_by(SetupFleetDecision.evaluated_at.asc().nulls_first(), Device.id)
        .limit(1))).first()
    if item is None:
        return False
    device_id, decision = item
    if decision is None:
        decision = SetupFleetDecision(id=uuid4(), policy_id=policy.id, policy_revision=policy.revision,
            device_id=device_id, release_id=release.id, target_sha256=release.sha256,
            status='waiting', safe_code='pending_evaluation', evaluated_at=now)
        session.add(decision)
        await session.flush()
    decision.evaluated_at = now
    if decision.job_id:
        decision.status, code = await owned_job_state(session, decision)
        decision.safe_code = code or decision.status
        await session.flush()
        return True
    if decision.safe_code == 'canonical_request_rejected':
        # Changing policy does not grant authority to replay a rejected chain.
        return True
    # Gateway writes presence under Device. Respect canonical Build -> Device
    # order, then evaluate fresh state while reconnect/version cannot race us.
    await lock_builds(session)
    await lock_device(session, device_id)
    facts = await load_device_facts(session, device_id, release.id, now=now)
    result = evaluate_device(policy, release, facts, now=now)
    decision.status, decision.safe_code = result.status, result.code
    if result.status != 'eligible':
        await session.flush()
        return True
    if len(await active_chain_devices(session)) >= policy.max_parallel:
        decision.status, decision.safe_code = 'waiting', 'capacity_full'
        await session.flush()
        return True
    # Savepoint contains only this canonical request. A bounded safe decision
    # survives source rejection; database/credentials/payloads are never copied.
    decision_id = decision.id
    try:
        async with session.begin_nested():
            job = await request_setup(session, device_id, release.id, policy.reason,
                actor=policy.updated_by, request_id=f'fleet_{decision.id.hex}', now=now)
            decision.job_id, decision.status, decision.safe_code = job.id, job.status, 'chain_requested'
            await session.flush()
    except Exception:
        # A controller/source rejection must not silently retry every minute.
        decision = await session.scalar(select(SetupFleetDecision).where(SetupFleetDecision.id == decision_id)
            .execution_options(populate_existing=True))
        decision.status, decision.safe_code = 'blocked', 'canonical_request_rejected'
        policy.enabled, policy.safe_code, policy.updated_at = False, 'fleet_request_requires_review', now
        policy.revision += 1
        await append_audit_event(session, actor_kind='service', actor_identifier='setup-fleet-worker',
            action='setup_updates.fleet_request_rejected', object_kind='setup_fleet_policy',
            object_identifier=str(policy.id), request_id=f'fleet_{decision.id.hex}', occurred_at=now,
            details={'revision': policy.revision, 'device_id': str(device_id),
                'safe_code': 'canonical_request_rejected'})
    await session.flush()
    return True


async def schedule_fleet(provider, *, limit=16):
    """Independent transactions; one broken device cannot roll back siblings."""
    for _ in range(min(max(limit, 1), 32)):
        try:
            async with provider() as session:
                try:
                    more = await schedule_one(session)
                    await session.commit()
                except Exception:
                    await session.rollback()
                    return
        except Exception:
            return
        if not more:
            return
