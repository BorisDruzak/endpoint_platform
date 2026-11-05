"""Durable server-owned preparation using canonical Core OTA operations.

Build locks precede Device locks. The private handoff status is flushed only
inside the transaction holding Device, so unrelated assignments cannot interleave.
"""
from datetime import timedelta
from uuid import uuid4

from sqlalchemy import select

from endpoint_contracts.update_safety import validate_public_update_prose
from endpoint_contracts.setup_updates import QUALIFIED_SETUP_CLIENT_VERSIONS
from endpoint_server.db.models import DeviceInstance, DeviceSession, UpdateBuild, UpdateTarget, UpdateRollout
from endpoint_server.db.instance_order import latest_instance_order
from endpoint_server.updates.service import create_rollout, create_rollback_rollout
from .models import SetupPreparation, SetupRelease, SetupClientPresence, SetupFleetDecision, SetupFleetQualification
from .service import SetupConflict, assign_setup, lock_device, locked_assignment, now_utc, utc, audit, qualified_presence

ACTIVE_PREPARATIONS = ('preparing_client', 'restoring_core', 'recovering_client', 'recovering_source')
BRIDGE = 'endpoint-windows-core-3.2.163-setup-client'
BRIDGE_VERSION = '3.2.163'
RETURN = 'endpoint-windows-core-3.2.157-setup-source'
RETURN156 = 'endpoint-windows-core-3.2.155-setup-source-725739f'
OBSERVER_BOOTSTRAP = 'endpoint-windows-core-3.2.166-observer-bootstrap'
OBSERVER_BOOTSTRAP_VERSION = '3.2.166'


def modern_bootstrap_source(instance, release, bootstrap):
    """Only an upward bootstrap below a distinct native target is supported.

    Staged native installation cannot take over the bootstrap's same-version
    directory. Existing 163/return preparations keep their historical strategy.
    """
    if instance is None or release is None or bootstrap is None:
        return False
    try:
        return (instance.platform == bootstrap.platform == 'windows_amd64'
            and bootstrap.build_identifier == OBSERVER_BOOTSTRAP
            and bootstrap.version == OBSERVER_BOOTSTRAP_VERSION
            and bootstrap.archive_type == 'zip' and bootstrap.minimum_launcher_version == '3.2.158'
            and (3, 2, 158) <= parts(instance.launcher_version) < parts(bootstrap.version)
            and (3, 2, 163) <= parts(instance.agent_version) < parts(bootstrap.version) < parts(release.version))
    except SetupConflict:
        return False


async def matching_bootstrap_observer(session, device_id, presence, now):
    if (not ready(presence, now) or presence.client_version != '1.0.6'
            or presence.core_version != OBSERVER_BOOTSTRAP_VERSION
            or presence.foundation_version is None
            or not (3, 2, 158) <= parts(presence.foundation_version) < parts(OBSERVER_BOOTSTRAP_VERSION)
            or now - utc(presence.last_seen_at) > timedelta(seconds=150)):
        return False
    instance = await session.scalar(select(DeviceInstance).where(DeviceInstance.device_id == device_id)
        .order_by(*latest_instance_order()).limit(1))
    connection = await session.scalar(select(DeviceSession).where(DeviceSession.device_id == device_id,
        DeviceSession.closed_at.is_(None), DeviceSession.session_identifier.like('gateway-%'))
        .order_by(DeviceSession.created_at.desc(), DeviceSession.id.desc()).limit(1))
    return (instance is not None and connection is not None and connection.closed_at is None
        and connection.device_instance_id == instance.id and utc(connection.expires_at) > now
        and instance.platform == 'windows_amd64'
        and instance.agent_version == presence.core_version and instance.launcher_version == presence.foundation_version
        and instance.last_seen_at is not None and connection.last_seen_at is not None
        and -timedelta(seconds=30) <= now - utc(instance.last_seen_at) <= timedelta(seconds=90)
        and -timedelta(seconds=30) <= now - utc(connection.last_seen_at) <= timedelta(seconds=90))


def parts(version):
    try:
        values = tuple(int(x) for x in version.split('.'))
        if len(values) != 3:
            raise ValueError()
        return values
    except (AttributeError, ValueError):
        raise SetupConflict('known Windows versions required') from None


def ready(presence, now):
    return qualified_presence(presence, now) and presence.client_version in QUALIFIED_SETUP_CLIENT_VERSIONS


async def _recovery_child(session, job, create):
    """A child of the held native attempt, serialized by the same Device lock.

    The private handoff never commits or releases Device; unrelated Core/Setup
    requests continue to see recovery_required after acquiring that lock.
    """
    job.status = 'handoff'
    await session.flush()
    try:
        result = await create()
    except BaseException:
        job.status = 'recovery_required'
        raise
    job.status = 'recovery_required'
    await session.flush()
    return result


async def request_client_recovery(session, assignment_id, reason, *, actor, request_id, now=None):
    now = now_utc(now)
    builds = await lock_builds(session)
    job = await locked_assignment(session, assignment_id)
    presence = await session.scalar(select(SetupClientPresence).where(SetupClientPresence.device_id == job.device_id))
    owned = await session.scalar(select(SetupPreparation.id).where(SetupPreparation.device_id == job.device_id,
        SetupPreparation.status.in_(ACTIVE_PREPARATIONS)))
    if (job.status != 'recovery_required' or job.safe_code != 'native_exit_requires_recovery'
            or job.attempt_id is None or job.started_at is None or owned
            or presence is None or not presence.ready or now - utc(presence.last_seen_at) > timedelta(seconds=150)):
        raise SetupConflict('known exited native operation and fresh idle source required')
    bridge, source = builds.get(BRIDGE), builds.get(RETURN)
    if (bridge is None or source is None or bridge.version != BRIDGE_VERSION or source.version != '3.2.157'
            or bridge.platform != 'windows_amd64' or source.platform != bridge.platform
            or presence.core_version != source.version or presence.foundation_version != '3.2.158'):
        raise SetupConflict('qualified recovery client and exact source required')
    reason = validate_public_update_prose(reason, field_name='reason', max_length=256, required=True)
    child = await _recovery_child(session, job, lambda: create_rollout(session, bridge.id, 'canary',
        [job.device_id], reason, actor, request_id, now=now))
    prep = SetupPreparation(id=uuid4(), device_id=job.device_id, release_id=job.release_id,
        assignment_id=job.id, bridge_rollout_id=child.id, return_build_id=source.id,
        status='recovering_client', reason=reason, requested_by=str(actor), updated_at=now)
    session.add(prep); await session.flush()
    await audit(session, prep, 'recovery_client_requested', actor, request_id, now)
    return prep


async def lock_builds(session):
    builds = (await session.scalars(select(UpdateBuild).where(
        UpdateBuild.build_identifier.in_((BRIDGE, RETURN, RETURN156, OBSERVER_BOOTSTRAP, 'endpoint-windows-core-3.2.159-setup-client', 'endpoint-windows-core-3.2.160-setup-client'))).order_by(UpdateBuild.id).with_for_update())).all()
    return {b.build_identifier: b for b in builds}


async def request_setup(session, device_id, release_id, reason, *, actor, request_id, now=None):
    now = now_utc(now)
    from .policy import reserve_fleet_admission
    await reserve_fleet_admission(session, device_id)
    builds = await lock_builds(session)
    await lock_device(session, device_id)
    reason = validate_public_update_prose(reason, field_name='reason', max_length=256, required=True)
    release = await session.get(SetupRelease, release_id)
    if release is None:
        raise SetupConflict('Setup release unavailable')
    owned = await session.scalar(select(SetupPreparation.id).where(
        SetupPreparation.device_id == device_id, SetupPreparation.status.in_(ACTIVE_PREPARATIONS)))
    if owned:
        raise SetupConflict('device already has an active Setup preparation')
    presence = await session.scalar(select(SetupClientPresence).where(SetupClientPresence.device_id == device_id))
    if ready(presence, now) and parts(presence.core_version) <= parts(release.version):
        return await assign_setup(session, device_id, release_id, reason, actor=actor, request_id=request_id, now=now)
    instance = await session.scalar(select(DeviceInstance).where(DeviceInstance.device_id == device_id)
        .order_by(*latest_instance_order()).limit(1))
    bootstrap = builds.get(OBSERVER_BOOTSTRAP)
    if modern_bootstrap_source(instance, release, bootstrap):
        if presence is not None and now-utc(presence.last_seen_at) <= timedelta(minutes=10):
            raise SetupConflict('current observer must settle before bootstrap')
        child = await create_rollout(session, bootstrap.id, 'canary', [device_id], reason,
            actor, request_id, now=now)
        prep = SetupPreparation(id=uuid4(), device_id=device_id, release_id=release_id,
            bridge_rollout_id=child.id, return_build_id=None, status='preparing_client',
            reason=reason, requested_by=str(actor), updated_at=now)
        session.add(prep); await session.flush()
        await audit(session, prep, 'preparation_requested', actor, request_id, now)
        return prep
    source_identifier = RETURN156 if instance is not None and parts(instance.launcher_version) == (3, 2, 156) else RETURN
    bridge, source = builds.get(BRIDGE), builds.get(source_identifier)
    if (instance is None or bridge is None or source is None
            or bridge.platform != 'windows_amd64' or source.platform != bridge.platform
            or bridge.version != BRIDGE_VERSION or source.version != ('3.2.155' if source_identifier == RETURN156 else '3.2.157')
            or parts(instance.launcher_version) < (3, 2, 156)
            or (source.minimum_launcher_version is not None and parts(source.minimum_launcher_version) > parts(instance.launcher_version))
            or parts(instance.agent_version) >= parts(bridge.version)
            or not parts(source.version) < parts(release.version)):
        raise SetupConflict('qualified Setup client preparation unavailable for this source')
    child = await create_rollout(session, bridge.id, 'canary', [device_id], reason,
                                 actor, request_id, now=now)
    prep = SetupPreparation(id=uuid4(), device_id=device_id, release_id=release_id,
        bridge_rollout_id=child.id, return_build_id=source.id, status='preparing_client',
        reason=reason, requested_by=str(actor), updated_at=now)
    session.add(prep)
    await session.flush()
    await audit(session, prep, 'preparation_requested', actor, request_id, now)
    return prep


async def advance_preparations(session, *, now=None):
    now = now_utc(now)
    builds = await lock_builds(session)
    identities = (await session.execute(select(SetupPreparation.id, SetupPreparation.device_id,
        SetupPreparation.bridge_rollout_id, SetupPreparation.return_rollout_id)
        .where(SetupPreparation.status.in_(ACTIVE_PREPARATIONS))
        .order_by(SetupPreparation.device_id).limit(32))).all()
    for prep_id, device_id, bridge_id, return_id in identities:
        # Core pause/activate takes Rollout before Device; respect that order.
        await session.scalars(select(UpdateRollout).where(UpdateRollout.id.in_(
            [x for x in (bridge_id, return_id) if x is not None]))
            .order_by(UpdateRollout.id).with_for_update())
        await session.scalars(select(UpdateTarget).where(UpdateTarget.rollout_id.in_(
            [x for x in (bridge_id, return_id) if x is not None]))
            .order_by(UpdateTarget.id).with_for_update())
        await lock_device(session, device_id)
        prep = await session.scalar(select(SetupPreparation).where(SetupPreparation.id == prep_id)
            .with_for_update().execution_options(populate_existing=True))
        if prep.status not in ACTIVE_PREPARATIONS:
            continue
        rollout_id = prep.return_rollout_id or prep.bridge_rollout_id
        target = await session.scalar(select(UpdateTarget).where(
            UpdateTarget.rollout_id == rollout_id, UpdateTarget.device_id == device_id))
        if target is None or target.status in ('failed', 'rolled_back', 'cancelled'):
            prep.status, prep.safe_code = 'blocked', 'core_preparation_failed'
        elif target.status == 'applied':
            presence = await session.scalar(select(SetupClientPresence).where(SetupClientPresence.device_id == device_id))
            if prep.return_build_id is None:
                bootstrap = builds.get(OBSERVER_BOOTSTRAP)
                bridge_rollout = await session.get(UpdateRollout, prep.bridge_rollout_id)
                release = await session.get(SetupRelease, prep.release_id)
                if (prep.status != 'preparing_client' or prep.return_rollout_id is not None
                        or bootstrap is None or bootstrap.version != OBSERVER_BOOTSTRAP_VERSION
                        or bootstrap.minimum_launcher_version != '3.2.158' or bootstrap.platform != 'windows_amd64'
                        or bootstrap.archive_type != 'zip' or bridge_rollout is None or bridge_rollout.build_id != bootstrap.id
                        or release is None or parts(release.version) <= parts(bootstrap.version)):
                    prep.status, prep.safe_code = 'blocked', 'immutable_source_unavailable'
                elif not await matching_bootstrap_observer(session, device_id, presence, now):
                    continue
                else:
                    automatic = await session.scalar(select(SetupFleetDecision.id).where(
                        SetupFleetDecision.job_id == prep.id, SetupFleetDecision.device_id == device_id,
                        SetupFleetDecision.release_id == prep.release_id))
                    qualified = await session.scalar(select(SetupFleetQualification.id).where(
                        SetupFleetQualification.release_id == release.id,
                        SetupFleetQualification.sha256 == release.sha256,
                        SetupFleetQualification.source_foundation == presence.foundation_version,
                        SetupFleetQualification.qualified_at <= now, SetupFleetQualification.expires_at > now))
                    if automatic and qualified is None:
                        prep.status, prep.safe_code = 'blocked', 'source_not_qualified'
                    else:
                        prep.status = 'handoff'; await session.flush()
                        job = await assign_setup(session, device_id, prep.release_id, prep.reason,
                            actor=prep.requested_by, request_id=f'setup_{prep.id.hex}', now=now, assignment_id=prep.id)
                        prep.assignment_id, prep.status = job.id, 'completed'
                prep.updated_at = now
                await audit(session, prep, 'preparation_' + prep.status, prep.requested_by, f'setup_{prep.id.hex}', now)
                await session.flush()
                continue
            source = next((builds[name] for name in (RETURN, RETURN156)
                if name in builds and builds[name].id == prep.return_build_id), None)
            if source is None:
                prep.status, prep.safe_code, prep.updated_at = 'blocked', 'immutable_source_unavailable', now
                await audit(session, prep, 'preparation_blocked', prep.requested_by, f'setup_{prep.id.hex}', now)
                await session.flush()
                continue
            expected = source.version if prep.return_rollout_id else BRIDGE_VERSION
            if not ready(presence, now) or presence.core_version != expected:
                continue
            if prep.status == 'recovering_client':
                job = await locked_assignment(session, prep.assignment_id)
                if job.status != 'recovery_required' or RETURN not in builds or builds[RETURN].id != prep.return_build_id:
                    prep.status, prep.safe_code = 'blocked', 'recovery_ownership_differs'
                else:
                    child = await _recovery_child(session, job, lambda: create_rollback_rollout(session,
                        prep.bridge_rollout_id, prep.return_build_id, [device_id], prep.reason,
                        prep.requested_by, f'setup_{prep.id.hex}', now=now))
                    prep.return_rollout_id, prep.status = child.id, 'recovering_source'
            elif prep.status == 'recovering_source':
                # The recovered observer settles its original attempt using
                # actual exit21 plus unchanged-source/private/session proof.
                prep.status = 'completed'
            elif prep.status == 'preparing_client':
                if not presence.foundation_version:
                    # A nullable hello must not roll back unrelated preparations.
                    continue
                if (source.minimum_launcher_version is not None
                        and parts(source.minimum_launcher_version) > parts(presence.foundation_version)):
                    prep.status, prep.safe_code = 'blocked', 'immutable_source_unavailable'
                else:
                    prep.status = 'handoff'
                    await session.flush()
                    child = await create_rollback_rollout(session, prep.bridge_rollout_id,
                        prep.return_build_id, [device_id], prep.reason, prep.requested_by,
                        f'setup_{prep.id.hex}', now=now)
                    prep.return_rollout_id, prep.status = child.id, 'restoring_core'
            else:
                prep.status = 'handoff'
                await session.flush()
                job = await assign_setup(session, device_id, prep.release_id, prep.reason,
                    actor=prep.requested_by, request_id=f'setup_{prep.id.hex}', now=now,
                    assignment_id=prep.id)
                prep.assignment_id, prep.status = job.id, 'completed'
        else:
            continue
        prep.updated_at = now
        await audit(session, prep, 'preparation_' + prep.status, prep.requested_by, f'setup_{prep.id.hex}', now)
        await session.flush()


async def cancel_preparation(session, preparation_id, *, actor, request_id, now=None):
    identity = await session.scalar(select(SetupPreparation.device_id).where(SetupPreparation.id == preparation_id))
    if identity is None:
        raise SetupConflict('Setup preparation unavailable')
    await lock_device(session, identity)
    prep = await session.scalar(select(SetupPreparation).where(SetupPreparation.id == preparation_id)
        .with_for_update().execution_options(populate_existing=True))
    if prep.status not in (*ACTIVE_PREPARATIONS, 'cancelled'):
        raise SetupConflict('Setup preparation is already terminal')
    if prep.status != 'cancelled':
        prep.status, prep.safe_code, prep.updated_at = 'cancelled', 'future_stages_cancelled', now_utc(now)
        await audit(session, prep, 'preparation_cancelled', actor, request_id, prep.updated_at)
    return prep
