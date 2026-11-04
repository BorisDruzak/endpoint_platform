"""Read-only fleet admission and audited controls for exact full Setup releases."""
from dataclasses import dataclass
from datetime import timedelta
from typing import Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import select, text

from endpoint_contracts.setup_updates import ACTIVE_SETUP_PHASES, SetupProgressV1
from endpoint_contracts.update_safety import validate_public_update_prose
from endpoint_server.audit.service import append_audit_event
from endpoint_server.db.instance_order import latest_instance_order
from endpoint_server.db.models import Device, DeviceInstance, DeviceSession, UpdateBuild, UpdateTarget
from .models import (SetupRelease, SetupAssignment, SetupPreparation, SetupClientPresence,
                     SetupFleetPolicy, SetupFleetDecision, SetupFleetQualification)
from .preparation import ACTIVE_PREPARATIONS
from .service import SetupConflict, now_utc, utc, require_new_wss

FLEET_LOCK = 735306158
QUALIFIED_BRIDGE = 'endpoint-windows-core-3.2.163-setup-client'
SOURCE156_RETURN = 'endpoint-windows-core-3.2.155-setup-source-725739f'
SOURCE157_RETURN = 'endpoint-windows-core-3.2.157-setup-source'


class FleetPolicyUpdate(BaseModel):
    model_config = ConfigDict(extra='forbid')
    expected_revision: int = Field(ge=0)
    enabled: bool = False
    release_id: UUID | None = None
    scope: Literal['all_active', 'selected'] = 'all_active'
    device_ids: list[UUID] = Field(default_factory=list, max_length=500)
    max_parallel: int = Field(default=1, ge=1, le=2)
    reason: str = Field(min_length=1, max_length=256)

    @model_validator(mode='after')
    def valid_scope(self):
        self.reason = validate_public_update_prose(self.reason, field_name='reason', max_length=256, required=True)
        if self.enabled and self.release_id is None:
            raise ValueError('A full Setup target is required')
        if self.scope == 'selected' and not self.device_ids:
            raise ValueError('Select at least one device')
        if self.scope == 'all_active' and self.device_ids:
            raise ValueError('All-active scope cannot include a device selection')
        if len(set(self.device_ids)) != len(self.device_ids):
            raise ValueError('Duplicate devices')
        return self


async def fleet_lock(session, *, wait=False):
    """One lock for worker admission and policy edits, before Build/Device locks."""
    if session.bind.dialect.name != 'postgresql':
        return True
    if wait:
        await session.execute(text('SELECT pg_advisory_xact_lock(:key)'), {'key': FLEET_LOCK})
        return True
    return bool(await session.scalar(text('SELECT pg_try_advisory_xact_lock(:key)'), {'key': FLEET_LOCK}))


def version(value):
    try:
        parts = tuple(int(p) for p in value.split('.'))
        return parts if len(parts) == 3 and all(p >= 0 for p in parts) else None
    except (ValueError, AttributeError):
        return None


def product_release(release):
    # Full Setup has its own EXE registry. Core bridge ZIP numbers are not a
    # product-version ceiling: future signed Setups need their own qualification.
    value = version(release.version) if release else None
    return (isinstance(release, SetupRelease) and value is not None and value >= (3, 2, 156)
        and release.artifact_name.endswith('.exe'))


def valid_qualification(qualification, release, now):
    return bool(qualification and qualification.sha256 == release.sha256
        and utc(qualification.qualified_at) <= now <= utc(qualification.expires_at))


async def qualifications(session, release_id, *, now):
    release = await session.get(SetupRelease, release_id)
    if release is None or not product_release(release):
        return []
    return [row for row in (await session.scalars(select(SetupFleetQualification).where(
        SetupFleetQualification.release_id == release_id))).all() if valid_qualification(row, release, now)]


async def qualify_release(session, release_id, evidence_assignment_id, *, actor, request_id, now=None):
    """Qualify an exact full target and persisted source profile after native proof.

    Call through an operator maintenance transaction after native canary acceptance.
    This does not create, enable, resume or widen a fleet policy.
    """
    now = now_utc(now)
    await fleet_lock(session, wait=True)
    release = await session.get(SetupRelease, release_id)
    job = await session.get(SetupAssignment, evidence_assignment_id)
    if (not product_release(release) or job is None
            or job.release_id != release_id or job.status != 'applied' or job.finished_at is None
            or not timedelta(0) <= now - utc(job.finished_at) <= timedelta(days=1)):
        raise SetupConflict('Fresh applied native evidence required')
    source_foundation, source_core = version(job.source_foundation_version), version(job.source_core_version)
    if (job.source_client_version != '1.0.5' or source_foundation is None or source_core is None
            or not (3, 2, 156) <= source_foundation <= version(release.version)
            or source_core > version(release.version)):
        raise SetupConflict('Persisted qualified source profile required')
    try:
        report = SetupProgressV1.model_validate(job.last_report)
    except (ValueError, TypeError):
        raise SetupConflict('Complete native evidence required') from None
    proof = report.proof
    if (report.phase != 'applied' or report.attempt_id != job.attempt_id or proof is None
            or proof.exit_code != 0 or not proof.native_verified or not proof.core_verified
            or not proof.provenance_verified or not proof.services_verified or not proof.companions_restored
            or proof.pending or proof.foundation_version != release.version or proof.core_version != release.version
            or proof.source_revision != release.source_revision or proof.msi_sha256 != release.msi_sha256
            or proof.soak.sensor_count < 1 or proof.soak.duration_seconds < 180
            or not proof.soak.services_stable or not proof.soak.companions_stable or not proof.soak.connected):
        raise SetupConflict('Native and active user sensor qualification required')
    presence = await session.scalar(select(SetupClientPresence).where(SetupClientPresence.device_id == job.device_id))
    if (presence is None or presence.client_version != '1.0.5' or not presence.ready
            or presence.foundation_version != release.version or presence.core_version != release.version
            or not -timedelta(seconds=30) <= now-utc(presence.last_seen_at) <= timedelta(seconds=90)):
        raise SetupConflict('Fresh qualified client required')
    await require_new_wss(session, job, release, now)
    from endpoint_server.db.models import PolicySensorHealthCurrent
    health = await session.scalar(select(PolicySensorHealthCurrent).where(
        PolicySensorHealthCurrent.device_id == job.device_id))
    if (health is None or health.activity_listener_state != 'READY' or health.user_sensor_last_seen_at is None
            or not -timedelta(seconds=30) <= now-utc(health.received_at) <= timedelta(seconds=150)
            or not -timedelta(seconds=30) <= now-utc(health.user_sensor_last_seen_at) <= timedelta(seconds=150)):
        raise SetupConflict('Fresh active user sensor health required')
    prep = await session.scalar(select(SetupPreparation).where(
        SetupPreparation.assignment_id == job.id, SetupPreparation.device_id == job.device_id,
        SetupPreparation.release_id == release_id))
    if prep is not None:
        expected_source = {'3.2.156': SOURCE156_RETURN, '3.2.157': SOURCE157_RETURN,
                           '3.2.158': SOURCE157_RETURN}.get(job.source_foundation_version)
        if prep.status != 'completed' or prep.return_rollout_id is None or expected_source is None:
            raise SetupConflict('Completed supported source preparation evidence required')
        from endpoint_server.db.models import UpdateRollout
        chain = (await session.execute(select(UpdateRollout.id, UpdateBuild.id, UpdateBuild.build_identifier, UpdateTarget.status)
            .join(UpdateRollout, UpdateRollout.build_id == UpdateBuild.id)
            .join(UpdateTarget, UpdateTarget.rollout_id == UpdateRollout.id)
            .where(UpdateTarget.device_id == job.device_id,
                UpdateRollout.id.in_([prep.bridge_rollout_id, prep.return_rollout_id])))).all()
        by_rollout = {rollout_id: (build_id, name, status) for rollout_id, build_id, name, status in chain}
        bridge = by_rollout.get(prep.bridge_rollout_id)
        source = by_rollout.get(prep.return_rollout_id)
        if (len(chain) != 2 or bridge is None or source is None
                or bridge[1:] != (QUALIFIED_BRIDGE, 'applied')
                or source != (prep.return_build_id, expected_source, 'applied')):
            raise SetupConflict('Exact applied bridge and compatible source return required')
    row = await session.scalar(select(SetupFleetQualification).where(
        SetupFleetQualification.release_id == release_id, SetupFleetQualification.sha256 == release.sha256,
        SetupFleetQualification.source_foundation == job.source_foundation_version).with_for_update())
    if row is None:
        row = SetupFleetQualification(id=uuid4(), release_id=release_id, sha256=release.sha256,
            source_foundation=job.source_foundation_version)
        session.add(row)
    row.evidence_assignment_id = job.id
    row.qualified_at, row.expires_at = now, now + timedelta(days=30)
    row.qualified_by, row.evidence_code = str(actor), 'native0_sensor_source_verified'
    await session.flush()
    await append_audit_event(session, actor_kind='operator', actor_identifier=str(actor),
        action='setup_updates.fleet_release_qualified', object_kind='setup_fleet_qualification',
        object_identifier=str(row.id), request_id=request_id, occurred_at=now,
        details={'release_id': str(release_id), 'sha256': release.sha256,
            'source_foundation': row.source_foundation, 'evidence_assignment_id': str(job.id)})
    return row


async def update_policy(session, body, *, actor, request_id, now=None):
    body = FleetPolicyUpdate.model_validate(body)
    now = now_utc(now)
    await fleet_lock(session, wait=True)
    policy = await session.scalar(select(SetupFleetPolicy).with_for_update().execution_options(populate_existing=True))
    if (policy.revision if policy else 0) != body.expected_revision:
        raise SetupConflict('Fleet policy revision changed')
    if body.release_id:
        release = await session.get(SetupRelease, body.release_id)
        if not product_release(release):
            raise SetupConflict('Qualified full Setup product required')
        if body.enabled and not await qualifications(session, body.release_id, now=now):
            raise SetupConflict('Exact Setup artifact has no current native qualification')
    if body.scope == 'selected':
        actual = set((await session.scalars(select(Device.id).where(
            Device.id.in_(body.device_ids), Device.retired_at.is_(None)))).all())
        if actual != set(body.device_ids):
            raise SetupConflict('Active selected devices required')
    if policy is None:
        policy = SetupFleetPolicy(id=uuid4(), revision=0)
        session.add(policy)
    policy.revision += 1
    for name in ('enabled', 'release_id', 'scope', 'max_parallel', 'reason'):
        setattr(policy, name, getattr(body, name))
    policy.device_ids = [str(i) for i in body.device_ids]
    policy.updated_at, policy.updated_by, policy.safe_code = now, str(actor), None
    await session.flush()
    await append_audit_event(session, actor_kind='operator', actor_identifier=str(actor),
        action='setup_updates.fleet_policy_changed', object_kind='setup_fleet_policy',
        object_identifier=str(policy.id), request_id=request_id, occurred_at=now,
        details={'revision': policy.revision, 'enabled': policy.enabled,
            'release_id': str(policy.release_id) if policy.release_id else None,
            'scope': policy.scope, 'device_count': len(policy.device_ids),
            'max_parallel': policy.max_parallel, 'reason': policy.reason})
    return policy


@dataclass(frozen=True)
class Decision:
    status: str
    code: str


async def load_device_facts(session, device_id, release_id, *, now):
    device = await session.get(Device, device_id)
    release = await session.get(SetupRelease, release_id)
    target_sha256 = release.sha256 if release else ''
    instance = await session.scalar(select(DeviceInstance).where(DeviceInstance.device_id == device_id)
        .order_by(*latest_instance_order()).limit(1).execution_options(populate_existing=True))
    connection = await session.scalar(select(DeviceSession).where(DeviceSession.device_id == device_id,
        DeviceSession.closed_at.is_(None), DeviceSession.session_identifier.like('gateway-%'))
        .order_by(DeviceSession.created_at.desc(), DeviceSession.id.desc()).limit(1)
        .execution_options(populate_existing=True))
    prep = await session.scalar(select(SetupPreparation.id).where(SetupPreparation.device_id == device_id,
        SetupPreparation.status.in_(ACTIVE_PREPARATIONS)))
    assignment = await session.scalar(select(SetupAssignment.status).where(SetupAssignment.device_id == device_id,
        SetupAssignment.status.in_(ACTIVE_SETUP_PHASES)))
    core = await session.scalar(select(UpdateTarget.id).where(UpdateTarget.device_id == device_id,
        UpdateTarget.status.in_(('assigned', 'requested', 'scheduled'))))
    previous = await session.scalar(select(SetupAssignment.id).join(SetupRelease,
        SetupRelease.id == SetupAssignment.release_id).where(SetupAssignment.device_id == device_id,
        SetupRelease.sha256 == target_sha256))
    previous_prep = await session.scalar(select(SetupPreparation.id).join(SetupRelease,
        SetupRelease.id == SetupPreparation.release_id).where(SetupPreparation.device_id == device_id,
        SetupRelease.sha256 == target_sha256, SetupPreparation.status.in_(('blocked', 'cancelled'))))
    previous_rejection = await session.scalar(select(SetupFleetDecision.id).where(
        SetupFleetDecision.device_id == device_id, SetupFleetDecision.target_sha256 == target_sha256,
        SetupFleetDecision.safe_code == 'canonical_request_rejected'))
    return dict(device=device, instance=instance, connection=connection, prep=prep, assignment=assignment,
        core=core, previous=previous or previous_prep or previous_rejection,
        qualifications=await qualifications(session, release_id, now=now))


def evaluate_device(policy, release, facts, *, now):
    """Pure: an eligible result is admission permission, never native success."""
    device, instance, connection = facts['device'], facts['instance'], facts['connection']
    if device is None or device.retired_at is not None:
        return Decision('blocked', 'device_retired')
    if policy.scope == 'selected' and str(device.id) not in policy.device_ids:
        return Decision('outside_scope', 'outside_scope')
    if not product_release(release):
        return Decision('blocked', 'target_not_product')
    if instance is None or instance.platform is None:
        return Decision('blocked', 'platform_unknown')
    if instance.platform != 'windows_amd64':
        return Decision('outside_scope', 'platform_unsupported')
    if (instance.last_seen_at is None or connection is None or connection.device_instance_id != instance.id
            or connection.last_seen_at is None or utc(connection.expires_at) <= now
            or not -timedelta(seconds=30) <= now - utc(instance.last_seen_at) <= timedelta(seconds=90)
            or not -timedelta(seconds=30) <= now - utc(connection.last_seen_at) <= timedelta(seconds=90)):
        return Decision('waiting', 'waiting_reconnect')
    if facts['assignment'] == 'recovery_required':
        return Decision('blocked', 'native_recovery_required')
    if facts['prep'] or facts['assignment'] or facts['core']:
        return Decision('waiting', 'active_operation')
    foundation, core, target = version(instance.launcher_version), version(instance.agent_version), version(release.version)
    if foundation is None or core is None:
        return Decision('blocked', 'source_unknown')
    if foundation >= target:
        return Decision('already_current', 'already_current')
    if core > target or foundation < (3, 2, 156) or core < (3, 2, 156):
        return Decision('blocked', 'source_unsupported')
    if facts['previous']:
        return Decision('blocked', 'previous_attempt_requires_review')
    if not any(q.source_foundation == instance.launcher_version for q in facts['qualifications']):
        return Decision('blocked', 'source_not_qualified')
    if not policy.enabled:
        return Decision('waiting', 'policy_paused')
    return Decision('eligible', 'eligible')


async def active_chain_devices(session):
    """Reserve full Setup chains, including manual jobs/holds, once per device.

    A preparation owns its Core children. Unrelated Core-only rollouts do not
    consume the native fleet limit; their per-device exclusion remains intact.
    """
    result = set((await session.scalars(select(SetupPreparation.device_id).where(
        SetupPreparation.status.in_(ACTIVE_PREPARATIONS)))).all())
    result.update((await session.scalars(select(SetupAssignment.device_id).where(
        SetupAssignment.status.in_(ACTIVE_SETUP_PHASES)))).all())
    return result


async def reserve_fleet_admission(session, device_id):
    """Canonical manual/worker entry, before Build/Device locks.

    Policy pause leaves explicit operator canaries available. While enabled,
    every new full Setup chain obeys the same fleet limit, including manual
    requests; continuation of an already reserved chain does not double-charge.
    The transaction-scoped global lock remains held until the request commits.
    """
    await fleet_lock(session, wait=True)
    policy = await session.scalar(select(SetupFleetPolicy).with_for_update()
        .execution_options(populate_existing=True))
    if policy is not None and policy.enabled:
        active = await active_chain_devices(session)
        if device_id not in active and len(active) >= policy.max_parallel:
            raise SetupConflict('Full Setup fleet concurrency limit reached')
