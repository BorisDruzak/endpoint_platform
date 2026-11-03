"""Audited, serialized full Setup assignment and independent acceptance gates."""
from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

from sqlalchemy import select

from endpoint_contracts.setup_updates import (
    ACTIVE_SETUP_PHASES, TERMINAL_SETUP_PHASES, QUALIFIED_SETUP_CLIENT_VERSION, SetupReleaseManifestV1,
    SetupClientHelloV1, SetupProgressV1, validate_setup_transition,
)
from endpoint_contracts.update_safety import validate_public_update_prose
from endpoint_server.audit.service import append_audit_event
from endpoint_server.db.models import Device, DeviceInstance, DeviceSession, UpdateTarget
from endpoint_server.db.instance_order import latest_instance_order
from endpoint_server.updates.agent_routes import _artifact_path

from .models import SetupRelease, SetupAssignment, SetupClientPresence, SetupPreparation


class SetupConflict(ValueError):
    """No authority or proof for this requested transition."""


def utc(value):
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def now_utc(value=None):
    return utc(value or datetime.now(UTC))


def qualified_presence(presence, now):
    return (presence is not None and presence.client_version == QUALIFIED_SETUP_CLIENT_VERSION
        and presence.ready and -timedelta(seconds=30) <= now - utc(presence.last_seen_at) <= timedelta(minutes=10))


def release_manifest(release):
    fields = SetupReleaseManifestV1.model_fields
    return SetupReleaseManifestV1.model_validate({
        'schema_version': 'windows_setup_release_v1',
        **{key: getattr(release, key) for key in fields if key != 'schema_version'},
    })


async def audit(session, assignment, action, actor, request_id, now):
    await append_audit_event(session, actor_kind='operator' if actor else 'agent',
        actor_identifier=str(actor) if actor else str(assignment.device_id),
        action='setup_updates.' + action, object_kind='setup_update_assignment',
        object_identifier=str(assignment.id), request_id=request_id,
        details={'device_id': str(assignment.device_id), 'release_id': str(assignment.release_id),
                 'status': assignment.status, 'safe_code': assignment.safe_code}, occurred_at=now)


async def lock_device(session, device_id):
    device = await session.scalar(select(Device).where(
        Device.id == device_id, Device.retired_at.is_(None)).with_for_update())
    if device is None:
        raise SetupConflict('active device unavailable')
    return device


async def register_release(session, manifest, *, artifact_root, actor, request_id):
    manifest = SetupReleaseManifestV1.model_validate(
        manifest.model_dump() if isinstance(manifest, SetupReleaseManifestV1) else manifest)
    artifact = _artifact_path(Path(artifact_root), manifest.artifact_name)
    if artifact is None or artifact.stat().st_size != manifest.size:
        raise SetupConflict('immutable Setup artifact unavailable')
    with artifact.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    if digest != manifest.sha256:
        raise SetupConflict('immutable Setup artifact differs')
    existing = await session.scalar(select(SetupRelease).where(
        SetupRelease.release_identifier == manifest.release_identifier).with_for_update())
    if existing:
        if release_manifest(existing) != manifest:
            raise SetupConflict('Setup release is immutable')
        return existing
    same_name = await session.scalar(select(SetupRelease.id).where(
        SetupRelease.artifact_name == manifest.artifact_name))
    if same_name:
        raise SetupConflict('Setup artifact name is immutable')
    release = SetupRelease(id=uuid4(), **manifest.model_dump(exclude={'schema_version'}))
    session.add(release)
    await session.flush()
    await append_audit_event(session, actor_kind='operator', actor_identifier=str(actor),
        action='setup_updates.release_registered', object_kind='setup_update_release',
        object_identifier=str(release.id), request_id=request_id,
        details={'release_identifier': release.release_identifier, 'version': release.version,
                 'artifact_name': release.artifact_name, 'sha256': release.sha256})
    return release


async def record_presence(session, device_id, hello, *, now=None):
    hello = SetupClientHelloV1.model_validate(hello.model_dump() if isinstance(hello, SetupClientHelloV1) else hello)
    await lock_device(session, device_id)
    presence = await session.scalar(select(SetupClientPresence).where(
        SetupClientPresence.device_id == device_id).with_for_update())
    if presence is None:
        presence = SetupClientPresence(id=uuid4(), device_id=device_id)
        session.add(presence)
    for key, value in hello.model_dump().items():
        setattr(presence, key, value)
    presence.last_seen_at = now_utc(now)
    await session.flush()
    return presence


async def assign_setup(session, device_id, release_id, reason, *, actor, request_id, now=None, assignment_id=None):
    now = now_utc(now)
    await lock_device(session, device_id)
    release = await session.get(SetupRelease, release_id)
    if release is None:
        raise SetupConflict('Setup release unavailable')
    reason = validate_public_update_prose(reason, field_name='reason', max_length=256)
    if not reason or len(reason) > 256:
        raise SetupConflict('bounded reason is required')
    presence = await session.scalar(select(SetupClientPresence).where(
        SetupClientPresence.device_id == device_id))
    if not qualified_presence(presence, now):
        raise SetupConflict('fresh ready Setup client required')
    active = await session.scalar(select(SetupAssignment.id).where(
        SetupAssignment.device_id == device_id, SetupAssignment.status.in_(ACTIVE_SETUP_PHASES)))
    core_active = await session.scalar(select(UpdateTarget.id).where(
        UpdateTarget.device_id == device_id, UpdateTarget.status.in_(['assigned', 'requested', 'scheduled'])))
    prep_active = await session.scalar(select(SetupPreparation.id).where(
        SetupPreparation.device_id == device_id,
        SetupPreparation.status.in_(['preparing_client', 'restoring_core'])))
    if active or core_active or prep_active:
        raise SetupConflict('device already has an active update')
    job = SetupAssignment(id=assignment_id or uuid4(), device_id=device_id, release_id=release_id, status='assigned',
        reason=reason, assigned_at=now, updated_at=now)
    session.add(job)
    await session.flush()
    await audit(session, job, 'assigned', actor, request_id, now)
    return job


async def locked_assignment(session, assignment_id, device_id=None):
    owner = await session.scalar(select(SetupAssignment.device_id).where(SetupAssignment.id == assignment_id))
    if owner is None or (device_id is not None and owner != device_id):
        raise SetupConflict('Setup operation unavailable')
    await lock_device(session, owner)
    job = await session.scalar(select(SetupAssignment).where(SetupAssignment.id == assignment_id)
                               .with_for_update().execution_options(populate_existing=True))
    if job is None:
        raise SetupConflict('Setup operation unavailable')
    return job


async def cancel_assignment(session, assignment_id, *, actor, request_id, now=None):
    now = now_utc(now)
    job = await locked_assignment(session, assignment_id)
    try:
        validate_setup_transition(job.status, 'cancelled')
    except ValueError as error:
        raise SetupConflict('native operation may have started; wait for its outcome') from error
    if job.status != 'cancelled':
        job.status = 'cancelled'
        job.updated_at = job.finished_at = now
        await audit(session, job, 'cancelled', actor, request_id, now)
    return job


async def require_new_wss(session, job, release, now):
    instance = await session.scalar(select(DeviceInstance).where(DeviceInstance.device_id == job.device_id)
        .order_by(*latest_instance_order()).limit(1))
    connection = await session.scalar(select(DeviceSession).where(
        DeviceSession.device_id == job.device_id, DeviceSession.closed_at.is_(None))
        .order_by(DeviceSession.created_at.desc(), DeviceSession.id.desc()).limit(1))
    if (instance is None or connection is None or instance.agent_version != release.version
            or instance.launcher_version != release.version or instance.last_seen_at is None
            or connection.last_seen_at is None or connection.device_instance_id != instance.id
            or job.started_at is None or utc(connection.created_at) <= utc(job.started_at)
            or now - utc(instance.last_seen_at) > timedelta(seconds=90)
            or now - utc(connection.last_seen_at) > timedelta(seconds=90)):
        raise SetupConflict('fresh post-install WSS and target versions required')


async def record_progress(session, device_id, assignment_id, report, *, now=None):
    report = SetupProgressV1.model_validate(report.model_dump() if isinstance(report, SetupProgressV1) else report)
    now = now_utc(now)
    job = await locked_assignment(session, assignment_id, device_id)
    if report.phase == 'installing' and job.status != 'installing':
        presence = await session.scalar(select(SetupClientPresence).where(SetupClientPresence.device_id == device_id))
        if not qualified_presence(presence, now):
            raise SetupConflict('fresh qualified Setup executor required before native start')
    if job.attempt_id is not None and job.attempt_id != report.attempt_id:
        raise SetupConflict('Setup attempt differs')
    payload = report.model_dump(mode='json')
    if job.status == report.phase:
        if job.last_report == payload:
            return job
        if job.status in TERMINAL_SETUP_PHASES:
            raise SetupConflict('replayed Setup report differs')
        job.last_report = payload
        job.safe_code = report.safe_code
        job.updated_at = now
        await audit(session, job, 'progress', None, str(report.attempt_id), now)
        await session.flush()
        return job
    try:
        validate_setup_transition(job.status, report.phase)
    except ValueError as error:
        raise SetupConflict('Setup progress transition refused') from error
    release = await session.get(SetupRelease, job.release_id)
    if report.phase == 'failed' and job.status == 'recovery_required':
        presence = await session.scalar(select(SetupClientPresence).where(SetupClientPresence.device_id == device_id))
        recovery = await session.scalar(select(SetupPreparation).where(SetupPreparation.assignment_id == job.id)
            .order_by(SetupPreparation.created_at.desc()).limit(1))
        returned = (await session.scalar(select(UpdateTarget).where(UpdateTarget.rollout_id == recovery.return_rollout_id,
            UpdateTarget.device_id == device_id))) if recovery and recovery.return_rollout_id else None
        if (report.proof is None or report.safe_code != 'native_failed_source_verified'
                or job.safe_code != 'native_exit_requires_recovery' or not qualified_presence(presence, now)
                or report.proof.core_version != '3.2.157' or report.proof.foundation_version != '3.2.158'
                or presence.core_version != '3.2.157' or presence.foundation_version != '3.2.158'
                or report.proof.msi_sha256 != release.msi_sha256 or report.proof.source_revision != release.source_revision
                or (recovery and (recovery.status != 'completed' or returned is None or returned.status != 'applied'))):
            raise SetupConflict('verified source recovery required before releasing native ownership')
        instance = await session.scalar(select(DeviceInstance).where(DeviceInstance.device_id == device_id)
            .order_by(*latest_instance_order()).limit(1))
        connection = await session.scalar(select(DeviceSession).where(DeviceSession.device_id == device_id,
            DeviceSession.closed_at.is_(None)).order_by(DeviceSession.created_at.desc()).limit(1))
        if (instance is None or connection is None or connection.device_instance_id != instance.id
                or instance.agent_version != report.proof.core_version
                or instance.launcher_version != report.proof.foundation_version
                or instance.last_seen_at is None or connection.last_seen_at is None
                or now - utc(instance.last_seen_at) > timedelta(seconds=90)
                or now - utc(connection.last_seen_at) > timedelta(seconds=90)):
            raise SetupConflict('fresh source WSS required for native failure recovery')
    if report.phase in ('applied', 'already_current'):
        proof = report.proof
        if (proof.foundation_version != release.version or proof.core_version != release.version
                or proof.source_revision != release.source_revision or proof.msi_sha256 != release.msi_sha256):
            raise SetupConflict('native proof differs from assigned Setup')
        if report.phase == 'applied':
            await require_new_wss(session, job, release, now)
    job.status = report.phase
    job.attempt_id = report.attempt_id
    job.safe_code = report.safe_code
    job.last_report = payload
    job.updated_at = now
    if report.phase == 'installing':
        job.started_at = now
    if report.phase in TERMINAL_SETUP_PHASES:
        job.finished_at = now
    await audit(session, job, report.phase, None, str(report.attempt_id), now)
    await session.flush()
    return job
