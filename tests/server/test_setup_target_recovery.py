"""Release native ownership as FAILED only after independent target recovery evidence."""
from datetime import timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy import select

from endpoint_contracts.endpoint_policy import EndpointPolicyV1
from endpoint_contracts.setup_updates import SetupProgressV1
from endpoint_server.context.models import ContextCollection, ContextSnapshot, ContextCurrent
from endpoint_server.db.models import AuditEvent, DeviceInstance, DeviceSession, UpdateRollout, UpdateTarget
from endpoint_server.policy.models import (
    PolicyDefinition, PolicyVersion, PolicyAssignment, PolicyDeviceState, PolicySensorHealthCurrent,
)
from endpoint_server.policy.service import create_policy_version, assign_device_policy
from endpoint_server.setup_updates.models import SetupClientPresence, SetupPreparation
from endpoint_server.setup_updates.service import record_progress, record_presence, SetupConflict, utc
from tests.contracts.test_endpoint_policy_v1 import _policy, POLICY_ID
from tests.server.test_setup_preparation import build
from tests.server.test_setup_update_service import db, state, started, proof, NOW


@pytest.fixture
async def recovered(db, state):
    connection = await db.connection()
    await connection.run_sync(lambda sync: DeviceInstance.metadata.create_all(sync, tables=[
        PolicyDefinition.__table__, PolicyVersion.__table__, PolicyAssignment.__table__,
        PolicyDeviceState.__table__, PolicySensorHealthCurrent.__table__,
        ContextCollection.__table__, ContextSnapshot.__table__, ContextCurrent.__table__,
    ]))
    job, attempt = await started(db, state)
    await record_progress(db, job.device_id, job.id, SetupProgressV1(
        attempt_id=attempt, phase='recovery_required', safe_code='native_exit_requires_recovery'), now=NOW)
    when = NOW + timedelta(seconds=300)
    release = state[1]
    await record_presence(db, job.device_id, dict(client_version='1.0.6', ready=True,
        core_version=release.version, foundation_version=release.version), now=when)
    presence = await db.scalar(select(SetupClientPresence).where(SetupClientPresence.device_id == job.device_id))
    instance = DeviceInstance(id=uuid4(), device_id=job.device_id, instance_identifier='recovered-target',
        platform='windows_amd64', agent_version=release.version, launcher_version=release.version,
        last_seen_at=when)
    db.add(instance)
    await db.flush()
    wss = DeviceSession(id=uuid4(), device_id=job.device_id, device_instance_id=instance.id,
        session_identifier='recovered-' + uuid4().hex, created_at=NOW + timedelta(seconds=5),
        last_seen_at=when, expires_at=when + timedelta(hours=1))
    db.add(PolicyDefinition(id=POLICY_ID, name='Recovery activity policy'))
    await db.flush()
    version = await create_policy_version(db, POLICY_ID, EndpointPolicyV1.model_validate(_policy()), actor_id=uuid4())
    await assign_device_policy(db, job.device_id, version.id, actor_id=uuid4())
    policy_state = PolicyDeviceState(id=uuid4(), device_id=job.device_id, policy_version_id=version.id,
        policy_digest=version.digest, status='APPLIED', applied_at=when, acknowledged_at=when)
    health = PolicySensorHealthCurrent(id=uuid4(), device_id=job.device_id, observation_id=uuid4(),
        policy_id=POLICY_ID, policy_version=1, observed_at=when, received_at=when,
        activity_listener_state='READY', user_sensor_last_seen_at=when, security_spool_state='READY',
        usb_source_state='READY', print_source_state='READY')
    collection = ContextCollection(id=uuid4(), device_id=job.device_id, profile='activity_v1',
        requested_by='agent', idempotency_key=uuid4().hex, status='completed', requested_at=when,
        completed_at=when)
    snapshot = ContextSnapshot(id=uuid4(), collection_id=collection.id, device_id=job.device_id,
        profile='activity_v1', collected_at=when, normalized_projection={})
    activity = ContextCurrent(id=uuid4(), device_id=job.device_id, profile='activity_v1',
        snapshot_id=snapshot.id, updated_at=when, last_observed_at=when)
    db.add_all([wss, policy_state, health, collection, snapshot, activity])
    await db.flush()
    evidence = proof()
    evidence['exit_code'] = 21
    report = SetupProgressV1(attempt_id=attempt, phase='failed',
                            safe_code='native_failed_target_recovered', proof=evidence)
    return SimpleNamespace(job=job, report=report, when=when, release=release, presence=presence,
                           instance=instance, wss=wss, policy=version, policy_state=policy_state,
                           health=health, activity=activity)


@pytest.mark.parametrize('completed_preparation', [False, True])
@pytest.mark.parametrize('observer_version', ['1.0.6', '1.0.7'])
async def test_target_recovery_records_failed_once_preserves_source_and_native_21(db, recovered, completed_preparation, observer_version):
    r = recovered
    r.presence.client_version = observer_version
    if completed_preparation:
        core = build('3.2.166', 'completed-bootstrap-' + uuid4().hex)
        rollout = UpdateRollout(id=uuid4(), rollout_identifier=uuid4().hex, build_id=core.id,
            mode='canary', status='completed')
        db.add_all([core, rollout])
        await db.flush()
        db.add(SetupPreparation(id=uuid4(), device_id=r.job.device_id, release_id=r.release.id,
            bridge_rollout_id=rollout.id, assignment_id=r.job.id, status='completed',
            requested_by='test-admin', reason='Completed observer preparation', updated_at=r.when))
        await db.flush()
    source = (r.job.source_foundation_version, r.job.source_core_version, r.job.source_client_version)
    started_at = r.job.started_at
    await record_progress(db, r.job.device_id, r.job.id, r.report, now=r.when)
    assert r.job.status == 'failed' and r.job.finished_at == r.when
    assert r.job.started_at == started_at
    assert (r.job.source_foundation_version, r.job.source_core_version, r.job.source_client_version) == source
    assert r.job.last_report['proof']['exit_code'] == 21
    assert r.job.last_report['proof']['native_phase'] == 'accepted'
    await record_progress(db, r.job.device_id, r.job.id, r.report, now=r.when + timedelta(hours=1))
    events = (await db.scalars(select(AuditEvent).where(AuditEvent.action == 'setup_updates.failed'))).all()
    assert len(events) == 1 and events[0].details['safe_code'] == 'native_failed_target_recovered'
    assert utc(r.job.finished_at) == r.when
    from endpoint_server.setup_updates.policy import qualify_release
    with pytest.raises(SetupConflict, match='Fresh applied native evidence required'):
        await qualify_release(db, r.release.id, r.job.id, actor='test-admin', request_id='not-qualification', now=r.when)


@pytest.mark.parametrize('observer_version', ['1.0.5', '1.0.8', '1.1.0', '2.0.0'])
async def test_target_recovery_rejects_unqualified_observer_versions(db, recovered, observer_version):
    r = recovered
    r.presence.client_version = observer_version
    await db.flush()
    with pytest.raises(SetupConflict, match='fresh qualified observer required'):
        await record_progress(db, r.job.device_id, r.job.id, r.report, now=r.when)
    assert r.job.status == 'recovery_required' and r.job.finished_at is None


@pytest.mark.parametrize('observer_version', ['1.0.6', '1.0.7'])
@pytest.mark.parametrize('defect', [
    'different-attempt', 'missing-attempt', 'unknown-outcome', 'not-recovery',
    'wrong-core', 'wrong-foundation', 'wrong-source', 'wrong-msi',
    'old-client', 'not-ready', 'wrong-presence-core', 'wrong-presence-foundation',
    'expired-presence', 'future-presence', 'pre-start-presence',
    'missing-wss', 'closed-wss', 'old-wss', 'future-wss-start', 'expired-wss', 'stale-wss', 'future-wss', 'foreign-instance',
    'wrong-agent', 'wrong-launcher', 'stale-instance', 'future-instance', 'wrong-platform', 'missing-start',
    'missing-health', 'listener-unavailable', 'missing-sensor', 'stale-sensor', 'future-sensor',
    'stale-health', 'future-health', 'stale-observation', 'pre-start-health',
    'health-policy-id', 'health-policy-version', 'missing-policy-state', 'policy-error',
    'policy-digest', 'policy-version', 'changed-effective-policy', 'missing-effective-policy',
    'missing-activity', 'stale-activity', 'future-activity', 'pre-start-activity',
    'missing-activity-observation', 'future-projection-update',
])
async def test_target_recovery_cannot_release_hold_with_unverified_target(db, recovered, defect, observer_version):
    r = recovered
    r.presence.client_version = observer_version
    report = r.report.model_dump()
    if defect == 'different-attempt': report['attempt_id'] = uuid4()
    elif defect == 'missing-attempt': r.job.attempt_id = None
    elif defect == 'unknown-outcome': r.job.safe_code = 'setup_outcome_unknown'
    elif defect == 'not-recovery': r.job.status = 'assigned'
    elif defect.startswith('wrong-') and defect.split('wrong-')[1] in ('core', 'foundation', 'source', 'msi'):
        key = {'core': 'core_version', 'foundation': 'foundation_version',
               'source': 'source_revision', 'msi': 'msi_sha256'}[defect.split('wrong-')[1]]
        report['proof'][key] = '3.2.157' if key.endswith('version') else 'f' * (40 if key == 'source_revision' else 64)
    elif defect == 'old-client': r.presence.client_version = '1.0.5'
    elif defect == 'not-ready': r.presence.ready = False
    elif defect == 'wrong-presence-core': r.presence.core_version = '3.2.157'
    elif defect == 'wrong-presence-foundation': r.presence.foundation_version = '3.2.157'
    elif defect == 'expired-presence': r.presence.last_seen_at = r.when - timedelta(seconds=91)
    elif defect == 'future-presence': r.presence.last_seen_at = r.when + timedelta(seconds=31)
    elif defect == 'pre-start-presence': r.presence.last_seen_at = NOW
    elif defect == 'missing-wss': await db.delete(r.wss)
    elif defect == 'closed-wss': r.wss.closed_at = r.when
    elif defect == 'old-wss': r.wss.created_at = NOW
    elif defect == 'future-wss-start': r.wss.created_at = r.when + timedelta(seconds=31)
    elif defect == 'expired-wss': r.wss.expires_at = r.when
    elif defect == 'stale-wss': r.wss.last_seen_at = r.when - timedelta(seconds=91)
    elif defect == 'future-wss': r.wss.last_seen_at = r.when + timedelta(seconds=31)
    elif defect == 'foreign-instance': r.wss.device_instance_id = uuid4()
    elif defect == 'wrong-agent': r.instance.agent_version = '3.2.157'
    elif defect == 'wrong-launcher': r.instance.launcher_version = '3.2.157'
    elif defect == 'stale-instance': r.instance.last_seen_at = r.when - timedelta(seconds=91)
    elif defect == 'future-instance': r.instance.last_seen_at = r.when + timedelta(seconds=31)
    elif defect == 'wrong-platform': r.instance.platform = 'linux_amd64'
    elif defect == 'missing-start': r.job.started_at = None
    elif defect == 'missing-health': await db.delete(r.health)
    elif defect == 'listener-unavailable': r.health.activity_listener_state = 'UNAVAILABLE'
    elif defect == 'missing-sensor': r.health.user_sensor_last_seen_at = None
    elif defect == 'stale-sensor': r.health.user_sensor_last_seen_at = r.when - timedelta(seconds=151)
    elif defect == 'future-sensor': r.health.user_sensor_last_seen_at = r.when + timedelta(seconds=31)
    elif defect == 'stale-health': r.health.received_at = r.when - timedelta(seconds=151)
    elif defect == 'future-health': r.health.received_at = r.when + timedelta(seconds=31)
    elif defect == 'stale-observation': r.health.observed_at = r.when - timedelta(seconds=151)
    elif defect == 'pre-start-health': r.health.user_sensor_last_seen_at = NOW
    elif defect == 'health-policy-id': r.health.policy_id = uuid4()
    elif defect == 'health-policy-version': r.health.policy_version = 2
    elif defect == 'missing-policy-state': await db.delete(r.policy_state)
    elif defect == 'policy-error': r.policy_state.status = 'ERROR'
    elif defect == 'policy-digest': r.policy_state.policy_digest = 'f' * 64
    elif defect == 'policy-version': r.policy_state.policy_version_id = uuid4()
    elif defect == 'changed-effective-policy':
        version = await create_policy_version(db, POLICY_ID,
            EndpointPolicyV1.model_validate(_policy(policy_version=2)), actor_id=uuid4())
        await assign_device_policy(db, r.job.device_id, version.id, actor_id=uuid4())
    elif defect == 'missing-effective-policy':
        assignment = await db.scalar(select(PolicyAssignment).where(PolicyAssignment.device_id == r.job.device_id))
        await db.delete(assignment)
    elif defect == 'missing-activity': await db.delete(r.activity)
    elif defect == 'stale-activity': r.activity.last_observed_at = r.when - timedelta(seconds=151)
    elif defect == 'future-activity': r.activity.last_observed_at = r.when + timedelta(seconds=31)
    elif defect == 'pre-start-activity': r.activity.last_observed_at = NOW
    elif defect == 'missing-activity-observation': r.activity.last_observed_at = None
    elif defect == 'future-projection-update': r.activity.updated_at = r.when + timedelta(seconds=31)
    before = r.job.status
    await db.flush()
    with pytest.raises(SetupConflict):
        await record_progress(db, r.job.device_id, r.job.id, report, now=r.when)
    assert r.job.status == before and r.job.finished_at is None


@pytest.mark.parametrize('kind', ['active-core', 'active-preparation', 'incomplete-linked-preparation'])
@pytest.mark.parametrize('observer_version', ['1.0.6', '1.0.7'])
async def test_target_recovery_preserves_other_update_ownership(db, recovered, kind, observer_version):
    r = recovered
    r.presence.client_version = observer_version
    core = build('3.2.170', 'other-owner-' + uuid4().hex)
    rollout = UpdateRollout(id=uuid4(), rollout_identifier=uuid4().hex, build_id=core.id,
        mode='canary', status='active', reason='Other update ownership')
    db.add_all([core, rollout])
    await db.flush()
    if kind == 'active-core':
        db.add(UpdateTarget(id=uuid4(), rollout_id=rollout.id, device_id=r.job.device_id,
            target_identifier=uuid4().hex, operation_id=uuid4().hex,
            status='scheduled', assigned_at=r.when, requested_at=r.when, updated_at=r.when))
    else:
        db.add(SetupPreparation(id=uuid4(), device_id=r.job.device_id, release_id=r.release.id,
            bridge_rollout_id=rollout.id, status='recovering_client', requested_by='test-admin',
            reason='Existing preparation', updated_at=r.when,
            assignment_id=r.job.id if kind == 'incomplete-linked-preparation' else None))
    await db.flush()
    with pytest.raises(SetupConflict):
        await record_progress(db, r.job.device_id, r.job.id, r.report, now=r.when)
    assert r.job.status == 'recovery_required' and r.job.finished_at is None


async def test_changed_terminal_target_recovery_replay_is_rejected(db, recovered):
    r = recovered
    await record_progress(db, r.job.device_id, r.job.id, r.report, now=r.when)
    changed = r.report.model_dump()
    changed['proof']['soak']['samples'] = 7
    with pytest.raises(SetupConflict):
        await record_progress(db, r.job.device_id, r.job.id, changed, now=r.when)


async def test_unchanged_activity_projection_with_fresh_observation_allows_target_recovery(db, recovered):
    r = recovered
    # Repeated unchanged activity advances last_observed_at without changing the projection epoch.
    r.activity.updated_at = NOW - timedelta(hours=3)
    await db.flush()
    await record_progress(db, r.job.device_id, r.job.id, r.report, now=r.when)
    assert r.job.status == 'failed' and r.job.last_report['proof']['exit_code'] == 21


@pytest.mark.parametrize('cycle', [False, True])
async def test_unknown_native_hold_cannot_be_promoted_through_authenticated_progress_api(db, state, recovered, monkeypatch, cycle):
    import httpx
    from endpoint_server.setup_updates import service
    from tests.server.test_setup_update_api import boundary

    r = recovered
    r.job.status = 'installing'
    r.job.safe_code = None
    r.job.last_report = None
    app, token = await boundary(db, state)
    job_id, attempt_id = r.job.id, r.report.attempt_id
    monkeypatch.setattr(service, 'now_utc', lambda value=None: r.when)
    path = f'/agent/v1/setup-updates/assignments/{job_id}/progress'
    transport = httpx.ASGITransport(app=app, client=('127.0.0.1', 12345))
    async with httpx.AsyncClient(transport=transport, base_url='https://endpoint.sosnadmin.local',
                                headers={'Authorization': 'Bearer ' + token}) as client:
        unknown = dict(attempt_id=str(attempt_id), phase='recovery_required', safe_code='setup_outcome_unknown')
        assert (await client.post(path, json=unknown)).status_code == 200
        if cycle:
            assert (await client.post(path, json=dict(attempt_id=str(attempt_id), phase='verifying'))).status_code == 200
            assert (await client.post(path, json=dict(attempt_id=str(attempt_id), phase='verifying',
                safe_code='post_install_observation'))).status_code == 200
        promotion = dict(attempt_id=str(attempt_id), phase='recovery_required',
                         safe_code='native_exit_requires_recovery')
        assert (await client.post(path, json=promotion)).status_code == 409
        assert (await client.post(path, json=r.report.model_dump(mode='json'))).status_code == 409
    await db.refresh(r.job)
    assert r.job.status in ('recovery_required', 'verifying') and r.job.finished_at is None
    assert r.job.safe_code == 'setup_outcome_unknown'
    if cycle:
        assert r.job.last_report['safe_code'] == 'post_install_observation'
        observed = (await db.scalars(select(AuditEvent).where(AuditEvent.action == 'setup_updates.progress'))).all()
        assert any(event.details.get('reported_safe_code') == 'post_install_observation' for event in observed)


async def test_known_exit_hold_keeps_its_origin_across_observation_updates(db, recovered):
    r = recovered
    await record_progress(db, r.job.device_id, r.job.id, SetupProgressV1(
        attempt_id=r.report.attempt_id, phase='recovery_required', safe_code='native_accepted'), now=r.when)
    assert r.job.safe_code == 'native_exit_requires_recovery'
    assert r.job.last_report['safe_code'] == 'native_accepted'
    await record_progress(db, r.job.device_id, r.job.id, r.report, now=r.when)
    assert r.job.status == 'failed' and r.job.last_report['proof']['exit_code'] == 21


@pytest.mark.parametrize('phase,native_phase,exit_code', [('applied', 'accepted', 0), ('rolled_back', 'rolled-back', 67)])
async def test_unknown_hold_still_accepts_existing_verified_terminal_proofs(db, recovered, phase, native_phase, exit_code):
    r = recovered
    r.job.safe_code = 'setup_outcome_unknown'
    await db.flush()
    await record_progress(db, r.job.device_id, r.job.id, SetupProgressV1(
        attempt_id=r.report.attempt_id, phase='verifying'), now=r.when)
    assert r.job.safe_code == 'setup_outcome_unknown'
    evidence = proof()
    evidence.update(native_phase=native_phase, exit_code=exit_code)
    await record_progress(db, r.job.device_id, r.job.id, SetupProgressV1(
        attempt_id=r.report.attempt_id, phase=phase, proof=evidence), now=r.when)
    assert r.job.status == phase and r.job.last_report['proof']['exit_code'] == exit_code
