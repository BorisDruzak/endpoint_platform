"""Fleet admission is distinct from native acceptance and never repeats an attempt."""
from datetime import timedelta
from uuid import uuid4

import pytest
from sqlalchemy import select

from endpoint_server.db.models import DeviceInstance, DeviceSession, UpdateTarget
from endpoint_server.setup_updates.models import SetupAssignment, SetupFleetPolicy, SetupFleetDecision, SetupFleetQualification
from endpoint_server.setup_updates.policy import evaluate_device, load_device_facts, update_policy, qualify_release, FleetPolicyUpdate
from endpoint_server.setup_updates.scheduler import schedule_one
from endpoint_server.setup_updates.service import SetupConflict
from tests.server.test_setup_update_service import db, state, NOW, proof


@pytest.fixture
async def fleet(db, state):
    # Reuse the real canonical Setup service and its ownership tables.
    async with db.bind.begin() as conn:
        await conn.run_sync(lambda c: SetupFleetPolicy.metadata.create_all(c, tables=[
            SetupFleetPolicy.__table__, SetupFleetDecision.__table__, SetupFleetQualification.__table__]))
    device, release, *_ = state
    from endpoint_server.setup_updates.service import record_presence
    await record_presence(db, device.id, dict(client_version='1.0.5', ready=True,
        foundation_version='3.2.156', core_version='3.2.156'), now=NOW)
    instance = DeviceInstance(id=uuid4(), device_id=device.id, instance_identifier='fleet156',
        platform='windows_amd64', agent_version='3.2.156', launcher_version='3.2.156', last_seen_at=NOW)
    db.add(instance)
    await db.flush()
    db.add(DeviceSession(id=uuid4(), device_id=device.id, device_instance_id=instance.id,
        session_identifier='gateway-fleet', expires_at=NOW + timedelta(minutes=2), last_seen_at=NOW))
    from endpoint_server.db.models import Device
    witness = Device(id=uuid4(), device_identifier='retired-qualification-fixture', retired_at=NOW)
    db.add(witness); await db.flush()
    evidence = SetupAssignment(id=uuid4(), device_id=witness.id, release_id=release.id, status='applied',
        reason='Isolated qualification fixture', assigned_at=NOW, updated_at=NOW)
    db.add(evidence); await db.flush()
    db.add(SetupFleetQualification(id=uuid4(), release_id=release.id, sha256=release.sha256,
        source_foundation='3.2.156', evidence_assignment_id=evidence.id, qualified_at=NOW,
        expires_at=NOW + timedelta(days=30), qualified_by='test-only', evidence_code='isolated_fixture'))
    await db.flush()
    policy = await update_policy(db, FleetPolicyUpdate(expected_revision=0, enabled=True,
        release_id=release.id, scope='all_active', max_parallel=1, reason='Isolated fleet test'),
        actor='test-admin', request_id='policy', now=NOW)
    return device, release, policy, instance


async def decision(db, fleet):
    device, release, policy, _ = fleet
    facts = await load_device_facts(db, device.id, release.id, now=NOW)
    return evaluate_device(policy, release, facts, now=NOW)


@pytest.mark.parametrize('client_version', ['1.0.5', '1.0.6', '1.0.7', '1.0.8'])
async def test_companion_fixed_observer_keeps_existing_native_qualification_gates(db, fleet, client_version):
    from endpoint_server.setup_updates.models import SetupClientPresence
    from endpoint_server.setup_updates.preparation import ready
    from endpoint_server.setup_updates.service import qualified_presence
    job, _ = await qualification_evidence(db, fleet)
    job.source_client_version = client_version
    presence = await db.scalar(select(SetupClientPresence).where(SetupClientPresence.device_id == job.device_id))
    presence.client_version = client_version
    assert qualified_presence(presence, NOW)
    assert ready(presence, NOW)
    qualified = await qualify_release(db, fleet[1].id, job.id,
        actor='test-admin', request_id='observer-compatible', now=NOW)
    assert qualified.evidence_assignment_id == job.id


@pytest.mark.parametrize('location', ['source', 'presence'])
async def test_unqualified_observer_cannot_supply_native_qualification(db, fleet, location):
    from endpoint_server.setup_updates.models import SetupClientPresence
    job, _ = await qualification_evidence(db, fleet)
    if location == 'source':
        job.source_client_version = '1.0.9'
    else:
        presence = await db.scalar(select(SetupClientPresence).where(SetupClientPresence.device_id == job.device_id))
        presence.client_version = '1.0.9'
    with pytest.raises(SetupConflict):
        await qualify_release(db, fleet[1].id, job.id,
            actor='test-admin', request_id='unqualified-observer', now=NOW)


async def test_fleet_requires_exact_authenticated_platform_and_fresh_open_wss(db, fleet):
    assert (await decision(db, fleet)).code == 'eligible'
    fleet[3].platform = None
    assert (await decision(db, fleet)).code == 'platform_unknown'
    fleet[3].platform = 'linux_amd64'
    assert (await decision(db, fleet)).code == 'platform_unsupported'
    fleet[3].platform = 'windows_amd64'
    fleet[3].last_seen_at = NOW - timedelta(minutes=5)
    assert (await decision(db, fleet)).code == 'waiting_reconnect'


async def test_same_or_newer_foundation_is_never_reinstalled_or_downgraded(db, fleet):
    for version in ('3.2.158', '3.2.163'):
        fleet[3].launcher_version = version
        fleet[3].agent_version = version
        assert (await decision(db, fleet)).code == 'already_current'


async def test_unknown_and_unqualified_source_are_persistably_blocked(db, fleet):
    fleet[3].launcher_version = '3.2.157'
    assert (await decision(db, fleet)).code == 'source_not_qualified'
    fleet[3].launcher_version = None
    assert (await decision(db, fleet)).code == 'source_unknown'


async def test_policy_revision_conflict_cannot_overwrite_operator_choice(db, fleet):
    with pytest.raises(SetupConflict):
        await update_policy(db, FleetPolicyUpdate(expected_revision=0, enabled=False,
            release_id=fleet[1].id, scope='all_active', max_parallel=1, reason='Stale tab'),
            actor='other', request_id='stale', now=NOW)
    assert fleet[2].enabled


async def test_preview_is_read_only_and_pause_stops_new_chains(db, fleet):
    fleet[2].enabled = False
    assert await schedule_one(db, now=NOW) is False
    assert (await db.scalars(select(SetupAssignment).where(SetupAssignment.device_id == fleet[0].id))).all() == []
    assert (await db.scalars(select(SetupFleetDecision))).all() == []


async def test_active_manual_native_hold_occupies_capacity_and_is_not_cancelled(db, fleet):
    from endpoint_server.db.models import Device
    other = Device(id=uuid4(), device_identifier='manual-held')
    db.add(other); await db.flush()
    job = SetupAssignment(id=uuid4(), device_id=other.id, release_id=fleet[1].id,
        status='recovery_required', reason='Manual unresolved native', assigned_at=NOW, updated_at=NOW)
    db.add(job); await db.flush()
    await schedule_one(db, now=NOW)
    await schedule_one(db, now=NOW)
    row = await db.scalar(select(SetupFleetDecision).where(SetupFleetDecision.device_id == fleet[0].id))
    assert row.safe_code == 'capacity_full'
    assert job.status == 'recovery_required'
    assert len((await db.scalars(select(SetupAssignment).where(SetupAssignment.status == 'recovery_required'))).all()) == 1


async def test_previous_native_failure_cannot_be_retried_by_new_policy_revision(db, fleet):
    device, release, *_ = fleet
    db.add(SetupAssignment(id=uuid4(), device_id=device.id, release_id=release.id,
        status='failed', reason='Previous attempt', assigned_at=NOW, updated_at=NOW))
    await db.flush()
    assert (await decision(db, fleet)).code == 'previous_attempt_requires_review'


async def test_new_qualification_rejects_sensor_absence_before_writing_record(db, state):
    device, release, *_ = state
    job = SetupAssignment(id=uuid4(), device_id=device.id, release_id=release.id, status='applied',
        reason='Evidence', assigned_at=NOW, updated_at=NOW, started_at=NOW-timedelta(minutes=4),
        finished_at=NOW, attempt_id=uuid4())
    evidence = proof(); evidence['soak']['sensor_count'] = 0
    job.last_report = dict(attempt_id=str(job.attempt_id), phase='applied', proof=evidence)
    db.add(job); await db.flush()
    with pytest.raises(SetupConflict):
        await qualify_release(db, release.id, job.id, actor='test-admin', request_id='qualify', now=NOW)


async def test_scheduler_requests_canonical_job_once_across_restart_and_policy_revision(db, fleet):
    device, release, policy, _ = fleet
    await schedule_one(db, now=NOW)
    row = await db.scalar(select(SetupFleetDecision))
    assert row.job_id is not None and row.status == 'assigned'
    assert (await db.get(SetupAssignment, row.job_id)).release_id == release.id
    await schedule_one(db, now=NOW+timedelta(seconds=1))
    policy.revision += 1
    await schedule_one(db, now=NOW+timedelta(seconds=2))
    assert len((await db.scalars(select(SetupAssignment).where(SetupAssignment.device_id == device.id))).all()) == 1


async def test_owned_native_hold_trips_circuit_without_changing_native_state(db, fleet):
    await schedule_one(db, now=NOW)
    row = await db.scalar(select(SetupFleetDecision))
    job = await db.get(SetupAssignment, row.job_id)
    job.status = 'recovery_required'
    await db.flush()
    assert await schedule_one(db, now=NOW+timedelta(seconds=1)) is False
    assert fleet[2].enabled is False and fleet[2].safe_code == 'fleet_failure_requires_review'
    assert job.status == 'recovery_required'


async def qualification_evidence(db, fleet, *, bridge='3.2.163', source_foundation='3.2.156'):
    from endpoint_server.db.models import UpdateBuild, UpdateRollout, PolicySensorHealthCurrent
    from endpoint_server.setup_updates.models import SetupPreparation
    from endpoint_server.setup_updates.service import record_presence
    from tests.server.test_setup_preparation import build
    device, release, _, instance = fleet
    instance.agent_version = instance.launcher_version = release.version
    job = SetupAssignment(id=uuid4(), device_id=device.id, release_id=release.id, status='applied',
        reason='Real-shaped qualification proof', assigned_at=NOW-timedelta(minutes=6), updated_at=NOW,
        started_at=NOW-timedelta(minutes=4), finished_at=NOW, attempt_id=uuid4(),
        source_foundation_version=source_foundation,
        source_core_version='3.2.155' if source_foundation == '3.2.156' else '3.2.157', source_client_version='1.0.5')
    native_proof = proof()
    native_proof['foundation_version'] = native_proof['core_version'] = release.version
    job.last_report = dict(attempt_id=str(job.attempt_id), phase='applied', proof=native_proof)
    db.add(job)
    bridge_name = f'endpoint-windows-core-{bridge}-setup-client'
    source_name = ('endpoint-windows-core-3.2.155-setup-source-725739f'
        if source_foundation == '3.2.156' else 'endpoint-windows-core-3.2.157-setup-source')
    bridge_build = await db.scalar(select(UpdateBuild).where(UpdateBuild.build_identifier == bridge_name))
    source_build = await db.scalar(select(UpdateBuild).where(UpdateBuild.build_identifier == source_name))
    bridge_build = bridge_build or build(bridge, bridge_name)
    source_build = source_build or build('3.2.155' if source_foundation == '3.2.156' else '3.2.157', source_name)
    db.add_all([bridge_build, source_build]); await db.flush()
    rollouts = []
    for b in (bridge_build, source_build):
        rollout = UpdateRollout(id=uuid4(), rollout_identifier=uuid4().hex, build_id=b.id, mode='canary', status='completed')
        db.add(rollout); await db.flush()
        db.add(UpdateTarget(id=uuid4(), rollout_id=rollout.id, device_id=device.id,
            target_identifier=uuid4().hex, operation_id=uuid4().hex, status='applied', assigned_at=NOW))
        rollouts.append(rollout)
    db.add(SetupPreparation(id=uuid4(), device_id=device.id, release_id=release.id, assignment_id=job.id,
        bridge_rollout_id=rollouts[0].id, return_rollout_id=rollouts[1].id, return_build_id=source_build.id,
        status='completed', reason='Source156 qualification', requested_by='test-admin', updated_at=NOW))
    connection = await db.scalar(select(DeviceSession).where(DeviceSession.device_id == device.id))
    connection.created_at = NOW-timedelta(minutes=3)
    await record_presence(db, device.id, dict(client_version='1.0.5', ready=True,
        foundation_version=release.version, core_version=release.version), now=NOW)
    async with db.bind.begin() as conn:
        await conn.run_sync(lambda c: PolicySensorHealthCurrent.__table__.create(c, checkfirst=True))
    health = PolicySensorHealthCurrent(id=uuid4(), device_id=device.id, observation_id=uuid4(),
        policy_id=uuid4(), policy_version=1, observed_at=NOW, received_at=NOW,
        activity_listener_state='READY', user_sensor_last_seen_at=NOW,
        security_spool_state='READY', usb_source_state='READY', print_source_state='READY')
    db.add(health); await db.flush()
    return job, health


async def test_exact_completed_163_chain_and_fresh_user_sensor_qualifies_without_enabling_policy(db, fleet):
    job, _ = await qualification_evidence(db, fleet)
    fleet[2].enabled = False
    result = await qualify_release(db, fleet[1].id, job.id, actor='test-admin', request_id='qualify', now=NOW)
    assert result.evidence_assignment_id == job.id and result.sha256 == fleet[1].sha256
    assert result.source_foundation == '3.2.156'
    assert fleet[2].enabled is False


@pytest.mark.parametrize('fault', ['old_bridge', 'stale_sensor'])
async def test_qualification_rejects_old_bridge_or_stale_sensor(db, fleet, fault):
    job, health = await qualification_evidence(db, fleet, bridge='3.2.162' if fault == 'old_bridge' else '3.2.163')
    if fault == 'stale_sensor':
        health.user_sensor_last_seen_at = NOW-timedelta(minutes=10)
    with pytest.raises(SetupConflict):
        await qualify_release(db, fleet[1].id, job.id, actor='test-admin', request_id='qualify', now=NOW)


async def test_failed_canonical_request_rolls_back_partial_job_and_pauses_without_replay(db, fleet, monkeypatch):
    import endpoint_server.setup_updates.scheduler as scheduler
    async def reject(session, device_id, release_id, *args, **kwargs):
        session.add(SetupAssignment(id=uuid4(), device_id=device_id, release_id=release_id,
            status='assigned', reason='Must roll back', assigned_at=NOW, updated_at=NOW))
        await session.flush()
        raise SetupConflict('private error must not escape')
    monkeypatch.setattr(scheduler, 'request_setup', reject)
    await schedule_one(db, now=NOW)
    assert not fleet[2].enabled
    row = await db.scalar(select(SetupFleetDecision))
    assert row.safe_code == 'canonical_request_rejected' and row.job_id is None
    assert (await db.scalars(select(SetupAssignment).where(SetupAssignment.device_id == fleet[0].id))).all() == []
    assert (await decision(db, fleet)).code == 'previous_attempt_requires_review'


async def test_complete_chain_reserves_one_slot_including_a_manual_core_child(db, fleet):
    from endpoint_server.setup_updates.policy import active_chain_devices
    from endpoint_server.setup_updates.models import SetupPreparation
    from endpoint_server.db.models import UpdateRollout
    from tests.server.test_setup_preparation import build
    device, release, *_ = fleet
    core = build('3.2.163', 'endpoint-windows-core-3.2.163-setup-client')
    db.add(core); await db.flush()
    rollout = UpdateRollout(id=uuid4(), rollout_identifier=uuid4().hex, build_id=core.id, mode='canary', status='active')
    db.add(rollout); await db.flush()
    db.add(UpdateTarget(id=uuid4(), rollout_id=rollout.id, device_id=device.id,
        target_identifier=uuid4().hex, operation_id=uuid4().hex, status='assigned', assigned_at=NOW))
    await db.flush()
    assert await active_chain_devices(db) == set()
    assert (await decision(db, fleet)).code == 'active_operation'
    db.add(SetupPreparation(id=uuid4(), device_id=device.id, release_id=release.id,
        bridge_rollout_id=rollout.id, status='preparing_client', reason='Manual chain', requested_by='test', updated_at=NOW))
    await db.flush()
    assert await active_chain_devices(db) == {device.id}
    assert (await decision(db, fleet)).code == 'active_operation'


async def test_manual_full_setup_cannot_exceed_enabled_policy_limit_but_pause_allows_operator_canary(db, fleet):
    from endpoint_server.setup_updates.policy import reserve_fleet_admission
    from endpoint_server.db.models import Device
    held = Device(id=uuid4(), device_identifier='manual-admission-hold')
    db.add(held); await db.flush()
    db.add(SetupAssignment(id=uuid4(), device_id=held.id, release_id=fleet[1].id,
        status='recovery_required', reason='Existing native owner', assigned_at=NOW, updated_at=NOW))
    await db.flush()
    with pytest.raises(SetupConflict):
        await reserve_fleet_admission(db, fleet[0].id)
    # Continuations already owning a slot are not charged a second slot.
    await reserve_fleet_admission(db, held.id)
    fleet[2].enabled = False
    await reserve_fleet_admission(db, fleet[0].id)


@pytest.mark.parametrize('target', ['3.2.159', '3.2.164'])
async def test_actual_qualified_future_full_setup_can_be_selected_without_core_version_ceiling(db, fleet, target):
    fleet[1].version = target
    job, _ = await qualification_evidence(db, fleet)
    qualification = await qualify_release(db, fleet[1].id, job.id, actor='test-admin', request_id='future', now=NOW)
    assert qualification.evidence_assignment_id == job.id
    policy = await update_policy(db, FleetPolicyUpdate(expected_revision=fleet[2].revision, enabled=True,
        release_id=fleet[1].id, scope='all_active', max_parallel=1, reason='Actual future native qualification'),
        actor='test-admin', request_id='future-policy', now=NOW)
    assert policy.release_id == fleet[1].id and policy.enabled


def test_core_only_build_is_not_a_full_setup_target_even_if_number_is_newer():
    from endpoint_server.setup_updates.policy import product_release
    from tests.server.test_setup_preparation import build
    core = build('3.2.164', 'future-core-only')
    assert not product_release(core)
    core.artifact_name = 'MislabelledCore.exe'
    assert not product_release(core)


async def test_current_source158_client_can_qualify_direct_future_setup_without_new_bootstrap(db, fleet):
    from endpoint_server.setup_updates.models import SetupPreparation
    fleet[1].version = '3.2.169'
    job, _ = await qualification_evidence(db, fleet)
    prep = await db.scalar(select(SetupPreparation).where(SetupPreparation.assignment_id == job.id))
    await db.delete(prep)
    job.source_foundation_version = job.source_core_version = '3.2.158'
    qualification = await qualify_release(db, fleet[1].id, job.id, actor='test-admin', request_id='direct', now=NOW)
    assert qualification.source_foundation == '3.2.158'


@pytest.mark.parametrize('field,value', [('source_foundation_version', None), ('source_core_version', None), ('source_client_version', '1.0.4')])
async def test_qualification_rejects_missing_or_legacy_immutable_source_facts(db, fleet, field, value):
    job, _ = await qualification_evidence(db, fleet)
    setattr(job, field, value)
    with pytest.raises(SetupConflict):
        await qualify_release(db, fleet[1].id, job.id, actor='test-admin', request_id='source', now=NOW)


@pytest.mark.parametrize('source', ['3.2.157', '3.2.158'])
async def test_qualified_source_preparation_requires_its_exact_compatible_return(db, fleet, source):
    from endpoint_server.setup_updates.models import SetupPreparation
    from endpoint_server.db.models import UpdateBuild
    fleet[1].version = '3.2.169'
    job, _ = await qualification_evidence(db, fleet, source_foundation=source)
    qualified = await qualify_release(db, fleet[1].id, job.id, actor='test-admin', request_id='mapped', now=NOW)
    assert qualified.source_foundation == source
    prep = await db.scalar(select(SetupPreparation).where(SetupPreparation.assignment_id == job.id))
    returned = await db.get(UpdateBuild, prep.return_build_id)
    returned.build_identifier = 'wrong-source-return'
    with pytest.raises(SetupConflict):
        await qualify_release(db, fleet[1].id, job.id, actor='test-admin', request_id='wrong', now=NOW)


async def same_artifact_alias(db, release):
    from endpoint_server.setup_updates.models import SetupRelease
    alias = SetupRelease(id=uuid4(), release_identifier=uuid4().hex, artifact_name=uuid4().hex+'.exe',
        **{key: getattr(release, key) for key in ('version', 'sha256', 'size', 'source_revision', 'msi_sha256', 'tray_sha256', 'sensor_sha256')})
    db.add(alias); await db.flush()
    return alias


async def test_same_bytes_under_another_release_uuid_cannot_replay_failed_native(db, fleet):
    alias = await same_artifact_alias(db, fleet[1])
    db.add(SetupAssignment(id=uuid4(), device_id=fleet[0].id, release_id=alias.id,
        status='failed', reason='Same native bytes under old name', assigned_at=NOW, updated_at=NOW))
    await db.flush()
    assert (await decision(db, fleet)).code == 'previous_attempt_requires_review'


@pytest.mark.parametrize('same_bytes', [True, False])
async def test_target_switch_does_not_hide_earlier_owned_chain_failure(db, fleet, same_bytes):
    await schedule_one(db, now=NOW)
    owned = await db.scalar(select(SetupFleetDecision))
    job = await db.get(SetupAssignment, owned.job_id)
    job.status = 'failed'
    alias = await same_artifact_alias(db, fleet[1])
    if not same_bytes:
        alias.sha256 = 'f'*64
    fleet[2].release_id = alias.id
    fleet[2].max_parallel = 2
    assert await schedule_one(db, now=NOW+timedelta(seconds=1)) is False
    assert not fleet[2].enabled and fleet[2].safe_code == 'fleet_failure_requires_review'

async def test_all_active_policy_includes_later_registrations_and_reconnects_with_two_global_slots(db, fleet):
    from endpoint_server.db.models import Device
    from endpoint_server.setup_updates.service import record_presence
    device, release, policy, original = fleet
    original.launcher_version = release.version  # Original cohort is already current.
    policy.max_parallel = 2
    later = []
    for index in range(3):
        row = Device(id=uuid4(), device_identifier=f'later-registration-{index}')
        db.add(row); await db.flush()
        instance = DeviceInstance(id=uuid4(), device_id=row.id, instance_identifier=uuid4().hex,
            platform='windows_amd64', agent_version='3.2.156', launcher_version='3.2.156',
            last_seen_at=NOW-timedelta(minutes=10))
        db.add(instance); await db.flush()
        connection = DeviceSession(id=uuid4(), device_id=row.id, device_instance_id=instance.id,
            session_identifier='gateway-'+uuid4().hex, expires_at=NOW+timedelta(minutes=5), last_seen_at=NOW-timedelta(minutes=10))
        db.add(connection)
        await record_presence(db, row.id, dict(client_version='1.0.5', ready=True,
            foundation_version='3.2.156', core_version='3.2.156'), now=NOW-timedelta(minutes=10))
        later.append((row, instance, connection))
    await db.flush()
    for tick in range(4):
        await schedule_one(db, now=NOW+timedelta(seconds=tick))
    assert (await db.scalars(select(SetupAssignment).where(SetupAssignment.device_id.in_([r.id for r, _, _ in later])))).all() == []
    waiting = (await db.scalars(select(SetupFleetDecision).where(SetupFleetDecision.device_id.in_([r.id for r, _, _ in later])))).all()
    assert len(waiting) == 3 and all(row.safe_code == 'waiting_reconnect' for row in waiting)
    for row, instance, connection in later:
        instance.last_seen_at = connection.last_seen_at = NOW+timedelta(seconds=5)
        await record_presence(db, row.id, dict(client_version='1.0.5', ready=True,
            foundation_version='3.2.156', core_version='3.2.156'), now=NOW+timedelta(seconds=5))
    for tick in range(8):
        await schedule_one(db, now=NOW+timedelta(seconds=tick+10))
    assignments = (await db.scalars(select(SetupAssignment).where(SetupAssignment.device_id.in_([r.id for r, _, _ in later])))).all()
    assert len(assignments) == 2
    assert len({job.device_id for job in assignments}) == 2
    decisions = (await db.scalars(select(SetupFleetDecision).where(SetupFleetDecision.device_id.in_([r.id for r, _, _ in later])))).all()
    assert sum(row.job_id is not None for row in decisions) == 2
    assert sum(row.safe_code == 'capacity_full' for row in decisions) == 1
    assert policy.scope == 'all_active' and policy.device_ids == []

async def _modern_source(db, fleet):
    from endpoint_server.setup_updates.models import SetupClientPresence
    device, release, policy, instance = fleet
    release.version = '3.2.165'
    instance.agent_version, instance.launcher_version = '3.2.164', '3.2.158'
    qualification = await db.scalar(select(SetupFleetQualification).where(SetupFleetQualification.release_id == release.id))
    qualification.source_foundation = '3.2.158'
    client = await db.scalar(select(SetupClientPresence).where(SetupClientPresence.device_id == device.id))
    client.client_version, client.foundation_version, client.core_version = '1.0.5', '3.2.158', '3.2.164'
    await db.flush()
    return device, release, policy, instance, client


@pytest.mark.parametrize('client_state', ['missing', 'stale', 'busy'])
async def test_reconnect_waits_for_setup_hello_without_poisoning_future_admission(db, fleet, client_state):
    from endpoint_server.setup_updates.service import record_presence
    device, release, policy, instance, client = await _modern_source(db, fleet)
    if client_state == 'missing':
        await db.delete(client)
    elif client_state == 'stale':
        client.last_seen_at = NOW-timedelta(minutes=12)
    else:
        client.ready = False
    await db.flush()
    await schedule_one(db, now=NOW)
    row = await db.scalar(select(SetupFleetDecision).where(SetupFleetDecision.device_id == device.id))
    assert (row.status, row.safe_code, row.job_id) == ('waiting', 'waiting_setup_client', None)
    assert policy.enabled and policy.safe_code is None
    assert (await db.scalars(select(SetupAssignment).where(SetupAssignment.device_id == device.id))).all() == []
    await record_presence(db, device.id, dict(client_version='1.0.5', ready=True,
        foundation_version='3.2.158', core_version='3.2.164'), now=NOW+timedelta(seconds=1))
    await schedule_one(db, now=NOW+timedelta(seconds=1))
    job = await db.scalar(select(SetupAssignment).where(SetupAssignment.device_id == device.id))
    assert job is not None and job.status == 'assigned'
    assert (job.source_foundation_version, job.source_core_version) == ('3.2.158', '3.2.164')
    assert policy.enabled


@pytest.mark.parametrize('foundation,core', [('3.2.156', '3.2.156'), ('3.2.158', '3.2.163'), (None, None)])
async def test_fleet_never_uses_a_different_observer_source_than_qualified_wss(db, fleet, foundation, core):
    from endpoint_server.setup_updates.models import SetupPreparation
    from endpoint_server.setup_updates.service import record_presence
    device, release, policy, instance, client = await _modern_source(db, fleet)
    client.foundation_version, client.core_version = foundation, core
    await db.flush()
    await schedule_one(db, now=NOW)
    row = await db.scalar(select(SetupFleetDecision).where(SetupFleetDecision.device_id == device.id))
    assert (row.status, row.safe_code, row.job_id) == ('waiting', 'waiting_source_confirmation', None)
    assert policy.enabled
    assert (await db.scalars(select(SetupAssignment).where(SetupAssignment.device_id == device.id))).all() == []
    assert (await db.scalars(select(SetupPreparation).where(SetupPreparation.device_id == device.id))).all() == []
    await record_presence(db, device.id, dict(client_version='1.0.5', ready=True,
        foundation_version='3.2.158', core_version='3.2.164'), now=NOW+timedelta(seconds=1))
    await schedule_one(db, now=NOW+timedelta(seconds=1))
    job = await db.scalar(select(SetupAssignment).where(SetupAssignment.device_id == device.id))
    assert job is not None and job.status == 'assigned'
    assert job.source_foundation_version == '3.2.158'
