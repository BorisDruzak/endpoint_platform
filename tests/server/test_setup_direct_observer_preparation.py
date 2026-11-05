"""A missing modern observer receives an upward Core child, never bridge163."""
from datetime import timedelta
from uuid import uuid4

import pytest
from sqlalchemy import delete, select

from endpoint_server.db.models import DeviceInstance, DeviceSession, UpdateTarget, UpdateRollout
from endpoint_server.setup_updates.models import SetupClientPresence, SetupAssignment, SetupFleetQualification, SetupFleetDecision
from endpoint_server.setup_updates.preparation import request_setup, advance_preparations
from endpoint_server.setup_updates.service import record_presence
from tests.server.test_setup_preparation import build
from tests.server.test_setup_update_service import db, state, NOW
from tests.server.test_setup_fleet_policy import fleet, decision, qualification_evidence
from endpoint_server.setup_updates.policy import qualify_release
from endpoint_server.setup_updates.service import SetupConflict


async def modern_source(db, state):
    device, release, *_ = state
    release.version = '3.2.167'
    await db.execute(delete(SetupClientPresence).where(SetupClientPresence.device_id == device.id))
    instance = DeviceInstance(id=uuid4(), device_id=device.id,
        instance_identifier='modern-no-observer', platform='windows_amd64',
        agent_version='3.2.165', launcher_version='3.2.165', last_seen_at=NOW)
    bootstrap = build('3.2.166', 'endpoint-windows-core-3.2.166-observer-bootstrap')
    bootstrap.minimum_launcher_version = '3.2.158'
    db.add_all([instance, bootstrap]); await db.flush()
    connection = DeviceSession(id=uuid4(), device_id=device.id, device_instance_id=instance.id,
        session_identifier='gateway-modern-source', created_at=NOW-timedelta(minutes=4),
        last_seen_at=NOW, expires_at=NOW+timedelta(minutes=2))
    db.add(connection); await db.flush()
    return device, release, instance, connection, bootstrap


async def test_modern_missing_observer_prepares_upward_then_assigns_without_return(db, state):
    device, release, instance, connection, bootstrap = await modern_source(db, state)
    prep = await request_setup(db, device.id, release.id, 'Prepare observer through Endpoint',
        actor='test-admin', request_id='modern-bootstrap', now=NOW)
    assert prep.status == 'preparing_client' and prep.return_build_id is None
    child = await db.scalar(select(UpdateTarget).where(UpdateTarget.rollout_id == prep.bridge_rollout_id))
    assert (await db.get(UpdateRollout, child.rollout_id)).build_id == bootstrap.id
    child.status = 'applied'
    instance.agent_version = '3.2.166'
    await record_presence(db, device.id, dict(client_version='1.0.6', ready=True,
        core_version='3.2.166', foundation_version='3.2.165'), now=NOW)
    await advance_preparations(db, now=NOW)
    job = await db.get(SetupAssignment, prep.id)
    assert prep.status == 'completed' and prep.return_rollout_id is None
    assert job.status == 'assigned' and job.source_core_version == '3.2.166'
    assert job.source_foundation_version == '3.2.165' and job.source_client_version == '1.0.6'
    assert len((await db.scalars(select(UpdateTarget))).all()) == 1


@pytest.mark.parametrize('fault', ['old_observer', 'not_ready', 'wss_core_mismatch'])
async def test_direct_preparation_waits_for_matching_fixed_observer_and_wss(db, state, fault):
    device, release, instance, connection, bootstrap = await modern_source(db, state)
    prep = await request_setup(db, device.id, release.id, 'Prepare observer through Endpoint',
        actor='test-admin', request_id='modern-wait', now=NOW)
    child = await db.scalar(select(UpdateTarget).where(UpdateTarget.rollout_id == prep.bridge_rollout_id))
    child.status = 'applied'
    instance.agent_version = '3.2.165' if fault == 'wss_core_mismatch' else '3.2.166'
    await record_presence(db, device.id, dict(client_version='1.0.5' if fault == 'old_observer' else '1.0.6',
        ready=fault != 'not_ready', core_version='3.2.166', foundation_version='3.2.165'), now=NOW)
    await advance_preparations(db, now=NOW)
    assert prep.status == 'preparing_client'
    assert await db.get(SetupAssignment, prep.id) is None


async def test_newer_http_pull_does_not_shadow_matching_bootstrap_wss(db, state):
    device, release, instance, connection, _ = await modern_source(db, state)
    prep = await request_setup(db, device.id, release.id, 'Prepare observer through Endpoint',
        actor='test-admin', request_id='http-shadow', now=NOW)
    child = await db.scalar(select(UpdateTarget).where(UpdateTarget.rollout_id == prep.bridge_rollout_id))
    child.status = 'applied'; instance.agent_version = '3.2.166'
    db.add(DeviceSession(id=uuid4(), device_id=device.id, device_instance_id=None,
        session_identifier='http-pull-newer', created_at=NOW-timedelta(seconds=2),
        last_seen_at=NOW, expires_at=NOW+timedelta(minutes=2)))
    await record_presence(db, device.id, dict(client_version='1.0.6', ready=True,
        core_version='3.2.166', foundation_version='3.2.165'), now=NOW)
    await advance_preparations(db, now=NOW)
    assert prep.status == 'completed'
    assert await db.get(SetupAssignment, prep.id) is not None


@pytest.mark.parametrize('fault', [None, 'wrong_bootstrap', 'failed_child', 'wrong_floor', 'wrong_source_core'])
async def test_direct_chain_can_qualify_only_exact_applied_bootstrap(db, fleet, fault):
    from endpoint_server.setup_updates.models import SetupPreparation
    from endpoint_server.db.models import UpdateBuild
    fleet[1].version = '3.2.167'
    job, _ = await qualification_evidence(db, fleet, source_foundation='3.2.165')
    prep = await db.scalar(select(SetupPreparation).where(SetupPreparation.assignment_id == job.id))
    bridge = await db.get(UpdateRollout, prep.bridge_rollout_id)
    bootstrap = await db.get(UpdateBuild, bridge.build_id)
    bootstrap.build_identifier = 'wrong-observer' if fault == 'wrong_bootstrap' else 'endpoint-windows-core-3.2.166-observer-bootstrap'
    bootstrap.version = '3.2.166'
    bootstrap.minimum_launcher_version = '3.2.166' if fault == 'wrong_floor' else '3.2.158'
    await db.execute(delete(UpdateTarget).where(UpdateTarget.rollout_id == prep.return_rollout_id))
    prep.return_build_id = prep.return_rollout_id = None
    child = await db.scalar(select(UpdateTarget).where(UpdateTarget.rollout_id == bridge.id))
    child.status = 'failed' if fault == 'failed_child' else 'applied'
    job.source_core_version = '3.2.165' if fault == 'wrong_source_core' else '3.2.166'
    job.source_client_version = '1.0.6'
    presence = await db.scalar(select(SetupClientPresence).where(SetupClientPresence.device_id == job.device_id))
    presence.client_version = '1.0.6'
    await db.flush()
    if fault:
        with pytest.raises(SetupConflict):
            await qualify_release(db, fleet[1].id, job.id, actor='test-admin', request_id='direct-proof', now=NOW)
    else:
        q = await qualify_release(db, fleet[1].id, job.id, actor='test-admin', request_id='direct-proof', now=NOW)
        assert q.source_foundation == '3.2.165' and q.evidence_assignment_id == job.id


async def fleet_bootstrap_source(db, fleet):
    device, release, policy, instance = fleet
    release.version = '3.2.167'
    instance.agent_version = instance.launcher_version = '3.2.165'
    await db.execute(delete(SetupClientPresence).where(SetupClientPresence.device_id == device.id))
    connection = await db.scalar(select(DeviceSession).where(DeviceSession.device_id == device.id))
    connection.created_at = NOW-timedelta(minutes=4)
    q = await db.scalar(select(SetupFleetQualification).where(SetupFleetQualification.release_id == release.id))
    q.source_foundation = '3.2.165'
    bootstrap = build('3.2.166', 'endpoint-windows-core-3.2.166-observer-bootstrap')
    bootstrap.minimum_launcher_version = '3.2.158'
    db.add(bootstrap); await db.flush()
    return connection, q, bootstrap


async def test_fleet_admits_registered_upward_bootstrap_after_observer_grace(db, fleet):
    await fleet_bootstrap_source(db, fleet)
    assert (await decision(db, fleet)).code == 'eligible'


@pytest.mark.parametrize('fault', ['late_hello', 'missing_build', 'busy_observer', 'same_version_target'])
async def test_observer_bootstrap_does_not_replace_busy_late_or_unsupported_sources(db, fleet, fault):
    connection, _, bootstrap = await fleet_bootstrap_source(db, fleet)
    if fault == 'late_hello':
        connection.created_at = NOW
    elif fault == 'missing_build':
        await db.delete(bootstrap)
    elif fault == 'busy_observer':
        await record_presence(db, fleet[0].id, dict(client_version='1.0.5', ready=False,
            core_version='3.2.165', foundation_version='3.2.165'), now=NOW)
    else:
        fleet[1].version = '3.2.166'
    await db.flush()
    assert (await decision(db, fleet)).code == 'waiting_setup_client'


async def test_automatic_direct_preparation_rechecks_source_qualification_before_native(db, fleet):
    _, qualification, _ = await fleet_bootstrap_source(db, fleet)
    device, release, policy, instance = fleet
    prep = await request_setup(db, device.id, release.id, 'Automatic observer preparation',
        actor='test-admin', request_id='direct-qualified', now=NOW)
    db.add(SetupFleetDecision(id=uuid4(), policy_id=policy.id, policy_revision=policy.revision,
        device_id=device.id, release_id=release.id, target_sha256=release.sha256,
        status='preparing_client', safe_code='chain_requested', job_id=prep.id, evaluated_at=NOW))
    child = await db.scalar(select(UpdateTarget).where(UpdateTarget.rollout_id == prep.bridge_rollout_id))
    child.status = 'applied'; instance.agent_version = '3.2.166'
    await record_presence(db, device.id, dict(client_version='1.0.6', ready=True,
        core_version='3.2.166', foundation_version='3.2.165'), now=NOW)
    await db.delete(qualification); await db.flush()
    await advance_preparations(db, now=NOW)
    assert prep.status == 'blocked' and prep.safe_code == 'source_not_qualified'
    assert await db.get(SetupAssignment, prep.id) is None
