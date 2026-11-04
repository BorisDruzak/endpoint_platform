from datetime import timedelta
from uuid import uuid4

from sqlalchemy import select, delete

from endpoint_server.db.models import UpdateBuild, UpdateTarget, DeviceInstance
from endpoint_server.setup_updates.models import SetupClientPresence, SetupAssignment
from endpoint_server.setup_updates.preparation import request_setup, advance_preparations, cancel_preparation
from endpoint_server.setup_updates.service import record_presence
from tests.server.test_setup_update_service import db, state, NOW
from endpoint_server.setup_updates.service import SetupConflict
from endpoint_server.updates.service import create_rollout
from endpoint_server.updates.errors import UpdateConflict
import pytest


async def test_legacy_ready_client_is_upgraded_before_new_unattended_setup(db, state):
    device, release, *_ = state
    await record_presence(db, device.id, dict(client_version='1.0.4', ready=True,
        core_version='3.2.156', foundation_version='3.2.156'), now=NOW)
    bridge = build('3.2.163', 'endpoint-windows-core-3.2.163-setup-client')
    source = build('3.2.155', 'endpoint-windows-core-3.2.155-setup-source-725739f')
    source.minimum_launcher_version = '3.2.155'
    db.add_all([bridge, source, DeviceInstance(id=uuid4(),device_id=device.id,
        instance_identifier='source156',agent_version='3.2.156',launcher_version='3.2.156',last_seen_at=NOW)])
    await db.flush()
    prep=await request_setup(db,device.id,release.id,'Automatic user sensor start',
        actor='test-admin',request_id='client-upgrade',now=NOW)
    assert prep.status=='preparing_client'
    assert prep.return_build_id==source.id


def build(version, identifier):
    return UpdateBuild(id=uuid4(), build_identifier=identifier, version=version, platform='windows_amd64',
        channel='canary', artifact_identifier=identifier+'.zip', artifact_url='https://endpoint.sosnadmin.local/artifact.zip',
        artifact_name=identifier+'.zip', archive_type='zip', sha256_digest='a'*64, size=100,
        minimum_launcher_version='3.2.156')


async def test_old_agent_preparation_uses_existing_ota_then_real_rollback_then_full_setup(db, state):
    device, release, *_ = state
    await db.execute(delete(SetupClientPresence))
    bridge = build('3.2.163', 'endpoint-windows-core-3.2.163-setup-client')
    baseline = build('3.2.157', 'endpoint-windows-core-3.2.157-setup-source')
    instance = DeviceInstance(id=uuid4(), device_id=device.id, instance_identifier='original',
        agent_version='3.2.158', launcher_version='3.2.158', last_seen_at=NOW)
    db.add_all([bridge, baseline, instance]);await db.flush()
    parent = await request_setup(db, device.id, release.id, 'Full Setup canary', actor='test-admin', request_id='start', now=NOW)
    assert parent.status == 'preparing_client'
    child = await db.scalar(select(UpdateTarget).where(UpdateTarget.rollout_id == parent.bridge_rollout_id))
    assert child.status == 'assigned'
    await advance_preparations(db, now=NOW)
    assert parent.return_rollout_id is None
    child.status = 'applied'
    await record_presence(db, device.id, dict(client_version='1.0.5', ready=True, core_version='3.2.163', foundation_version='3.2.158'), now=NOW)
    await advance_preparations(db, now=NOW)
    assert parent.status == 'restoring_core' and parent.return_rollout_id is not None
    returned = await db.scalar(select(UpdateTarget).where(UpdateTarget.rollout_id == parent.return_rollout_id))
    assert returned.status == 'assigned'
    returned.status = 'applied'
    await record_presence(db, device.id, dict(client_version='1.0.5', ready=True, core_version='3.2.157', foundation_version='3.2.158'), now=NOW)
    await advance_preparations(db, now=NOW)
    assert parent.status == 'completed'
    actual = await db.get(SetupAssignment, parent.assignment_id)
    assert actual.id == parent.id and actual.status == 'assigned' and actual.release_id == release.id
    count = len((await db.scalars(select(UpdateTarget))).all())
    await advance_preparations(db, now=NOW + timedelta(seconds=1))
    assert len((await db.scalars(select(UpdateTarget))).all()) == count


@pytest.mark.parametrize('outcome', ['cancelled', 'failed'])
async def test_preparation_does_not_start_later_stages_after_cancel_or_failed_core(db, state, outcome):
    device, release, *_ = state
    await db.execute(delete(SetupClientPresence))
    bridge = build('3.2.163', 'endpoint-windows-core-3.2.163-setup-client')
    baseline = build('3.2.157', 'endpoint-windows-core-3.2.157-setup-source')
    db.add_all([bridge, baseline, DeviceInstance(id=uuid4(), device_id=device.id,
        instance_identifier='source', agent_version='3.2.158', launcher_version='3.2.158', last_seen_at=NOW)])
    await db.flush()
    prep = await request_setup(db, device.id, release.id, 'Canary test', actor='test-admin', request_id='start', now=NOW)
    child = await db.scalar(select(UpdateTarget).where(UpdateTarget.rollout_id == prep.bridge_rollout_id))
    # Completing a real child does not release the parent preparation's ownership.
    child.status = 'applied'
    await db.flush()
    with pytest.raises(UpdateConflict):
        await create_rollout(db, baseline.id, 'canary', [device.id], 'unrelated', 'test-admin', 'other', now=NOW)
    if outcome == 'cancelled':
        await cancel_preparation(db, prep.id, actor='test-admin', request_id='stop', now=NOW)
    else:
        child.status = 'failed'
    await record_presence(db, device.id, dict(client_version='1.0.5', ready=True, core_version='3.2.163'), now=NOW)
    await advance_preparations(db, now=NOW)
    assert prep.status == ('cancelled' if outcome == 'cancelled' else 'blocked')
    assert prep.assignment_id is None and prep.return_rollout_id is None


async def test_foundation156_uses_frozen_core155_return_before_full_setup(db, state):
    device, release, *_ = state
    await db.execute(delete(SetupClientPresence))
    bridge = build('3.2.163', 'endpoint-windows-core-3.2.163-setup-client')
    compatible = build('3.2.155', 'endpoint-windows-core-3.2.155-setup-source-725739f')
    compatible.minimum_launcher_version = '3.2.155'
    incompatible = build('3.2.157', 'endpoint-windows-core-3.2.157-setup-source')
    incompatible.minimum_launcher_version = '3.2.157'
    db.add_all([bridge, compatible, incompatible, DeviceInstance(id=uuid4(), device_id=device.id,
        instance_identifier='clean156', agent_version='3.2.156', launcher_version='3.2.156', last_seen_at=NOW)])
    await db.flush()
    prep = await request_setup(db, device.id, release.id, 'True Foundation156 update',
        actor='test-admin', request_id='156-start', now=NOW)
    assert prep.return_build_id == compatible.id
    child = await db.scalar(select(UpdateTarget).where(UpdateTarget.rollout_id == prep.bridge_rollout_id))
    child.status = 'applied'
    await record_presence(db, device.id, dict(client_version='1.0.5', ready=True,
        core_version='3.2.163', foundation_version='3.2.156'), now=NOW)
    await advance_preparations(db, now=NOW)
    returned = await db.scalar(select(UpdateTarget).where(UpdateTarget.rollout_id == prep.return_rollout_id))
    assert returned.status == 'assigned'
    returned.status = 'applied'
    await record_presence(db, device.id, dict(client_version='1.0.5', ready=True,
        core_version='3.2.155', foundation_version='3.2.156'), now=NOW)
    await advance_preparations(db, now=NOW)
    assert prep.status == 'completed'
    assert (await db.get(SetupAssignment, prep.assignment_id)).status == 'assigned'


@pytest.mark.parametrize('fault', ['missing', 'incompatible'])
async def test_foundation156_refuses_unavailable_immutable_return(db, state, fault):
    device, release, *_ = state
    await db.execute(delete(SetupClientPresence))
    db.add(build('3.2.163', 'endpoint-windows-core-3.2.163-setup-client'))
    if fault == 'incompatible':
        source = build('3.2.155', 'endpoint-windows-core-3.2.155-setup-source-725739f')
        source.minimum_launcher_version = '3.2.157'
        db.add(source)
    db.add(DeviceInstance(id=uuid4(), device_id=device.id, instance_identifier='clean156',
        agent_version='3.2.156', launcher_version='3.2.156', last_seen_at=NOW))
    await db.flush()
    with pytest.raises(SetupConflict):
        await request_setup(db, device.id, release.id, 'Clean156 test',
            actor='test-admin', request_id='guard', now=NOW)
    assert (await db.scalars(select(UpdateTarget))).all() == []


async def test_missing_foundation_presence_waits_without_aborting_preparation(db, state):
    device, release, *_ = state
    await db.execute(delete(SetupClientPresence))
    db.add_all([build('3.2.163', 'endpoint-windows-core-3.2.163-setup-client'),
        build('3.2.157', 'endpoint-windows-core-3.2.157-setup-source'),
        DeviceInstance(id=uuid4(), device_id=device.id, instance_identifier='source',
            agent_version='3.2.158', launcher_version='3.2.158', last_seen_at=NOW)])
    await db.flush()
    prep = await request_setup(db, device.id, release.id, 'Missing Foundation test',
        actor='test-admin', request_id='missing-foundation', now=NOW)
    child = await db.scalar(select(UpdateTarget).where(UpdateTarget.rollout_id == prep.bridge_rollout_id))
    child.status = 'applied'
    await record_presence(db, device.id, dict(client_version='1.0.5', ready=True,
        core_version='3.2.163', foundation_version=None), now=NOW)
    await advance_preparations(db, now=NOW)
    assert prep.status == 'preparing_client' and prep.return_rollout_id is None

