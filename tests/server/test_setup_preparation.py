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


def build(version, identifier):
    return UpdateBuild(id=uuid4(), build_identifier=identifier, version=version, platform='windows_amd64',
        channel='canary', artifact_identifier=identifier+'.zip', artifact_url='https://endpoint.sosnadmin.local/artifact.zip',
        artifact_name=identifier+'.zip', archive_type='zip', sha256_digest='a'*64, size=100,
        minimum_launcher_version='3.2.156')


async def test_old_agent_preparation_uses_existing_ota_then_real_rollback_then_full_setup(db, state):
    device, release, *_ = state
    await db.execute(delete(SetupClientPresence))
    bridge = build('3.2.161', 'endpoint-windows-core-3.2.161-setup-client')
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
    await record_presence(db, device.id, dict(client_version='1.0.0', ready=True, core_version='3.2.161', foundation_version='3.2.158'), now=NOW)
    await advance_preparations(db, now=NOW)
    assert parent.status == 'restoring_core' and parent.return_rollout_id is not None
    returned = await db.scalar(select(UpdateTarget).where(UpdateTarget.rollout_id == parent.return_rollout_id))
    assert returned.status == 'assigned'
    returned.status = 'applied'
    await record_presence(db, device.id, dict(client_version='1.0.0', ready=True, core_version='3.2.157', foundation_version='3.2.158'), now=NOW)
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
    bridge = build('3.2.161', 'endpoint-windows-core-3.2.161-setup-client')
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
    await record_presence(db, device.id, dict(client_version='1.0.0', ready=True, core_version='3.2.161'), now=NOW)
    await advance_preparations(db, now=NOW)
    assert prep.status == ('cancelled' if outcome == 'cancelled' else 'blocked')
    assert prep.assignment_id is None and prep.return_rollout_id is None

