from datetime import timedelta
from uuid import uuid4

import pytest
from sqlalchemy import select

from endpoint_contracts.setup_updates import SetupProgressV1
from endpoint_server.db.models import UpdateTarget, DeviceInstance, DeviceSession
from endpoint_server.setup_updates.preparation import request_client_recovery, advance_preparations
from endpoint_server.setup_updates.service import record_progress, record_presence, SetupConflict
from endpoint_server.updates.service import create_rollout
from endpoint_server.updates.errors import UpdateConflict
from tests.server.test_setup_update_service import db, state, started, proof, NOW
from tests.server.test_setup_preparation import build


async def live_source(db, device_id):
    await record_presence(db, device_id, dict(client_version='1.0.4', ready=True,
        core_version='3.2.157', foundation_version='3.2.158'), now=NOW)
    instance = DeviceInstance(id=uuid4(),device_id=device_id,instance_identifier='source-recovered',
        agent_version='3.2.157',launcher_version='3.2.158',last_seen_at=NOW)
    db.add(instance);await db.flush()
    db.add(DeviceSession(id=uuid4(),device_id=device_id,device_instance_id=instance.id,
        session_identifier='recovered-wss',expires_at=NOW+timedelta(hours=1),last_seen_at=NOW,created_at=NOW))
    await db.flush()


async def test_recovery_children_preserve_native_hold_and_do_not_replay_setup(db, state):
    job, attempt = await started(db, state)
    await record_progress(db, job.device_id, job.id, SetupProgressV1(attempt_id=attempt,
        phase='recovery_required', safe_code='native_exit_requires_recovery'), now=NOW)
    bridge = build('3.2.162', 'endpoint-windows-core-3.2.162-setup-client')
    source = build('3.2.157', 'endpoint-windows-core-3.2.157-setup-source')
    db.add_all([bridge, source]); await db.flush()
    await record_presence(db, job.device_id, dict(client_version='1.0.3', ready=True, core_version='3.2.157', foundation_version='3.2.158'), now=NOW)
    prep = await request_client_recovery(db, job.id, 'Repair observer after verified native exit',
        actor='test-admin', request_id='recover', now=NOW)
    assert job.status == 'recovery_required' and job.finished_at is None
    assert prep.assignment_id == job.id and prep.status == 'recovering_client'
    with pytest.raises(UpdateConflict):
        await create_rollout(db, source.id, 'canary', [job.device_id], 'unrelated', 'test-admin', 'overlap', now=NOW)
    child = await db.scalar(select(UpdateTarget).where(UpdateTarget.rollout_id == prep.bridge_rollout_id))
    child.status = 'applied'
    await record_presence(db, job.device_id, dict(client_version='1.0.4', ready=True,
        core_version='3.2.162', foundation_version='3.2.158'), now=NOW)
    await advance_preparations(db, now=NOW)
    assert job.status == 'recovery_required' and prep.status == 'recovering_source'
    returned = await db.scalar(select(UpdateTarget).where(UpdateTarget.rollout_id == prep.return_rollout_id))
    await live_source(db, job.device_id)
    recovered = proof()
    recovered.update(core_version='3.2.157', native_phase='unchanged', exit_code=21)
    with pytest.raises(SetupConflict):
        await record_progress(db, job.device_id, job.id, SetupProgressV1(attempt_id=attempt,
            phase='failed', safe_code='native_failed_source_verified', proof=recovered), now=NOW)
    returned.status = 'applied'
    await advance_preparations(db, now=NOW)
    assert prep.status == 'completed' and job.status == 'recovery_required'
    await record_progress(db, job.device_id, job.id, SetupProgressV1(attempt_id=attempt,
        phase='failed', safe_code='native_failed_source_verified', proof=recovered), now=NOW)
    assert job.status == 'failed' and job.last_report['proof']['exit_code'] == 21


async def test_unknown_outcome_cannot_bootstrap_recovery_or_release_hold(db, state):
    job, attempt = await started(db, state)
    await record_progress(db, job.device_id, job.id, SetupProgressV1(attempt_id=attempt,
        phase='recovery_required', safe_code='setup_outcome_unknown'), now=NOW)
    with pytest.raises(SetupConflict):
        await request_client_recovery(db, job.id, 'Unknown process', actor='test-admin', request_id='unsafe', now=NOW)
    with pytest.raises(SetupConflict):
        await record_progress(db, job.device_id, job.id, SetupProgressV1(attempt_id=attempt,
            phase='failed'), now=NOW)
    recovered = proof()
    recovered.update(core_version='3.2.157', native_phase='unchanged', exit_code=21)
    await live_source(db, job.device_id)
    with pytest.raises(SetupConflict):
        await record_progress(db, job.device_id, job.id, SetupProgressV1(attempt_id=attempt,
            phase='failed', safe_code='native_failed_source_verified', proof=recovered), now=NOW)
