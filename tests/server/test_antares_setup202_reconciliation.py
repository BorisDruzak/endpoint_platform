"""An operator can close only the exact, evidenced ANTARES native failure."""
from datetime import timedelta
from uuid import uuid4

import pytest
from sqlalchemy import select

from endpoint_contracts.setup_updates import SetupProgressV1
from endpoint_server.db.models import AuditEvent, DeviceInstance, DeviceSession
from endpoint_server.setup_updates.service import SetupConflict, record_presence, record_progress
from tests.server.test_setup_update_service import NOW, db, state, started


@pytest.fixture
async def reconciliation(db, state, monkeypatch):
    from tools.release import reconcile_antares_setup202 as tool

    job, attempt = await started(db, state)
    await record_progress(db, job.device_id, job.id, SetupProgressV1(
        attempt_id=attempt, phase='recovery_required', safe_code='native_exit_requires_recovery'), now=NOW)
    job.source_foundation_version, job.source_core_version, job.source_client_version = '3.2.193', '3.2.201', '1.0.10'
    release = state[1]
    release.version, release.sha256, release.msi_sha256 = '3.2.202', tool.SETUP_SHA, tool.MSI_SHA
    monkeypatch.setattr(tool, 'ASSIGNMENT', job.id)
    monkeypatch.setattr(tool, 'DEVICE', job.device_id)
    monkeypatch.setattr(tool, 'ATTEMPT', attempt)
    monkeypatch.setattr(tool, 'RELEASE', release.id)
    now = NOW + timedelta(minutes=5)
    await record_presence(db, job.device_id, {
        'client_version': '1.0.10', 'ready': True, 'core_version': '3.2.201', 'foundation_version': '3.2.193',
    }, now=now)
    instance = DeviceInstance(id=uuid4(), device_id=job.device_id, instance_identifier='antares',
        platform='windows_amd64', agent_version='3.2.201', launcher_version='3.2.193', last_seen_at=now)
    db.add(instance)
    await db.flush()
    db.add(DeviceSession(id=uuid4(), device_id=job.device_id, device_instance_id=instance.id,
        session_identifier='fresh-antares', created_at=now - timedelta(seconds=10), last_seen_at=now,
        expires_at=now + timedelta(minutes=10)))
    await db.flush()
    return tool, job, now, {**tool.EXPECTED_HOST_FACTS, 'observed_at': now.isoformat()}


async def test_close_exact_failure_without_rewriting_agent_report(db, reconciliation):
    tool, job, now, evidence = reconciliation
    original = job.last_report.copy()
    for _ in range(2):
        await tool.reconcile(db, evidence, actor='operator', now=now)
    assert job.status == 'failed' and job.safe_code == tool.TERMINAL_CODE
    assert job.last_report == original
    events = (await db.scalars(select(AuditEvent).where(
        AuditEvent.action == 'setup_updates.verified_pre_msi_recovery'))).all()
    assert len(events) == 1 and events[0].details['native_exit'] == 21
    assert events[0].details['previous_safe_code'] == original['safe_code']


@pytest.mark.parametrize('defect', ['archive', 'stale', 'unknown', 'wrong_attempt'])
async def test_refuse_unmatched_recovery_evidence(db, reconciliation, defect):
    tool, job, now, evidence = reconciliation
    if defect == 'archive':
        evidence['archived_stage_sha256'] = '0' * 64
    elif defect == 'stale':
        evidence['observed_at'] = NOW.isoformat()
    elif defect == 'unknown':
        job.safe_code = 'setup_outcome_unknown'
    else:
        job.attempt_id = uuid4()
    await db.flush()
    with pytest.raises(SetupConflict):
        await tool.reconcile(db, evidence, actor='operator', now=now)
    assert job.status == 'recovery_required' and job.finished_at is None
