"""Full Setup ownership and server-side acceptance; no installer is simulated as success."""
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from endpoint_contracts.setup_updates import SetupReleaseManifestV1, SetupProgressV1
from endpoint_server.db.models import Device, DeviceInstance, DeviceSession, DeviceCredential, AdminUser, AdminSession, UpdateTarget, UpdateBuild, UpdateRollout, AuditEvent
from endpoint_server.setup_updates.models import SetupRelease, SetupAssignment, SetupClientPresence, SetupPreparation, SetupFleetPolicy, SetupFleetDecision, SetupFleetQualification
from endpoint_server.setup_updates.service import register_release, assign_setup, cancel_assignment, record_progress, record_presence, SetupConflict

NOW = datetime(2026, 11, 3, tzinfo=UTC)


@pytest_asyncio.fixture
async def db(tmp_path):
    engine = create_async_engine('sqlite+aiosqlite:///:memory:')
    tables = [Device.metadata.tables["installation_states"], Device.__table__, DeviceInstance.__table__, DeviceSession.__table__, DeviceCredential.__table__,
              UpdateBuild.__table__, UpdateRollout.__table__, UpdateTarget.__table__,
              AuditEvent.__table__, SetupRelease.__table__, SetupAssignment.__table__, SetupClientPresence.__table__, SetupPreparation.__table__,
              SetupFleetPolicy.__table__, SetupFleetDecision.__table__, SetupFleetQualification.__table__]
    async with engine.begin() as conn:
        await conn.run_sync(lambda c: Device.metadata.create_all(c, tables=tables))
        # Core's production-only partial index has no SQLite predicate.
        await conn.execute(text('DROP INDEX uq_update_targets_active_device'))
        await conn.execute(text("CREATE UNIQUE INDEX uq_update_targets_active_device ON update_targets(device_id) WHERE status IN ('assigned','requested','scheduled')"))
    async with async_sessionmaker(engine, expire_on_commit=False)() as session:
        yield session
    await engine.dispose()


@pytest_asyncio.fixture
async def state(db, tmp_path):
    device = Device(id=uuid4(), device_identifier='setup-test-device')
    db.add(device)
    await db.flush()
    artifact = tmp_path / 'Setup.exe'
    artifact.write_bytes(b'published immutable full Setup fixture')
    import hashlib
    manifest = SetupReleaseManifestV1(schema_version='windows_setup_release_v1',
        release_identifier='test-setup158', version='3.2.158', artifact_name=artifact.name,
        sha256=hashlib.sha256(artifact.read_bytes()).hexdigest(), size=artifact.stat().st_size,
        source_revision='b' * 40, msi_sha256='c' * 64, tray_sha256='d' * 64, sensor_sha256='e' * 64)
    release = await register_release(db, manifest, artifact_root=tmp_path, actor='test-admin', request_id='register')
    await record_presence(db, device.id, {'client_version': '1.0.4', 'ready': True,
                                       'foundation_version': '3.2.156', 'core_version': '3.2.156'}, now=NOW)
    return device, release, manifest, tmp_path


async def assignment(db, state):
    device, release, *_ = state
    return await assign_setup(db, device.id, release.id, 'Authorized single-device canary',
                              actor='test-admin', request_id='assign', now=NOW)


def progress(phase, attempt_id, proof=None):
    return SetupProgressV1(attempt_id=attempt_id, phase=phase, proof=proof)


async def started(db, state):
    job = await assignment(db, state)
    attempt = uuid4()
    for phase in ['downloading', 'verified', 'installing']:
        await record_progress(db, job.device_id, job.id, progress(phase, attempt), now=NOW)
    return job, attempt


def proof():
    return dict(foundation_version='3.2.158', core_version='3.2.158', source_revision='b' * 40,
                msi_sha256='c' * 64, native_phase='accepted', exit_code=0,
                native_verified=True, core_verified=True, provenance_verified=True,
                pending=False, services_verified=True, companions_restored=True,
                private=dict(credential=True, identity=True, origin=True, ca=True),
                soak=dict(duration_seconds=180, samples=6, sensor_count=1, sensor_cpu_percent_max=0,
                          services_stable=True, companions_stable=True, connected=True))


async def test_setup_registration_rechecks_actual_bytes_and_immutable_replay(db, state):
    _, first, manifest, root = state
    again = await register_release(db, manifest, artifact_root=root, actor='test-admin', request_id='replay')
    assert again.id == first.id
    (root / manifest.artifact_name).write_bytes(b'substituted')
    with pytest.raises(SetupConflict):
        await register_release(db, manifest, artifact_root=root, actor='test-admin', request_id='substituted')


async def test_client_readiness_is_required_and_one_active_assignment(db, state):
    job = await assignment(db, state)
    assert job.status == 'assigned'
    with pytest.raises(SetupConflict):
        await assignment(db, state)


@pytest.mark.parametrize('client_version', ['1.0.6', '1.0.7', '1.0.8'])
async def test_qualified_executor_accepts_setup_and_native_start(db, state, client_version):
    device, *_ = state
    await record_presence(db, device.id, dict(client_version=client_version, ready=True,
        foundation_version='3.2.156', core_version='3.2.156'), now=NOW)
    job, _ = await started(db, state)
    assert job.status == 'installing' and job.source_client_version == client_version


@pytest.mark.parametrize('client_version', ['1.0.1', '1.0.9'])
async def test_unqualified_executor_cannot_accept_setup_even_with_fresh_ready_presence(db, state, client_version):
    device, *_ = state
    await record_presence(db, device.id, dict(client_version=client_version, ready=True, core_version='3.2.157'), now=NOW)
    with pytest.raises(SetupConflict):
        await assignment(db, state)


async def test_unknown_native_outcome_keeps_device_exclusive_and_cannot_be_cancelled(db, state):
    job, attempt = await started(db, state)
    await record_progress(db, job.device_id, job.id,
        SetupProgressV1(attempt_id=attempt, phase='recovery_required', safe_code='native_outcome_unknown'), now=NOW)
    assert job.finished_at is None
    with pytest.raises(SetupConflict):
        await cancel_assignment(db, job.id, actor='test-admin', request_id='unsafe-cancel', now=NOW)
    with pytest.raises(SetupConflict):
        await assignment(db, state)
    from endpoint_server.updates.service import create_rollout
    from endpoint_server.updates.errors import UpdateConflict
    core=UpdateBuild(id=uuid4(),build_identifier='hold-guard-core',version='3.2.170',platform='windows_amd64',
        channel='canary',artifact_identifier='hold.zip',artifact_url='https://endpoint.sosnadmin.local/hold.zip',
        artifact_name='hold.zip',archive_type='zip',sha256_digest='a'*64,size=10)
    db.add(core);await db.flush()
    with pytest.raises(UpdateConflict):
        await create_rollout(db,core.id,'canary',[job.device_id],'competing Core','test-admin','overlap',now=NOW)


async def test_stale_client_cannot_authorize_a_new_setup(db, state):
    device, release, *_ = state
    with pytest.raises(SetupConflict):
        await assign_setup(db, device.id, release.id, 'test', actor='test-admin', request_id='stale', now=NOW + timedelta(hours=1))


async def test_no_cancel_after_native_start_acknowledgement(db, state):
    job, _ = await started(db, state)
    with pytest.raises(SetupConflict):
        await cancel_assignment(db, job.id, actor='test-admin', request_id='cancel', now=NOW)
    assert job.status == 'installing'


async def test_cancelled_assignment_cannot_start_even_with_previously_downloaded_bytes(db, state):
    job = await assignment(db, state)
    attempt = uuid4()
    for phase in ['downloading', 'verified']:
        await record_progress(db, job.device_id, job.id, progress(phase, attempt), now=NOW)
    await cancel_assignment(db, job.id, actor='test-admin', request_id='cancel', now=NOW)
    with pytest.raises(SetupConflict):
        await record_progress(db, job.device_id, job.id, progress('installing', attempt), now=NOW)


async def test_progress_is_bound_to_one_device_and_attempt(db, state):
    job, attempt = await started(db, state)
    for wrong_device, wrong_attempt in [(uuid4(), attempt), (job.device_id, uuid4())]:
        with pytest.raises(SetupConflict):
            await record_progress(db, wrong_device, job.id, progress('verifying', wrong_attempt), now=NOW)


async def test_native_proof_without_new_wss_is_not_success(db, state):
    job, attempt = await started(db, state)
    await record_progress(db, job.device_id, job.id, progress('verifying', attempt), now=NOW)
    with pytest.raises(SetupConflict):
        await record_progress(db, job.device_id, job.id, progress('applied', attempt, proof()), now=NOW)
    assert job.status == 'verifying'


async def test_only_matching_native_proof_and_fresh_new_session_complete_assignment(db, state):
    job, attempt = await started(db, state)
    instance = DeviceInstance(id=uuid4(), device_id=job.device_id, instance_identifier='after-setup',
        agent_version='3.2.158', launcher_version='3.2.158', last_seen_at=NOW + timedelta(seconds=10))
    db.add(instance)
    await db.flush()
    db.add(DeviceSession(id=uuid4(), device_id=job.device_id, device_instance_id=instance.id,
        session_identifier='session-' + uuid4().hex, expires_at=NOW + timedelta(hours=1),
        created_at=NOW + timedelta(seconds=5), last_seen_at=NOW + timedelta(seconds=10), source_address='192.0.2.10'))
    await db.flush()
    await record_progress(db, job.device_id, job.id, progress('verifying', attempt), now=NOW)
    bad = {**proof(), 'msi_sha256': 'f' * 64}
    with pytest.raises(SetupConflict):
        await record_progress(db, job.device_id, job.id, progress('applied', attempt, bad), now=NOW + timedelta(seconds=10))
    report = progress('applied', attempt, proof())
    first = await record_progress(db, job.device_id, job.id, report, now=NOW + timedelta(seconds=10))
    again = await record_progress(db, job.device_id, job.id, report, now=NOW + timedelta(seconds=11))
    assert first.id == again.id and again.status == 'applied'
    assert len((await db.scalars(select(AuditEvent).where(AuditEvent.action == 'setup_updates.applied'))).all()) == 1


async def test_active_progress_can_advance_native_stage_without_renewing_start(db, state):
    job, attempt = await started(db, state)
    original_started = job.started_at
    stage = SetupProgressV1(attempt_id=attempt, phase='installing', safe_code='native_trial')
    await record_progress(db, job.device_id, job.id, stage, now=NOW + timedelta(seconds=30))
    again = await record_progress(db, job.device_id, job.id, stage, now=NOW + timedelta(seconds=31))
    assert again.safe_code == 'native_trial' and again.started_at.replace(tzinfo=UTC) == original_started
