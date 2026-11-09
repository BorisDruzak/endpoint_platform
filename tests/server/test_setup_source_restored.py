"""Modern preparation cancellation closes the original known21 as FAILED."""
from datetime import timedelta
from uuid import uuid4

import pytest

from endpoint_contracts.setup_updates import SetupProgressV1
from endpoint_server.db.models import WindowsSetupRelease
from endpoint_server.setup_updates.service import SetupConflict, record_progress
from tests.server.test_setup_target_recovery import recovered
from tests.server.test_setup_update_service import db, state


@pytest.fixture
async def source_restored(db, recovered):
    r = recovered
    connection = await db.connection()
    await connection.run_sync(lambda c: WindowsSetupRelease.metadata.create_all(c, tables=[WindowsSetupRelease.__table__]))
    r.job.source_core_version = r.job.source_foundation_version = '3.2.177'
    r.job.source_client_version = '1.0.7'
    r.presence.client_version = '1.0.8'
    r.presence.core_version = r.presence.foundation_version = '3.2.177'
    r.instance.agent_version = r.instance.launcher_version = '3.2.177'
    # Source did not restart: current connection may predate the failed update.
    r.wss.created_at = r.job.started_at - timedelta(hours=1)
    r.release.version = '3.2.185'
    r.catalog = WindowsSetupRelease(id=uuid4(), version='3.2.177', agent_version='3.2.177',
        artifact_identifier='trusted177', filename='Setup177.exe', setup_sha256='1' * 64,
        msi_sha256='2' * 64, source_commit='3' * 40, msi_source_commit='3' * 40,
        authenticode_status='valid', msi_authenticode_status='valid',
        authenticode_publisher='CN=Trusted', msi_authenticode_publisher='CN=Trusted',
        product_code='{77777777-7777-4777-8777-777777777777}')
    db.add(r.catalog)
    raw = r.report.model_dump()
    raw['safe_code'] = 'native_failed_source_restored'
    raw['proof'].update(foundation_version='3.2.177', core_version='3.2.177', source_revision='3' * 40,
        msi_sha256='2' * 64, native_phase='unchanged', source_recovery=dict(
            schema_version='windows_setup_source_recovery_v1', operation_id=str(uuid4()),
            binding_sha256='4' * 64, inputs_sha256='5' * 64, owner_sha256='6' * 64,
            target_version=r.release.version, target_source_revision=r.release.source_revision,
            target_msi_sha256=r.release.msi_sha256, target_setup_sha256=r.release.sha256,
            source_product_code=r.catalog.product_code))
    r.report = SetupProgressV1.model_validate(raw)
    await db.flush()
    return r


async def test_restored_source_settles_original_failed_native21_without_qualifying_target(db, source_restored):
    r = source_restored
    started = r.job.started_at
    await record_progress(db, r.job.device_id, r.job.id, r.report, now=r.when)
    assert r.job.status == 'failed' and r.job.safe_code == 'native_failed_source_restored'
    assert r.job.started_at == started and r.job.last_report['proof']['exit_code'] == 21
    assert r.job.last_report['proof']['source_recovery']['target_version'] == '3.2.185'
    await record_progress(db, r.job.device_id, r.job.id, r.report, now=r.when + timedelta(hours=1))


@pytest.mark.parametrize('fault', ['unknown_hold', 'old_observer', 'stale_observer', 'source_version',
    'catalog_digest', 'catalog_source', 'catalog_unsigned', 'catalog_retired', 'product',
    'target_digest', 'target_setup', 'target_source', 'target_version', 'stale_sensor',
    'prestart_activity', 'wss_expired', 'wss_future', 'no_sensor'])
async def test_restored_source_refuses_unverified_or_unrelated_evidence(db, source_restored, fault):
    r = source_restored
    raw = r.report.model_dump()
    descriptor = raw['proof']['source_recovery']
    if fault == 'unknown_hold': r.job.safe_code = 'setup_outcome_unknown'
    elif fault == 'old_observer': r.presence.client_version = '1.0.7'
    elif fault == 'stale_observer': r.presence.last_seen_at = r.when - timedelta(seconds=91)
    elif fault == 'source_version': r.job.source_core_version = '3.2.176'
    elif fault == 'catalog_digest': r.catalog.msi_sha256 = '0' * 64
    elif fault == 'catalog_source': r.catalog.msi_source_commit = '0' * 40
    elif fault == 'catalog_unsigned': r.catalog.msi_authenticode_status = 'unsigned'
    elif fault == 'catalog_retired': r.catalog.retired_at = r.when
    elif fault == 'product': descriptor['source_product_code'] = '{88888888-8888-4888-8888-888888888888}'
    elif fault == 'target_digest': descriptor['target_msi_sha256'] = '0' * 64
    elif fault == 'target_setup': descriptor['target_setup_sha256'] = '0' * 64
    elif fault == 'target_source': descriptor['target_source_revision'] = '0' * 40
    elif fault == 'target_version': descriptor['target_version'] = '3.2.184'
    elif fault == 'stale_sensor': r.health.user_sensor_last_seen_at = r.when - timedelta(seconds=151)
    elif fault == 'prestart_activity': r.activity.last_observed_at = r.job.started_at
    elif fault == 'wss_expired': r.wss.expires_at = r.when
    elif fault == 'wss_future': r.wss.last_seen_at = r.when + timedelta(seconds=31)
    elif fault == 'no_sensor': raw['proof']['soak']['sensor_count'] = 0
    await db.flush()
    with pytest.raises((SetupConflict, ValueError)):
        await record_progress(db, r.job.device_id, r.job.id, raw, now=r.when)
    assert r.job.status == 'recovery_required' and r.job.finished_at is None
