"""Close the one verified ANTARES Setup 202 failure from an operator session."""
from datetime import datetime, timedelta
from uuid import UUID

from sqlalchemy import select

from endpoint_contracts.setup_updates import validate_setup_transition
from endpoint_server.audit.service import append_audit_event
from endpoint_server.db.instance_order import latest_instance_order
from endpoint_server.db.models import DeviceInstance, DeviceSession, UpdateTarget
from endpoint_server.setup_updates.models import SetupClientPresence, SetupPreparation, SetupRelease
from endpoint_server.setup_updates.preparation import ACTIVE_PREPARATIONS
from endpoint_server.setup_updates.service import SetupConflict, locked_assignment, now_utc, utc

DEVICE = UUID('15bfeab1-5a29-4c9b-8458-964c4392e732')
ASSIGNMENT = UUID('c6facd92-88f2-40f3-ab4b-79c33015d34d')
ATTEMPT = UUID('0f57adb5-af9b-4861-b1c0-124774ff3742')
RELEASE = UUID('34debe91-6ff8-4e50-a175-27f0b78719ed')
SETUP_SHA = 'cb9044bde74e0d2ed7290edee968d4255cc724a17120dc1c7c645d8490475c1d'
MSI_SHA = 'dadb2c739e3020e98a7b4a773063b5269028bcffb4fa1c26cc034be24ae36ea0'
TERMINAL_CODE = 'native_failed_before_msi_source_restored'
SOURCE = ('3.2.193', '3.2.201', '1.0.10')
EXPECTED_HOST_FACTS = {
    'host': 'ANTARES',
    'operation_id': 'cf85346d-b6af-47f4-bcc3-a815e6aca448',
    'phase': 'rolled-back',
    'safe_code': 'native_not_started_restored',
    'native_exit': 21,
    'source_product_state': 5,
    'target_product_state': -1,
    'native_busy': False,
    'setup_sha256': SETUP_SHA,
    'target_msi_sha256': MSI_SHA,
    'observer_job_sha256': '9b54648a84b871f2ee59f94de89f7750407481e89201f8ce5554697bb23efe98',
    'observer_start_sha256': 'ba06dc4fc07183b6546c4dc8d5cc3ca5863081ca21a04cf6b1040cc14ca26adb',
    'active_pointer_sha256': 'a8bdabbcd03005feed8dc40a0fe48d89d7f0118ac1f60830efcaefd75b8c3f93',
    'signed_recovery_sha256': 'd9381f8d338e978db5c2569dd97a85cd3e8e2dd33a0ca92b1fd98c2ac5d335a7',
    'terminal_stage_sha256': '5f9112249a9213acac722df5129bb233a33303b7d76c6f3d038e1bac78557470',
    'archived_stage_sha256': 'ff2cb4b0da5277dc7f6c7a8b584f33eda51834720c63855e1c401cf0cd8e91ba',
    'archived_fence_sha256': 'f116500ef4fae6e904d0e76e9762db261960961c57fa7a3379e3b57f3d247669',
    'archived_child_sha256': '0b2d258c857753077ffe4f64fddb659bbc1dd619966f2b4d773830e80b90842c',
    'archived_barrier_sha256': '5540988440ec47535cba320ce9ec9b1217c0a81b54ddbc6a8761f420f3fd9341',
    'archived_watchdog_sha256': 'cab81d4a01e9a3061f799f254761ec9237c0fca18fdeed6e72cc3e019f8faf04',
}


def fresh(timestamp, now):
    return timestamp is not None and -timedelta(seconds=30) <= now - utc(timestamp) <= timedelta(seconds=120)


async def reconcile(session, evidence, *, actor, now=None):
    """Accept pinned facts collected over Kerberos by an authorized operator."""
    now = now_utc(now)
    facts = dict(evidence)
    try:
        observed_at = datetime.fromisoformat(facts.pop('observed_at'))
    except (KeyError, TypeError, ValueError) as error:
        raise SetupConflict('fresh ANTARES host observation required') from error
    if (facts != EXPECTED_HOST_FACTS or not actor.strip() or observed_at.tzinfo is None
            or not fresh(observed_at, now)):
        raise SetupConflict('pinned ANTARES recovery evidence required')

    job = await locked_assignment(session, ASSIGNMENT, DEVICE)
    release = await session.get(SetupRelease, RELEASE)
    previous_report = {'attempt_id': str(ATTEMPT), 'phase': 'recovery_required',
                       'safe_code': 'native_exit_requires_recovery', 'proof': None}
    if (job.attempt_id != ATTEMPT or job.release_id != RELEASE or job.started_at is None
            or job.last_report != previous_report
            or (job.source_foundation_version, job.source_core_version, job.source_client_version) != SOURCE
            or release is None or (release.version, release.sha256, release.msi_sha256) != ('3.2.202', SETUP_SHA, MSI_SHA)):
        raise SetupConflict('ANTARES assignment differs from the known native failure')
    if job.status == 'failed' and job.safe_code == TERMINAL_CODE and job.finished_at is not None:
        return job
    if job.status != 'recovery_required' or job.safe_code != previous_report['safe_code'] or job.finished_at is not None:
        raise SetupConflict('known unresolved ANTARES exit required')

    presence = await session.scalar(select(SetupClientPresence).where(SetupClientPresence.device_id == DEVICE))
    instance = await session.scalar(select(DeviceInstance).where(DeviceInstance.device_id == DEVICE)
                                    .order_by(*latest_instance_order()).limit(1))
    connection = await session.scalar(select(DeviceSession).where(
        DeviceSession.device_id == DEVICE, DeviceSession.closed_at.is_(None))
        .order_by(DeviceSession.created_at.desc(), DeviceSession.id.desc()).limit(1))
    if (presence is None or not presence.ready or not fresh(presence.last_seen_at, now)
            or (presence.foundation_version, presence.core_version, presence.client_version) != SOURCE
            or instance is None or instance.platform != 'windows_amd64'
            or (instance.launcher_version, instance.agent_version) != SOURCE[:2]
            or connection is None or connection.device_instance_id != instance.id
            or utc(connection.created_at) <= utc(job.started_at) or utc(connection.expires_at) <= now
            or not fresh(instance.last_seen_at, now) or not fresh(connection.last_seen_at, now)):
        raise SetupConflict('fresh restored ANTARES agent and observer required')
    core_active = await session.scalar(select(UpdateTarget.id).where(UpdateTarget.device_id == DEVICE,
        UpdateTarget.status.in_(('assigned', 'requested', 'scheduled'))))
    prep_active = await session.scalar(select(SetupPreparation.id).where(SetupPreparation.device_id == DEVICE,
        SetupPreparation.status.in_(ACTIVE_PREPARATIONS)))
    if core_active or prep_active:
        raise SetupConflict('another ANTARES operation owns the device')

    validate_setup_transition(job.status, 'failed')
    job.status, job.safe_code = 'failed', TERMINAL_CODE
    job.updated_at = job.finished_at = now
    await append_audit_event(session, actor_kind='operator', actor_identifier=actor,
        action='setup_updates.verified_pre_msi_recovery', object_kind='setup_update_assignment',
        object_identifier=str(job.id), request_id=f'pre-msi-recovery-{ATTEMPT}',
        details={**evidence, 'device_id': str(DEVICE), 'attempt_id': str(ATTEMPT),
                 'previous_safe_code': previous_report['safe_code'], 'status': job.status,
                 'terminal_safe_code': TERMINAL_CODE}, occurred_at=now)
    await session.flush()
    return job
