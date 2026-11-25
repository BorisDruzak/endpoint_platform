"""Default campaign publication is atomic on real isolated PostgreSQL."""
import asyncio
from datetime import UTC, datetime, timedelta
import hashlib
from pathlib import Path
from uuid import uuid4

from alembic import command
import pytest
from sqlalchemy import select, delete

from endpoint_server.db.session import AsyncSessionProvider
from endpoint_server.db.models import EnrollmentCampaign, WindowsSetupRelease, AuditEvent, Device
from endpoint_server.enrollment.default_campaign import include_windows_release, lock_campaign_set
from endpoint_server.setup_updates.models import SetupAssignment, SetupFleetQualification, SetupRelease
from tools.register_windows_setup_release import SetupSidecar, register_release
from tests.server.test_update_postgresql import update_migration_database_urls, _alembic_config


def campaign():
    return EnrollmentCampaign(id=uuid4(),campaign_identifier=uuid4().hex,token_digest=uuid4().hex,
        target_platform='windows',allowed_cidrs=['192.168.101.0/24'],expires_at=datetime.now(UTC)+timedelta(days=30),
        max_uses=100,use_count=3,policy=dict(policy_id='default-windows',enrollment_mode='auto',allowed_installer_releases=['3.2.156']))


def artifact(root, version, *, signed=True):
    file=root/f'EndpointAgentSetup-{version}-x64.exe';file.write_bytes(version.encode())
    metadata=SetupSidecar(schema_version='endpoint_windows_setup_release_v1',version=version,agent_version=version,
        source_commit='a'*40,msi_source_commit='b'*40,filename=file.name,
        setup_sha256=hashlib.sha256(file.read_bytes()).hexdigest(),msi_sha256='c'*64,
        authenticode_status='valid' if signed else 'unsigned',authenticode_publisher='CN=Fixture' if signed else None,
        msi_authenticode_status='valid',msi_authenticode_publisher='CN=Fixture')
    return metadata,file


@pytest.fixture(scope='module')
def publication_url(update_migration_database_urls, preserve_migration_loggers):
    url,_=update_migration_database_urls;command.upgrade(_alembic_config(url),'head');return url


async def fresh_campaign(url):
    p=AsyncSessionProvider(url)
    async with p() as s:
        await s.execute(delete(SetupFleetQualification))
        await s.execute(delete(SetupAssignment))
        await s.execute(delete(SetupRelease))
        await s.execute(delete(WindowsSetupRelease));await s.execute(delete(EnrollmentCampaign))
        c=campaign();s.add(c);await s.commit();ident=c.id
    await p.close();return ident


def test_publication_adds_new_signed_release_and_idempotent_retry(publication_url,tmp_path):
    async def run():
        cid=await fresh_campaign(publication_url);meta,file=artifact(tmp_path,'3.2.200');store=tmp_path/'store';store.mkdir()
        release=await register_release(meta,file,database_url=publication_url,artifact_root=store,default_campaign_id=cid)
        again=await register_release(meta,file,database_url=publication_url,artifact_root=store,default_campaign_id=cid)
        assert again.id==release.id
        p=AsyncSessionProvider(publication_url)
        async with p() as s:
            c=await s.get(EnrollmentCampaign,cid)
            assert c.policy['allowed_installer_releases']==['3.2.156','3.2.200']
            assert (c.use_count,c.max_uses,c.allowed_cidrs)==(3,100,['192.168.101.0/24'])
            events=(await s.scalars(select(AuditEvent).where(AuditEvent.object_identifier==str(cid),AuditEvent.action=='enrollment_campaign.release_included'))).all()
            assert len(events)==1
        await p.close()
    asyncio.run(run())


@pytest.mark.parametrize('fault',['ambiguous','disabled','unsigned','capacity','exhausted','no_expiry'])
def test_invalid_auto_campaign_does_not_commit_release(publication_url,tmp_path,fault):
    async def run():
        cid=await fresh_campaign(publication_url);p=AsyncSessionProvider(publication_url)
        async with p() as s:
            c=await s.get(EnrollmentCampaign,cid)
            if fault=='ambiguous':s.add(campaign())
            elif fault=='disabled':c.disabled_at=datetime.now(UTC)
            elif fault=='exhausted':c.use_count=c.max_uses
            elif fault=='no_expiry':c.expires_at=None
            elif fault=='capacity':c.policy={**c.policy,'allowed_installer_releases':[f'3.2.{i}' for i in range(64)]}
            await s.commit()
        meta,file=artifact(tmp_path,'3.2.200',signed=fault!='unsigned');store=tmp_path/'store';store.mkdir()
        with pytest.raises(ValueError):
            await register_release(meta,file,database_url=publication_url,artifact_root=store,
                default_campaign_id=None if fault=='ambiguous' else cid)
        async with p() as s:
            assert await s.scalar(select(WindowsSetupRelease.id).where(WindowsSetupRelease.version==meta.version)) is None
            c=await s.get(EnrollmentCampaign,cid)
            assert '3.2.200' not in c.policy['allowed_installer_releases']
        await p.close()
    asyncio.run(run())


def test_concurrent_publications_do_not_lose_allowed_versions(publication_url,tmp_path):
    async def run():
        cid=await fresh_campaign(publication_url);store=tmp_path/'store';store.mkdir()
        pairs=[artifact(tmp_path,v) for v in ('3.2.201','3.2.202')]
        await asyncio.gather(*(register_release(m,f,database_url=publication_url,artifact_root=store,default_campaign_id=cid) for m,f in pairs))
        p=AsyncSessionProvider(publication_url)
        async with p() as s:
            c=await s.get(EnrollmentCampaign,cid)
            assert set(c.policy['allowed_installer_releases'])=={'3.2.156','3.2.201','3.2.202'}
        await p.close()
    asyncio.run(run())


def test_publication_waits_for_campaign_creation_transaction(publication_url,tmp_path):
    async def run():
        await fresh_campaign(publication_url)
        meta,file=artifact(tmp_path,'3.2.203');store=tmp_path/'store';store.mkdir()
        p=AsyncSessionProvider(publication_url)
        async with p() as creator:
            await lock_campaign_set(creator)
            creator.add(campaign());await creator.flush()
            task=asyncio.create_task(register_release(meta,file,database_url=publication_url,artifact_root=store))
            await asyncio.sleep(0.1)
            assert not task.done()
            await creator.commit()
            with pytest.raises(ValueError):await task
        async with p() as s:
            assert await s.scalar(select(WindowsSetupRelease.id).where(WindowsSetupRelease.version==meta.version)) is None
        await p.close()
    asyncio.run(run())


def candidate_artifact(root):
    meta, file = artifact(root, '3.2.177')
    return meta.model_copy(update={'product_code': '{12345678-1234-1234-1234-123456789ABC}'}), file


async def qualify_candidate(url, meta, file, *, fault=None):
    now = datetime.now(UTC)
    qualified_at = now - timedelta(days=31 if fault == 'expired' else 0)
    provider = AsyncSessionProvider(url)
    try:
        async with provider() as session:
            device = Device(id=uuid4(), device_identifier=uuid4().hex)
            target = SetupRelease(id=uuid4(), release_identifier=uuid4().hex, version=meta.agent_version,
                artifact_name=meta.filename, sha256='f' * 64 if fault == 'other_digest' else meta.setup_sha256,
                size=file.stat().st_size + (fault == 'wrong_size'), source_revision=meta.msi_source_commit,
                msi_sha256=meta.msi_sha256, tray_sha256='d' * 64, sensor_sha256='e' * 64)
            session.add_all([device, target])
            await session.flush()
            job = SetupAssignment(id=uuid4(), release_id=target.id, device_id=device.id,
                status='recovery_required' if fault == 'recovery_required' else 'applied', reason='Native fixture',
                assigned_at=qualified_at-timedelta(minutes=10), started_at=qualified_at-timedelta(minutes=8),
                finished_at=qualified_at-timedelta(minutes=2), updated_at=qualified_at, attempt_id=uuid4(),
                source_foundation_version='3.2.156')
            session.add(job)
            await session.flush()
            qualification = SetupFleetQualification(id=uuid4(), release_id=target.id, sha256=target.sha256,
                source_foundation=job.source_foundation_version, evidence_assignment_id=job.id,
                qualified_by='fixture', qualified_at=qualified_at, expires_at=qualified_at+timedelta(days=30),
                evidence_code='native0_sensor_source_verified')
            session.add(qualification)
            await session.commit()
            return qualification.id
    finally:
        await provider.close()


async def publication_snapshot(url, cid):
    p = AsyncSessionProvider(url)
    try:
        async with p() as s:
            c = await s.get(EnrollmentCampaign, cid)
            return (c.allowed_cidrs, c.expires_at, c.max_uses, c.use_count,
                    c.token_digest, c.disabled_at, c.revoked_at,
                    {k: v for k, v in c.policy.items() if k != 'allowed_installer_releases'})
    finally:
        await p.close()


def test_promotion_preview_checks_current_provider_without_changing_it(publication_url, tmp_path):
    from tools.register_windows_setup_release import preview_promotion

    async def run():
        cid = await fresh_campaign(publication_url)
        meta, file = candidate_artifact(tmp_path)
        store = tmp_path / 'store'
        store.mkdir()
        target = dict(database_url=publication_url, artifact_root=store, default_campaign_id=cid)
        candidate = await register_release(meta, file, **target, candidate_only=True, include_in_auto_campaign=False)
        qualification = await qualify_candidate(publication_url, meta, file)
        checked = await preview_promotion(meta, **target, qualification_id=qualification)
        assert checked['release_id'] == str(candidate.id)
        assert checked['download_published'] is False
        assert checked['auto_enrollment'] == {'campaign_id': str(cid), 'already_included': False}
        assert datetime.fromisoformat(checked['qualification_expires_at']) > datetime.now(UTC)

        with pytest.raises(ValueError, match='not found'):
            await preview_promotion(meta, **target, qualification_id=uuid4())
        stored = store / file.name
        stored.write_bytes(b'wrong stored artifact')
        with pytest.raises(ValueError, match='Stored Setup artifact differs'):
            await preview_promotion(meta, **target, qualification_id=qualification)
        stored.write_bytes(file.read_bytes())

        provider = AsyncSessionProvider(publication_url)
        try:
            async with provider() as session:
                assert not (await session.get(WindowsSetupRelease, candidate.id)).download_published
                campaign = await session.get(EnrollmentCampaign, cid)
                assert meta.version not in campaign.policy['allowed_installer_releases']
                events = (await session.scalars(select(AuditEvent).where(
                    AuditEvent.object_identifier.in_([str(candidate.id), str(cid)])))).all()
                assert [event.action for event in events] == ['windows_setup_release.registered']
                campaign.disabled_at = datetime.now(UTC)
                await session.commit()
            with pytest.raises(ValueError, match='one active default'):
                await preview_promotion(meta, **target, qualification_id=qualification)
        finally:
            await provider.close()

    asyncio.run(run())


@pytest.mark.parametrize('diagnostic', [False, True])
def test_candidate_promotion_preserves_identity_authority_and_one_way_visibility(publication_url, tmp_path, diagnostic):
    async def run():
        cid = await fresh_campaign(publication_url)
        before = await publication_snapshot(publication_url, cid)
        meta, file = candidate_artifact(tmp_path)
        store = tmp_path / 'store'; store.mkdir()
        args = dict(database_url=publication_url, artifact_root=store, default_campaign_id=cid,
                    include_in_auto_campaign=not diagnostic)
        candidate = await register_release(meta, file, **args, candidate_only=True)
        assert candidate.download_published is False
        again = await register_release(meta, file, **args, candidate_only=True)
        assert again.id == candidate.id and again.download_published is False
        p = AsyncSessionProvider(publication_url)
        async with p() as s:
            c = await s.get(EnrollmentCampaign, cid)
            assert ('3.2.177' in c.policy['allowed_installer_releases']) is (not diagnostic)
        qualification = await qualify_candidate(publication_url, meta, file)
        promoted = await register_release(meta, file, **args, promotion_qualification_id=qualification)
        with pytest.raises(ValueError, match='not found'):
            await register_release(meta, file, **args, promotion_qualification_id=uuid4())
        retried = await register_release(meta, file, **args, candidate_only=True)
        assert promoted.id == retried.id == candidate.id
        assert promoted.created_at == retried.created_at == candidate.created_at
        assert retried.download_published is True
        async with p() as s:
            persisted = await s.get(WindowsSetupRelease, candidate.id)
            assert persisted.download_published is True
            for name, value in meta.model_dump(exclude={'schema_version'}).items():
                assert getattr(persisted, name) == value
            events = (await s.scalars(select(AuditEvent).where(AuditEvent.object_identifier == str(candidate.id)))).all()
            assert sorted(e.action for e in events) == ['windows_setup_release.download_published', 'windows_setup_release.registered']
            event, = [e for e in events if e.action == 'windows_setup_release.download_published']
            assert event.details['qualification_id'] == str(qualification)
        assert await publication_snapshot(publication_url, cid) == before
        assert (store / file.name).read_bytes() == file.read_bytes()
        await p.close()
    asyncio.run(run())


@pytest.mark.parametrize('fault', ['missing', 'ambiguous', 'exhausted'])
def test_failed_campaign_promotion_keeps_candidate_hidden(publication_url, tmp_path, fault):
    async def run():
        cid = await fresh_campaign(publication_url)
        meta, file = candidate_artifact(tmp_path)
        store = tmp_path / 'store'; store.mkdir()
        args = dict(database_url=publication_url, artifact_root=store)
        candidate = await register_release(meta, file, **args, candidate_only=True)
        qualification = await qualify_candidate(publication_url, meta, file)
        p = AsyncSessionProvider(publication_url)
        async with p() as s:
            c = await s.get(EnrollmentCampaign, cid)
            if fault == 'missing': c.disabled_at = datetime.now(UTC)
            elif fault == 'ambiguous': s.add(campaign())
            else: c.use_count = c.max_uses
            await s.commit()
        with pytest.raises(ValueError):
            await register_release(meta, file, **args, promotion_qualification_id=qualification)
        async with p() as s:
            assert (await s.get(WindowsSetupRelease, candidate.id)).download_published is False
            events = (await s.scalars(select(AuditEvent).where(AuditEvent.object_identifier == str(candidate.id)))).all()
            assert [e.action for e in events] == ['windows_setup_release.registered']
        await p.close()
    asyncio.run(run())


@pytest.mark.parametrize('field,value', [
    ('source_commit', 'e' * 40), ('agent_version', '3.2.178'),
    ('setup_sha256', 'e' * 64), ('msi_sha256', 'f' * 64), ('msi_source_commit', 'f' * 40),
    ('product_code', '{00000000-0000-0000-0000-000000000000}'),
    ('filename', 'other.exe'), ('authenticode_status', 'unsigned'),
    ('msi_authenticode_status', 'unsigned'), ('authenticode_publisher', 'CN=Other'),
    ('msi_authenticode_publisher', 'CN=Other'),
])
def test_candidate_promotion_rejects_changed_immutable_metadata(publication_url, tmp_path, field, value):
    async def run():
        await fresh_campaign(publication_url)
        meta, file = candidate_artifact(tmp_path)
        store = tmp_path / 'store'; store.mkdir()
        args = dict(database_url=publication_url, artifact_root=store)
        candidate = await register_release(meta, file, **args, candidate_only=True)
        with pytest.raises(ValueError):
            await register_release(meta.model_copy(update={field: value}), file, **args)
        p = AsyncSessionProvider(publication_url)
        async with p() as s:
            assert (await s.get(WindowsSetupRelease, candidate.id)).download_published is False
        await p.close()
    asyncio.run(run())


def test_concurrent_promotions_emit_one_transition(publication_url, tmp_path):
    async def run():
        await fresh_campaign(publication_url)
        meta, file = candidate_artifact(tmp_path)
        store = tmp_path / 'store'; store.mkdir()
        args = dict(database_url=publication_url, artifact_root=store)
        candidate = await register_release(meta, file, **args, candidate_only=True)
        qualification = await qualify_candidate(publication_url, meta, file)
        results = await asyncio.gather(*(register_release(meta, file, **args, promotion_qualification_id=qualification)
                                         for _ in range(2)))
        assert all(r.id == candidate.id and r.download_published for r in results)
        p = AsyncSessionProvider(publication_url)
        async with p() as s:
            events = (await s.scalars(select(AuditEvent).where(AuditEvent.object_identifier == str(candidate.id),
                AuditEvent.action == 'windows_setup_release.download_published'))).all()
            assert len(events) == 1
        await p.close()
    asyncio.run(run())


@pytest.mark.parametrize('fault,error', [
    ('missing', 'qualification'), ('expired', 'qualification'), ('other_digest', 'qualification'),
    ('unknown_id', 'qualification'), ('recovery_required', 'qualification'), ('wrong_size', 'artifact'),
    ('tampered', 'artifact'), ('missing_candidate', 'existing installer candidate'),
])
def test_exact_qualification_and_stored_artifact_required_before_visibility(publication_url, tmp_path, fault, error):
    async def run():
        cid = await fresh_campaign(publication_url)
        meta, file = candidate_artifact(tmp_path)
        store = tmp_path / 'store'; store.mkdir()
        args = dict(database_url=publication_url, artifact_root=store, default_campaign_id=cid)
        candidate = None
        if fault != 'missing_candidate':
            candidate = await register_release(meta, file, **args, candidate_only=True, include_in_auto_campaign=False)
        qualification = None
        if fault == 'unknown_id':
            qualification = uuid4()
        elif fault != 'missing':
            qualification = await qualify_candidate(publication_url, meta, file, fault=fault)
        if fault == 'tampered':
            (store / file.name).write_bytes(b'replaced bytes')
        with pytest.raises(ValueError, match=error):
            await register_release(meta, file, **args, promotion_qualification_id=qualification)
        provider = AsyncSessionProvider(publication_url)
        try:
            async with provider() as session:
                if candidate is None:
                    assert await session.scalar(select(WindowsSetupRelease.id)) is None
                    assert list(store.iterdir()) == []
                else:
                    assert not (await session.get(WindowsSetupRelease, candidate.id)).download_published
                campaign_row = await session.get(EnrollmentCampaign, cid)
                assert meta.version not in campaign_row.policy['allowed_installer_releases']
        finally:
            await provider.close()
    asyncio.run(run())
