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
from endpoint_server.db.models import EnrollmentCampaign, WindowsSetupRelease, AuditEvent
from endpoint_server.enrollment.default_campaign import include_windows_release, lock_campaign_set
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
def publication_url(update_migration_database_urls):
    url,_=update_migration_database_urls;command.upgrade(_alembic_config(url),'head');return url


async def fresh_campaign(url):
    p=AsyncSessionProvider(url)
    async with p() as s:
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
