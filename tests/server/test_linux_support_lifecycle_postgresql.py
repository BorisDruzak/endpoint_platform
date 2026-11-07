"""Real lock/migration gates; only existing loopback disposable-DB fixture."""
import asyncio
from datetime import UTC,datetime,timedelta
import json
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
from alembic import command
from sqlalchemy import select

from endpoint_contracts.linux_installation_lifecycle import LinuxInstallationEventV1
from endpoint_server.db.models import Device,DeviceCredential,EnrollmentCampaign,EnrollmentClaim
from endpoint_server.context.models import ContextCollection,ContextSnapshot,ContextCurrent
from endpoint_server.db.session import AsyncSessionProvider
from endpoint_server.installation_lifecycle.models import InstallationState,InstallationEvent
from endpoint_server.installation_lifecycle.linux_sources import LinuxNativeRelease,resolve_linux_source
from endpoint_server.installation_lifecycle.service import accept_event,InstallationConflict
from endpoint_server.support_access.service import register,SupportConflict
from tests.server.test_update_postgresql import update_migration_database_urls,_alembic_config,_fetch
from tests.server.test_linux_support_lifecycle import registration
from tests.contracts.test_linux_support_lifecycle import native_data,event_data

pytestmark=pytest.mark.usefixtures('preserve_migration_loggers')


async def seed(session,platform='linux'):
    now=datetime.now(UTC)
    device=Device(device_identifier=uuid4().hex);session.add(device);await session.flush()
    credential=DeviceCredential(device_id=device.id,credential_identifier='initial',token_digest=uuid4().hex)
    session.add(credential)
    campaign=EnrollmentCampaign(campaign_identifier=uuid4().hex,token_digest=uuid4().hex,
        max_uses=1,use_count=1,allowed_cidrs=['127.0.0.0/8'],target_platform=platform,policy={})
    session.add(campaign);await session.flush()
    session.add(EnrollmentClaim(campaign_id=campaign.id,claim_identifier=uuid4().hex,claim_digest=uuid4().hex,
        installation_session_digest=uuid4().hex,fingerprint_digest=uuid4().hex,expires_at=now+timedelta(hours=1),
        device_id=device.id,claimed_at=now))
    collection=ContextCollection(device_id=device.id,profile='baseline_v1',requested_by='fixture',idempotency_key=uuid4().hex,
        status='completed',requested_at=now,completed_at=now)
    session.add(collection);await session.flush()
    payload=json.loads(Path('tests/fixtures/context/'+('alt' if platform=='linux' else 'windows')+'/baseline_v1.json').read_text())
    snapshot=ContextSnapshot(collection_id=collection.id,device_id=device.id,profile='baseline_v1',
        collected_at=now,normalized_projection=payload)
    session.add(snapshot);await session.flush()
    session.add(ContextCurrent(device_id=device.id,profile='baseline_v1',snapshot_id=snapshot.id,updated_at=now))
    await session.flush()
    return SimpleNamespace(device=device,credential=credential)


def test_linux_migration_defaults_roundtrip_and_no_silent_authority_loss(update_migration_database_urls):
    url,plain=update_migration_database_urls
    config=_alembic_config(url)
    command.upgrade(config,'0048_installation_lifecycle')
    async def legacy():
        provider=AsyncSessionProvider(url)
        try:
            # Legacy insert intentionally omits every new field.
            from sqlalchemy import text
            async with provider() as session:
                device=Device(device_identifier=uuid4().hex);session.add(device);await session.flush()
                credential=DeviceCredential(device_id=device.id,credential_identifier='initial',token_digest=uuid4().hex)
                session.add(credential);await session.flush()
                from tests.contracts.test_support_access import key
                await session.execute(text('INSERT INTO support_access (id,device_id,source_credential_id,tunnel_public_key,host_public_key,remote_port,component_version,revision,generation,operator_public_keys,installed,tunnel_connected) VALUES (:id,:device,:credential,:tunnel,:host,32000,\'1.0.0\',1,1,\'[]\',false,false)'),
                    {'id':uuid4(),'device':device.id,'credential':credential.id,'tunnel':key(30),'host':key(31)})
                await session.commit()
        finally:
            await provider.close()
    asyncio.run(legacy())
    command.upgrade(config,'head')
    row=asyncio.run(_fetch(plain,'SELECT platform,linux_admin_username,linux_admin_uid FROM support_access'))[0]
    assert tuple(row)==('windows_amd64',None,None)
    command.downgrade(config,'0048_installation_lifecycle')
    command.upgrade(config,'head')
    assert asyncio.run(_fetch(plain,'SELECT platform FROM support_access'))[0]['platform']=='windows_amd64'


def test_linux_and_windows_share_key_role_lock_and_causal_head(update_migration_database_urls):
    url,_=update_migration_database_urls
    command.upgrade(_alembic_config(url),'head')
    async def scenario():
        provider=AsyncSessionProvider(url)
        try:
            async with provider() as session:
                principals=[await seed(session),await seed(session,'windows')]
                # Minimal exact registry fixture is not publication qualification.
                session.add(LinuxNativeRelease(**{k:v for k,v in native_data().items() if k!='exit_code'},
                    signer_fingerprint='A'*40,frozen_manifest_sha256='c'*64,reviewed_by='fixture-review'))
                await session.commit()
            async def enroll(index,principal):
                async with provider() as session:
                    try:
                        from endpoint_contracts.support_access import SupportRegistration
                        from tests.contracts.test_support_access import key
                        body=registration(60) if index==0 else SupportRegistration(tunnel_public_key=key(60),host_public_key=key(61),component_version='1.0.1')
                        row=await register(session,principal.device.id,principal.credential.id,body,
                            platform='linux_amd64' if index==0 else 'windows_amd64')
                        await session.commit();return row
                    except SupportConflict:
                        await session.rollback();return None
            rows=await asyncio.gather(*(enroll(index,p) for index,p in enumerate(principals)))
            assert len([row for row in rows if row])==1
            principal=principals[0]
            first=LinuxInstallationEventV1.model_validate(event_data(device_id=str(principal.device.id)))
            async def send(body):
                async with provider() as session:
                    try:
                        # Production route's DeviceBearer revalidation takes this lock.
                        await session.scalar(select(Device).where(Device.id==principal.device.id).with_for_update())
                        ack=await accept_event(session,principal,body,request_id='pg-fixture',source_resolver=resolve_linux_source)
                        await session.commit();return ack
                    except InstallationConflict:
                        await session.rollback();return None
            results=await asyncio.gather(send(first),send(first.model_copy(update={'event_id':uuid4()})))
            assert len([result for result in results if result])==1
            async with provider() as session:
                projection=await session.scalar(select(InstallationState).where(InstallationState.device_id==principal.device.id))
                assert projection.sequence==1
                assert len((await session.scalars(select(InstallationEvent).where(InstallationEvent.device_id==principal.device.id))).all())==1
        finally:
            await provider.close()
    asyncio.run(scenario())


def test_linux_authority_blocks_destructive_downgrade(update_migration_database_urls):
    url,_=update_migration_database_urls
    config=_alembic_config(url)
    command.upgrade(config,'head')
    async def scenario():
        provider=AsyncSessionProvider(url)
        try:
            async with provider() as session:
                session.add(LinuxNativeRelease(**{**{k:v for k,v in native_data().items() if k!='exit_code'},
                    'version':'3.2.179','core_nevra':'endpoint-agent-core-3.2.179-alt1.x86_64','core_rpm_sha256':'e'*64},
                    signer_fingerprint='A'*40,frozen_manifest_sha256='c'*64,reviewed_by='fixture-review'))
                await session.commit()
        finally:
            await provider.close()
    asyncio.run(scenario())
    with pytest.raises(RuntimeError,match='authority must be preserved'):
        command.downgrade(config,'0048_installation_lifecycle')
