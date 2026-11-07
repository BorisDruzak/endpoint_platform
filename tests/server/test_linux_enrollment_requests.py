"""Source-qualified Linux enrollment: real public builders and PostgreSQL flow."""
import asyncio
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address, ip_network
from uuid import UUID, uuid4
import secrets

import pytest
from alembic import command
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from endpoint_server.db.session import AsyncSessionProvider
from endpoint_server.enrollment.campaigns import issue_campaign, hardware_fingerprint_digest
from endpoint_server.main import create_app
from tests.server.test_update_postgresql import update_migration_database_urls, _alembic_config
from tests.server.test_enrollment_request_api import _settings, PEPPER
from tests.contracts.test_linux_support_lifecycle import native_data, event_data
from tests.server.test_linux_support_lifecycle import registration

pytestmark = pytest.mark.usefixtures('preserve_migration_loggers')


def source_data():
    return {key: value for key, value in native_data().items() if key != 'exit_code'}


def body():
    return dict(schema_version='linux_pre_enrollment_request_create_v1', platform='linux',
        installation_id='linux-' + uuid4().hex, hardware_fingerprint='sha256:canonical-linux-hardware',
        request_capability=secrets.token_urlsafe(32), native=source_data(), requested_at=datetime.now(UTC).isoformat(),
        hostname='linux-fixture', macs=[])


def test_linux_selection_and_same_domain_digest_builders():
    from endpoint_contracts.linux_enrollment import LinuxPreEnrollmentRequestCreateV1
    from endpoint_server.enrollment.linux_requests import select_linux_campaign, build_linux_request
    now = datetime.now(UTC)
    source_id = uuid4()
    campaign = issue_campaign(PEPPER, expires_at=now+timedelta(hours=1), max_uses=2,
        allowed_cidrs=['127.0.0.0/8'], target_platform='linux', policy={
            'policy_id':'linux-fixture', 'enrollment_mode':'auto', 'allowed_native_releases':[str(source_id)]}, now=now).record
    selection = select_linux_campaign([campaign], source_id=source_id, source_address=ip_address('127.0.0.1'), now=now)
    assert selection.status == 'auto_approved'
    from pc_agent.enrollment_bootstrap import _derive_hardware_fingerprint
    hardware = _derive_hardware_fingerprint(lambda: {'product_uuid':'fixture-native-machine','macs':['aabbccddeeff']})
    request, binding = build_linux_request(LinuxPreEnrollmentRequestCreateV1.model_validate({**body(),'hardware_fingerprint':hardware}),
        source_id=source_id, selection=selection, source_address=ip_address('127.0.0.1'), pepper=PEPPER, now=now)
    assert request.platform == 'linux'
    assert binding.claim_fingerprint_digest == hardware_fingerprint_digest(hardware, PEPPER)
    assert binding.claim_fingerprint_digest != request.fingerprint_digest
    campaign.target_platform = 'windows'
    assert select_linux_campaign([campaign], source_id=source_id, source_address=ip_address('127.0.0.1'), now=now).campaign is None


@pytest.mark.parametrize('change', [
    {'platform':'windows'}, {'native':{**source_data(),'exit_code':0}},
    {'native':{**source_data(),'core_nevra':'agent-3.2.178-alt1.aarch64'}},
    {'campaign_id':str(uuid4())}, {'request_capability':'unsafe value'},
])
def test_linux_request_rejects_platform_native_outcome_and_campaign_invention(change):
    from pydantic import ValidationError
    from endpoint_contracts.linux_enrollment import LinuxPreEnrollmentRequestCreateV1
    with pytest.raises(ValidationError):
        LinuxPreEnrollmentRequestCreateV1.model_validate({**body(),**change})


@pytest.mark.parametrize('change', ['expired','revoked','disabled','budget','network','source','ambiguous'])
def test_linux_campaign_selection_revalidates_authority(change):
    from endpoint_server.enrollment.linux_requests import select_linux_campaign
    now = datetime.now(UTC)
    source_id = uuid4()
    campaign = issue_campaign(PEPPER, expires_at=now+timedelta(hours=1), max_uses=2,
        allowed_cidrs=['127.0.0.0/8'], target_platform='linux', policy={
            'policy_id':'linux-fixture', 'enrollment_mode':'auto', 'allowed_native_releases':[str(source_id)]}, now=now).record
    campaigns = [campaign]
    if change == 'expired': campaign.expires_at = now
    if change == 'revoked': campaign.revoked_at = now
    if change == 'disabled': campaign.disabled_at = now
    if change == 'budget': campaign.use_count = 2
    if change == 'network': campaign.allowed_cidrs = ['192.0.2.0/24']
    if change == 'source': source_id = uuid4()
    if change == 'ambiguous': campaigns.append(campaign)
    selected = select_linux_campaign(campaigns, source_id=source_id, source_address=ip_address('127.0.0.1'), now=now)
    assert selected.campaign is None and selected.status == 'review_required'


def test_fresh_linux_bootstraps_before_core_and_recovery_is_same_identity(update_migration_database_urls):
    url, _ = update_migration_database_urls
    command.upgrade(_alembic_config(url), 'head')
    async def scenario():
        from endpoint_server.installation_lifecycle.linux_sources import LinuxNativeRelease
        from endpoint_server.support_access.platforms import verified_platform
        from endpoint_server.db.models import EnrollmentClaim, DeviceCredential
        from endpoint_server.enrollment.linux_requests import LinuxEnrollmentBinding
        provider = AsyncSessionProvider(url)
        try:
            async with provider() as session:
                source = LinuxNativeRelease(**source_data(), signer_fingerprint='A'*40,
                    frozen_manifest_sha256='c'*64, reviewed_by='fixture-review')
                session.add(source)
                await session.flush()
                campaign = issue_campaign(PEPPER, expires_at=datetime.now(UTC)+timedelta(hours=1),
                    max_uses=2, allowed_cidrs=['127.0.0.0/8'], target_platform='linux', policy={
                        'policy_id':'linux-fixture', 'enrollment_mode':'auto', 'allowed_native_releases':[str(source.id)]}).record
                session.add(campaign)
                await session.commit()
            app = create_app(replace(_settings(), database_url=url, allowed_agent_cidrs=(ip_network('127.0.0.0/8'),)), session_provider=provider)
            async with AsyncClient(transport=ASGITransport(app=app), base_url='https://endpoint.sosnadmin.local') as client:
                payload = body()
                created = await asyncio.gather(*(client.post('/api/v1/enrollment/linux/requests', json=payload) for _ in range(2)))
                assert sorted(item.status_code for item in created) == [200, 201]
                assert created[0].json()['request_id'] == created[1].json()['request_id']
                response = created[0]
                request_id = response.json()['request_id']
                assert response.json()['status'] == 'auto_approved'
                proof = {k:payload[k] for k in ('request_capability','installation_id','hardware_fingerprint')}
                claims = await asyncio.gather(*(client.post(f'/api/v1/enrollment/linux/requests/{request_id}/claim', json=proof) for _ in range(2)))
                assert all(item.status_code == 200 for item in claims), [item.text for item in claims]
                assert claims[0].json() == claims[1].json()
                response = claims[0]
                claim = response.json()['claim']
                again = await client.post(f'/api/v1/enrollment/linux/requests/{request_id}/claim', json=proof)
                assert again.json()['claim'] == claim
                enrollment = dict(schema_version='agent_enrollment_request_v1', platform='linux',
                    installation_id=payload['installation_id'], hardware_fingerprint=payload['hardware_fingerprint'],
                    delivery_nonce='b'*43, requested_at=payload['requested_at'])
                enrolled = await asyncio.gather(*(client.post('/agent/v1/enroll', headers={'Authorization':f'Bearer {claim}'}, json=enrollment) for _ in range(2)))
                assert sorted(item.status_code for item in enrolled) == [200, 201], [item.text for item in enrolled]
                response = enrolled[0]
                delivery = response.json()
                retry = await client.post('/agent/v1/enroll', headers={'Authorization':f'Bearer {claim}'}, json=enrollment)
                assert retry.status_code == 200 and retry.json() == delivery
                token_headers = {'Authorization':f"Bearer {delivery['device_token']}"}
                response = await client.post('/agent/v1/support-access/linux/register', headers=token_headers,
                    json=registration().model_dump(mode='json'))
                assert response.status_code == 200, response.text
                response = await client.post('/agent/v1/installation/linux/events', headers=token_headers,
                    json=event_data(device_id=delivery['device_id']))
                assert response.status_code == 200, response.text
                async with provider() as session:
                    from endpoint_server.db.models import EnrollmentRequest
                    persisted = await session.get(EnrollmentRequest,UUID(request_id))
                    persisted.expires_at = datetime.now(UTC)-timedelta(seconds=1)
                    await session.commit()
                status_result = await client.post(f'/api/v1/enrollment/linux/requests/{request_id}/status',
                    json={'request_capability':payload['request_capability']})
                assert status_result.json()['status']=='device_registered'
                # An obsolete handoff poll cannot revoke an enrolled bootstrap.
                assert (await client.post(f'/api/v1/enrollment/linux/requests/{request_id}/claim',json=proof)).status_code==410
                status_result = await client.post(f'/api/v1/enrollment/linux/requests/{request_id}/status',
                    json={'request_capability':payload['request_capability']})
                assert status_result.json()['status']=='device_registered'
                async with provider() as session:
                    binding = await session.scalar(select(LinuxEnrollmentBinding).where(LinuxEnrollmentBinding.enrollment_request_id==UUID(request_id)))
                    claim_row = await session.get(EnrollmentClaim, binding.claim_id)
                    credential = await session.get(DeviceCredential, binding.credential_id)
                    device_id = UUID(delivery['device_id'])
                    assert claim_row.device_id == credential.device_id == device_id
                    assert claim_row.claimed_at is not None
                    assert await verified_platform(session, device_id) == 'linux_amd64'
                    assert await verified_platform(session, device_id, credential_id=uuid4()) is None
                    assert await verified_platform(session, uuid4()) is None
                    from endpoint_contracts.linux_installation_lifecycle import LinuxNativeSource
                    wrong = LinuxNativeSource(**{**source_data(), 'source_revision':'f'*40})
                    assert await verified_platform(session, device_id, native_source=wrong) is None
                    # A genuine binding cannot override contradictory or malformed
                    # canonical context, including a mismatched current pointer.
                    from endpoint_server.context.models import ContextCollection, ContextSnapshot, ContextCurrent
                    collection = ContextCollection(device_id=device_id, profile='baseline_v1', requested_by='fixture',
                        idempotency_key=uuid4().hex, status='completed', requested_at=datetime.now(UTC), completed_at=datetime.now(UTC))
                    session.add(collection)
                    await session.flush()
                    import json
                    from pathlib import Path
                    baseline = json.loads(Path('tests/fixtures/context/alt/baseline_v1.json').read_text())
                    snapshot = ContextSnapshot(collection_id=collection.id,device_id=device_id, profile='baseline_v1',
                        collected_at=datetime.now(UTC), normalized_projection=baseline)
                    session.add(snapshot)
                    await session.flush()
                    current = ContextCurrent(device_id=device_id,profile='baseline_v1',snapshot_id=snapshot.id,updated_at=datetime.now(UTC))
                    session.add(current)
                    await session.flush()
                    import copy
                    for platform, architecture in [('windows','x86_64'),('linux','aarch64')]:
                        bad = copy.deepcopy(baseline)
                        bad['sections']['system']['platform'] = platform
                        bad['sections']['system']['architecture'] = architecture
                        snapshot.normalized_projection = bad
                        await session.flush()
                        assert await verified_platform(session,device_id) is None
                    snapshot.normalized_projection = {}
                    await session.flush()
                    assert await verified_platform(session,device_id) is None
                    # Production composite FK itself prevents a dangling pointer.
                    from sqlalchemy.exc import IntegrityError
                    with pytest.raises(IntegrityError):
                        async with session.begin_nested():
                            snapshot.profile = 'inventory_v1'
                            await session.flush()
                    await session.delete(current)
                    await session.flush()
                    assert await verified_platform(session,device_id) == 'linux_amd64'
                    binding.claim_id = None
                    binding.credential_id = None
                    await session.flush()
                    assert await verified_platform(session, device_id) is None
        finally:
            await provider.close()
    asyncio.run(scenario())


def test_issued_linux_claim_revalidates_retired_source_without_consuming_authority(update_migration_database_urls):
    url, _ = update_migration_database_urls
    command.upgrade(_alembic_config(url), 'head')
    async def scenario():
        from endpoint_server.installation_lifecycle.linux_sources import LinuxNativeRelease
        from endpoint_server.db.models import EnrollmentCampaign, EnrollmentClaim, EnrollmentRequest
        provider = AsyncSessionProvider(url)
        try:
            native = {**source_data(), 'version':'3.2.179','core_nevra':'endpoint-agent-core-3.2.179-alt1.x86_64','core_rpm_sha256':'e'*64}
            async with provider() as session:
                source = LinuxNativeRelease(**native, signer_fingerprint='A'*40, frozen_manifest_sha256='c'*64,reviewed_by='fixture')
                session.add(source)
                await session.flush()
                campaign = issue_campaign(PEPPER, expires_at=datetime.now(UTC)+timedelta(hours=1), max_uses=1,
                    allowed_cidrs=['127.0.0.0/8'], target_platform='linux', policy={
                        'policy_id':'linux-retirement','enrollment_mode':'auto','allowed_native_releases':[str(source.id)]}).record
                session.add(campaign)
                await session.commit()
                sid, cid = source.id, campaign.id
            app = create_app(replace(_settings(),database_url=url,allowed_agent_cidrs=(ip_network('127.0.0.0/8'),)),session_provider=provider)
            async with AsyncClient(transport=ASGITransport(app=app),base_url='https://endpoint.sosnadmin.local') as client:
                payload = {**body(), 'native':native,'hardware_fingerprint':'sha256:other-native-machine'}
                response = await client.post('/api/v1/enrollment/linux/requests',json=payload)
                assert response.status_code == 201 and response.json()['status']=='auto_approved',response.text
                rid = response.json()['request_id']
                path = f'/api/v1/enrollment/linux/requests/{rid}'
                assert (await client.post(path+'/status',json={'request_capability':'z'*43})).status_code == 404
                proof = {key:payload[key] for key in ('request_capability','installation_id','hardware_fingerprint')}
                response = await client.post(path+'/claim',json=proof)
                assert response.status_code == 200,response.text
                claim = response.json()['claim']
                async with provider() as session:
                    source = await session.get(LinuxNativeRelease,sid)
                    source.retired_at = datetime.now(UTC)
                    await session.commit()
                assert (await client.post(path+'/claim',json=proof)).status_code == 409
                enrollment = dict(schema_version='agent_enrollment_request_v1',platform='linux',installation_id=payload['installation_id'],
                    hardware_fingerprint=payload['hardware_fingerprint'],requested_at=payload['requested_at'],delivery_nonce='b'*43)
                assert (await client.post('/agent/v1/enroll',headers={'Authorization':f'Bearer {claim}'},json=enrollment)).status_code == 403
                async with provider() as session:
                    consumed = await session.scalar(select(EnrollmentClaim).where(EnrollmentClaim.enrollment_request_id==UUID(rid)))
                    assert consumed.claimed_at is None and consumed.device_id is None
                    assert (await session.get(EnrollmentCampaign,cid)).use_count == 0
                    assert (await session.get(EnrollmentRequest,UUID(rid))).status == 'claim_issued'
        finally:
            await provider.close()
    asyncio.run(scenario())


def test_historical_linux156_without_request_fk_requires_exact_claim_and_admin(update_migration_database_urls):
    url, _ = update_migration_database_urls
    command.upgrade(_alembic_config(url), 'head')
    async def scenario():
        from endpoint_contracts.linux_enrollment import LinuxPreEnrollmentRequestCreateV1
        from endpoint_contracts.linux_installation_lifecycle import LinuxInstallationEventV1
        from endpoint_server.auth.admin_sessions import ADMIN_SESSION_COOKIE, issue_admin_session
        from endpoint_server.db.models import AdminUser, EnrollmentClaim, EnrollmentRequest, Device
        from endpoint_server.enrollment.campaigns import issue_install_claim
        from endpoint_server.enrollment.linux_requests import build_linux_request
        from endpoint_server.enrollment.requests import CampaignSelection
        from endpoint_server.installation_lifecycle.linux_sources import LinuxNativeRelease, resolve_linux_source
        from endpoint_server.installation_lifecycle.models import InstallationParent
        from endpoint_server.installation_lifecycle.service import accept_event
        from tests.server.test_linux_support_lifecycle_postgresql import seed
        provider = AsyncSessionProvider(url)
        settings = replace(_settings(), database_url=url)
        try:
            async with provider() as session:
                principal = await seed(session)
                previous = principal.device.id
                now = datetime.now(UTC)
                source = await session.scalar(select(LinuxNativeRelease).where(LinuxNativeRelease.version==source_data()['version']))
                if source is None:
                    source = LinuxNativeRelease(**source_data(), signer_fingerprint='A'*40, frozen_manifest_sha256='c'*64, reviewed_by='fixture-review')
                    session.add(source)
                    await session.flush()
                campaign = issue_campaign(PEPPER, expires_at=now+timedelta(hours=1), max_uses=10,
                    allowed_cidrs=['127.0.0.0/8'], target_platform='linux', policy={
                        'policy_id':'linux-history', 'enrollment_mode':'manual', 'allowed_native_releases':[str(source.id)]}).record
                session.add(campaign)
                await session.flush()
                from pc_agent.enrollment_bootstrap import _derive_hardware_fingerprint
                payload = LinuxPreEnrollmentRequestCreateV1.model_validate({**body(), 'hardware_fingerprint':
                    _derive_hardware_fingerprint(lambda: {'product_uuid':'fixture-legacy156','macs':['aabbccddeeff']})})
                record, binding = build_linux_request(payload, source_id=source.id, source_address=ip_address('127.0.0.1'),
                    selection=CampaignSelection('waiting_approval',campaign,'MANUAL_POLICY'), pepper=PEPPER, now=now)
                session.add(record)
                await session.flush()
                session.add(binding)
                old_claim = issue_install_claim(campaign, PEPPER, installation_session='legacy156',
                    hardware_fingerprint=payload.hardware_fingerprint, expires_at=now+timedelta(hours=1), now=now).record
                old_claim.device_id = previous
                old_claim.claimed_at = now
                session.add(old_claim)
                admin = AdminUser(username=uuid4().hex, password_digest='fixture-only', scopes=[])
                session.add(admin)
                await session.flush()
                issued = issue_admin_session(admin.id, settings.session_secret)
                session.add(issued.record)
                installed = LinuxInstallationEventV1.model_validate(event_data(device_id=str(previous)))
                await accept_event(session,principal,installed,request_id='test',source_resolver=resolve_linux_source)
                await session.commit()
                rid, cid = record.id, old_claim.id
            app = create_app(settings, session_provider=provider)
            async with AsyncClient(transport=ASGITransport(app=app), base_url=settings.public_base_url) as client:
                client.cookies.set(ADMIN_SESSION_COOKIE, issued.token)
                path = f'/api/admin/enrollment/requests/{rid}/approve'
                headers = {'X-CSRF-Token':issued.csrf_token}
                proof = {'previous_device_id':str(previous)}
                assert (await client.post(path,json=proof)).status_code == 403
                assert (await client.post(path,json=proof,headers=headers)).status_code == 409
                async with provider() as session:
                    removed = installed.model_copy(update={'event_id':uuid4(),'sequence':2,'previous_event_id':installed.event_id,'action':'removed'})
                    await accept_event(session,principal,removed,request_id='test',source_resolver=resolve_linux_source)
                    await session.commit()
                for failure in ('hardware','unconsumed','wrong_device','retired'):
                    async with provider() as session:
                        old = await session.get(EnrollmentClaim,cid)
                        old.fingerprint_digest = hardware_fingerprint_digest('sha256:other-hardware' if failure=='hardware' else payload.hardware_fingerprint, PEPPER)
                        old.claimed_at = None if failure=='unconsumed' else now
                        old.device_id = None if failure=='wrong_device' else previous
                        (await session.get(Device, previous)).retired_at = now if failure=='retired' else None
                        await session.commit()
                    assert (await client.post(path,json=proof,headers=headers)).status_code == 409, failure
                async with provider() as session:
                    old = await session.get(EnrollmentClaim,cid)
                    old.fingerprint_digest = hardware_fingerprint_digest(payload.hardware_fingerprint, PEPPER)
                    old.claimed_at = now
                    old.device_id = previous
                    (await session.get(Device,previous)).retired_at = None
                    await session.commit()
                result = await client.post(path,json=proof,headers=headers)
                assert result.status_code == 204, result.text
                async with provider() as session:
                    relation = await session.scalar(select(InstallationParent).where(InstallationParent.enrollment_request_id==rid))
                    assert relation.previous_device_id == previous
                    assert (await session.get(EnrollmentClaim,cid)).enrollment_request_id is None
                    assert (await session.get(EnrollmentRequest,rid)).device_id is None
        finally:
            await provider.close()
    asyncio.run(scenario())
