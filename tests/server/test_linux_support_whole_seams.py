"""Real Linux producer/provider seams; no installed-host operations."""
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from endpoint_contracts.linux_installation_lifecycle import LinuxInstallationEventV1
from endpoint_server.installation_lifecycle.service import accept_event
from endpoint_server.installation_lifecycle.linux_sources import LinuxNativeRelease, resolve_linux_source
from endpoint_server.support_access.service import register, record_runtime_status
from pc_agent.platform.linux.installation_lifecycle import LifecycleJournal
from pc_agent.tests.test_linux_installation_lifecycle import MemoryStore
from tests.contracts.test_linux_support_lifecycle import native_data
from tests.server.test_linux_support_lifecycle import sessions, identity, registration
from tests.server.test_linux_native_rebind_expiry import configured, healthy


async def journal_reinstall(session, principal, settings, *, offline):
    now = datetime.now(UTC)
    row = await register(session, principal.device.id, principal.credential.id,
        registration(), platform='linux_amd64', settings=settings, now=now)
    from endpoint_server.support_access.installation import consume_installation_access
    healthy(row, now)
    await consume_installation_access(session, row, settings, now)
    expiry = row.expires_at
    session.add(LinuxNativeRelease(**{k:v for k,v in native_data().items() if k!='exit_code'},
        signer_fingerprint='A'*40, frozen_manifest_sha256='c'*64, reviewed_by='fixture'))
    await session.flush()
    journal = LifecycleJournal(MemoryStore())
    async def drain():
        for raw in journal.pending_events():
            body = LinuxInstallationEventV1.model_validate(raw)
            ack = await accept_event(session, principal, body, request_id='journal-seam', source_resolver=resolve_linux_source)
            assert await accept_event(session, principal, body, request_id='exact-replay', source_resolver=resolve_linux_source) == ack
            journal.acknowledge(ack.model_dump(mode='json'))
    for action in ('install', 'remove', 'install'):
        journal.begin(action, {k:v for k,v in native_data().items() if k!='exit_code'})
        journal.native_result(0)
        journal.cleanup_result({'support':'complete','browser':'complete'})
        journal.settle(exact_native_state=True, device_id=str(principal.device.id))
        if not offline:
            await drain()
    await drain()
    rebound = await register(session, principal.device.id, principal.credential.id,
        registration(4), platform='linux_amd64', settings=settings)
    assert rebound.id == row.id and rebound.enabled and rebound.expires_at == expiry
    assert rebound.installation_access_pending_until is None
    healthy(rebound, datetime.now(UTC))
    await consume_installation_access(session, rebound, settings, datetime.now(UTC))
    assert rebound.expires_at == expiry and not journal.pending_events()


@pytest.mark.parametrize('offline', [False, True])
async def test_real_journal_provider_reinstall(sessions, tmp_path, offline):
    async with sessions() as session:
        await journal_reinstall(session, await identity(session), configured(tmp_path), offline=offline)


@pytest.mark.parametrize('configuration,allowed', [
    ('canonical', True), ('staging', True), ('staging_opt_out', False),
    ('mixed', False), ('missing_pin', False), ('invalid_pin', False),
    ('unavailable', False), ('wrong_port', False),
])
async def test_populated_linux_export_matches_effective_policy(sessions, tmp_path, configuration, allowed):
    from endpoint_server.support_access.linux_routes import policy
    from endpoint_server.support_access.exporter import export_once
    from endpoint_server.support_access.service import get_broker_leases
    import json
    settings = configured(tmp_path)
    async with sessions() as session:
        principal = await identity(session)
        row = await register(session, principal.device.id, principal.credential.id,
            registration(), platform='linux_amd64', settings=settings)
        now = datetime.now(UTC)
        healthy(row, now)
        from endpoint_server.support_access.installation import consume_installation_access
        await consume_installation_access(session, row, settings, now)
        expiry = row.expires_at
        settings = replace(settings, support_linux_install_auto_enable=False)
        if configuration in ('staging', 'staging_opt_out'):
            settings = replace(settings, public_base_url='https://endpoint-staging.sosnadmin.local',
                support_gateway_host='endpoint-staging.sosnadmin.local', support_linux_staging_gateway_enabled=True)
            if configuration == 'staging_opt_out':
                await session.flush()
                assert len(await get_broker_leases(session, now, settings=settings)) == 1
                await session.commit()
                await export_once(sessions, tmp_path/'leases.json', now=now, settings=settings)
                assert len(json.loads((tmp_path/'leases.json').read_text())['leases']) == 1
                settings = replace(settings, support_linux_staging_gateway_enabled=False)
        elif configuration == 'mixed':
            settings = replace(settings, support_gateway_host='endpoint-staging.sosnadmin.local')
        elif configuration in ('missing_pin', 'invalid_pin'):
            settings = replace(settings, support_gateway_host_public_key='' if configuration == 'missing_pin' else 'invalid')
        elif configuration == 'unavailable':
            settings = replace(settings, device_token_pepper=None)
        elif configuration == 'wrong_port':
            settings = replace(settings, support_gateway_port=22)
        assert (await policy(session, row, settings)).enabled is allowed
        await session.commit()
        leases = await get_broker_leases(session, now, settings=settings)
        assert bool(leases) is allowed
        await export_once(sessions, tmp_path/'leases.json', now=now, settings=settings)
        assert bool(json.loads((tmp_path/'leases.json').read_text())['leases']) is allowed
        assert row.enabled and row.expires_at == expiry


async def service_recovery(provider, row, settings, monkeypatch, *, persistent=False, restart=False, failure='account'):
    """Real status recorder/projection/lease/service loop; only HTTPS and OS replaced."""
    import asyncio
    import threading
    from contextlib import contextmanager
    from pc_agent.platform.linux import support_access_service as service
    from pc_agent.platform.linux.support_access import SupportError
    from endpoint_contracts.linux_support_access import LinuxSupportStatusReport
    from endpoint_server.support_access.models import SupportAccess
    from endpoint_server.support_access.linux_routes import policy
    outgoing, projections, starts, readiness = [], [], [], []
    clock = [10.0]
    class Stop(threading.Event):
        def wait(self, timeout=None):
            clock[0] += 31
            if clock[0] > 10000:
                self.set()
            return super().wait(.001)
    stop = Stop()
    restarting = [False]
    config = dict(device_id=str(row.device_id), credential_id=str(row.id), support_token='eps1.'+'x'*64,
        origin=settings.public_base_url, environment='production')
    class Store:
        state = None
        def __init__(self, *_): pass
        @contextmanager
        def locked(self): yield self
        def json(self, name, **_): return config if name=='config.json' else self.state
        def read(self, *_): return b'fixture CA'
        def keys(self): return row.host_public_key, row.tunnel_public_key
        def save(self, _name, state): Store.state = state
    class HTTPS:
        def __init__(self, *_): pass
        def request(self, action, token, body):
            outgoing.append(body.copy())
            async def report():
                async with provider() as session:
                    current = await session.get(SupportAccess, row.id)
                    # SQLite fixture loses timezone on roundtrip; PostgreSQL's
                    # production TIMESTAMPTZ returns aware UTC values.
                    from endpoint_server.support_access.service import utc
                    current.expires_at = utc(current.expires_at)
                    now = datetime.now(UTC)
                    record_runtime_status(current, LinuxSupportStatusReport.model_validate(body), now)
                    response = await policy(session, current, settings)
                    await session.commit()
                    projections.append(response.enabled)
                    return response.model_dump(mode='json'), now.timestamp()
            result = asyncio.run(report())
            if failure=='https' and len(outgoing)==1:
                raise SupportError('https_unavailable')
            if len(outgoing) >= (2 if restart and not restarting[0] else 5): stop.set()
            return result
    class Children:
        active = False
        def __init__(self, *_): pass
        def stop(self): self.active = False
        def prepare(self, p):
            readiness.append(p.revision)
            if persistent:
                raise SupportError('account_not_authorized')
        def start(self, p, deadline):
            starts.append((p.revision, deadline))
            if failure=='native' and len(starts)==1:
                raise SupportError('child_start_failed')
            self.active = True
        def alive(self): return self.active
        def connected(self): return self.active
    account_checks = []
    def account(*_):
        account_checks.append(True)
        if failure=='account' and (len(account_checks)==1 or persistent):
            raise SupportError('account_not_authorized')
    monkeypatch.setattr(service, 'PrivateStore', Store)
    monkeypatch.setattr(service, 'SupportHTTPS', HTTPS)
    monkeypatch.setattr(service, 'NativeChildren', Children)
    monkeypatch.setattr(service, 'validate_account', account)
    monkeypatch.setattr(service, 'boot_time', lambda: clock[0])
    monkeypatch.setattr(service, 'boot_id', lambda: 'same-boot')
    await asyncio.to_thread(service.run_service, stop_event=stop)
    if restart:
        # Error+authority survives the service instance. Recovered local readiness
        # must precede a clean status; disabled policy still cannot start anything.
        assert Store.state['last_error'] == 'configuration_conflict'
        restarting[0] = True
        stop.clear()
        await asyncio.to_thread(service.run_service, stop_event=stop)
    expected = {'account':'configuration_conflict','native':'tunnel_failed','https':'policy_unavailable'}[failure]
    assert outgoing[1]['last_error_code'] == expected
    assert projections[1] is False
    assert readiness or failure=='https'
    if persistent:
        assert all(x['last_error_code']=='configuration_conflict' for x in outgoing[1:])
        assert not starts and not any(x['tunnel_connected'] for x in outgoing)
    else:
        assert outgoing[-1]['last_error_code'] is None and outgoing[-1]['tunnel_connected']
        assert any(not x['tunnel_connected'] and x['last_error_code'] is None for x in outgoing[2:])
        assert starts and Store.state['authority']['expires_at'] == row.expires_at.timestamp()
    async with provider() as session:
        current = await session.get(SupportAccess, row.id)
        from endpoint_server.support_access.service import utc
        assert current.revision == row.revision and utc(current.expires_at) == utc(row.expires_at)


@pytest.mark.parametrize('persistent,restart,failure', [(False,False,'account'),(True,False,'account'),
    (True,True,'account'),(False,True,'account'),(False,False,'https'),(False,False,'native')])
async def test_actual_provider_masked_policy_service_recovery(sessions, tmp_path, monkeypatch, persistent, restart, failure):
    settings = configured(tmp_path)
    async with sessions() as session:
        principal = await identity(session)
        row = await register(session, principal.device.id, principal.credential.id,
            registration(), platform='linux_amd64', settings=settings)
        now = datetime.now(UTC)
        healthy(row, now)
        from endpoint_server.support_access.installation import consume_installation_access
        await consume_installation_access(session, row, settings, now)
        await session.commit()
    await service_recovery(sessions, row, settings, monkeypatch, persistent=persistent, restart=restart, failure=failure)


async def test_initial_provider_availability_binds_first_enabled_authority(sessions, tmp_path):
    from endpoint_server.support_access.linux_routes import policy
    from endpoint_server.support_access.installation import consume_installation_access
    from pc_agent.platform.linux.support_access import SupportPolicy, LeaseState
    settings=configured(tmp_path)
    async with sessions() as session:
        principal=await identity(session)
        row=await register(session,principal.device.id,principal.credential.id,
            registration(),platform='linux_amd64',settings=settings)
        now=datetime.now(UTC)
        healthy(row,now)
        await consume_installation_access(session,row,settings,now)
        revision,expiry=row.revision,row.expires_at
        row.installed=False
        state=LeaseState()
        for installed in (False,True):
            row.installed=installed
            raw=(await policy(session,row,settings)).model_dump(mode='json')
            parsed=SupportPolicy.parse(raw,device_id=str(row.device_id),origin=settings.public_base_url,
                host_key=row.host_public_key,tunnel_key=row.tunnel_public_key)
            deadline=state.accept(parsed,wall=now.timestamp(),server=now.timestamp(),boot=10,boot_id='a')
            assert bool(deadline) is installed
            assert row.revision==revision and row.expires_at==expiry
