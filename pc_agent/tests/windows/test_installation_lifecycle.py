"""Native facts survive removal, retry in order, and never borrow presence authority."""
import importlib
import json
from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import UUID

import pytest

DEVICE = '11111111-1111-4111-8111-111111111111'
TX1 = '22222222-2222-4222-8222-222222222222'
TX2 = '33333333-3333-4333-8333-333333333333'
NATIVE = dict(version='3.2.177', product_code='{44444444-4444-4444-8444-444444444444}',
              source_revision='a'*40, msi_sha256='b'*64, exit_code=0)


def notification_module():
    return importlib.import_module('pc_agent.platform.windows.installation_notification')


def module():
    assert importlib.util.find_spec('pc_agent.platform.windows.installation_lifecycle') is not None, 'native lifecycle implementation missing'
    return importlib.import_module('pc_agent.platform.windows.installation_lifecycle')


@pytest.fixture
def outbox(tmp_path, monkeypatch):
    m = module()
    monkeypatch.setattr(m, '_assert_private', lambda _: None)
    monkeypatch.setattr(m, '_protect_private', lambda _: None)
    monkeypatch.setattr(m.installer_fence, 'assert_state_security', lambda *a, **k: None)
    return m.NativeLifecycleOutbox(tmp_path / 'installation-events')


def add(box, tx=TX1, action='removed', device=DEVICE):
    return box.record(transaction_id=tx, action=action, device_id=device,
                      native=NATIVE, cleanup={'support':'complete','browser':'complete'},
                      occurred_at=datetime(2026, 11, 7, tzinfo=UTC))


def ack(event):
    return dict(schema_version='endpoint_installation_event_ack_v1',
                **{key:event[key] for key in ('device_id','event_id','generation_id','sequence')},
                state=event['action'], received_at='2026-11-07T09:00:00Z')


def test_lost_response_retries_identical_removal_before_installed(outbox):
    removal = add(outbox)
    sent = []
    def lost(event):
        sent.append(event)
        raise OSError('response lost')
    assert outbox.deliver(DEVICE, lost) == 'pending'
    installed = add(outbox, TX2, 'installed')
    assert installed['sequence'] == 2
    assert installed['previous_event_id'] == removal['event_id']
    assert installed['generation_id'] == removal['generation_id']
    def accepted(event):
        sent.append(event)
        return ack(event)
    assert outbox.deliver(DEVICE, accepted) == 'delivered'
    assert [event['action'] for event in sent] == ['removed', 'removed', 'installed']
    assert sent[0] == sent[1]
    assert outbox.deliver(DEVICE, lambda _: pytest.fail('duplicate after ack')) == 'delivered'


def test_same_native_transaction_is_idempotent_and_changed_fact_rejected(outbox):
    first = add(outbox)
    assert add(outbox) == first
    with pytest.raises(ValueError):
        add(outbox, action='installed')


@pytest.mark.parametrize('field,value', [('device_id', TX2), ('generation_id', TX2),
    ('event_id', TX2), ('sequence', 4), ('state', 'installed')])
def test_wrong_ack_never_advances_cursor(outbox, field, value):
    add(outbox)
    assert outbox.deliver(DEVICE, lambda event: {**ack(event), field:value}) == 'pending'
    attempts=[]
    assert outbox.deliver(DEVICE, lambda event: attempts.append(event) or ack(event)) == 'delivered'
    assert len(attempts)==1


@pytest.mark.parametrize('defect', ['missing-journal', 'missing-anchor', 'corrupt', 'sequence-gap'])
def test_existing_stream_is_never_silently_reinitialized(outbox, defect):
    add(outbox)
    if defect == 'missing-journal':
        (outbox.root/'journal.json').unlink()
    elif defect == 'missing-anchor':
        (outbox.root/'anchor.json').unlink()
    elif defect == 'corrupt':
        (outbox.root/'journal.json').write_text('{}')
    else:
        path=outbox.root/'journal.json'
        value=json.loads(path.read_text());value['facts'][0]['event']['sequence']=2
        path.write_text(json.dumps(value))
    with pytest.raises(ValueError):
        add(outbox, TX2, 'installed')


def test_fresh_install_binds_only_after_durable_enrollment(outbox):
    assert add(outbox, action='installed', device=None) is None
    assert outbox.pending(DEVICE) == []
    outbox.bind_installation(TX1, DEVICE)
    assert outbox.pending(DEVICE)[0]['action']=='installed'
    with pytest.raises(ValueError):
        outbox.bind_installation(TX1, TX2)


def test_unidentified_removal_cannot_borrow_new_enrollment(outbox):
    add(outbox, device=None)
    with pytest.raises(ValueError):
        outbox.bind_installation(TX1, DEVICE)
    assert json.loads((outbox.root/'journal.json').read_text())['facts'][0]['delivery']=='undeliverable'


def test_other_device_does_not_receive_old_pending_facts(outbox):
    add(outbox)
    add(outbox, TX2, 'installed', device=TX2)
    sent=[]
    assert outbox.deliver(TX2, lambda event: sent.append(event) or ack(event))=='delivered'
    assert len(sent)==1 and sent[0]['device_id']==TX2
    assert len(outbox.pending(DEVICE))==1


def test_missing_established_outbox_directory_does_not_reset_generation(outbox):
    add(outbox)
    for child in outbox.root.iterdir():
        child.unlink()
    outbox.root.rmdir()
    with pytest.raises(ValueError):
        add(outbox, TX2, 'installed')


def test_committed_upgrade_new_child_emits_installed_only():
    m=module()
    assert m.native_action({'operation':'install','compound':{'upgrade_id':TX1}})=='installed'


@pytest.mark.parametrize('change', [{'operation':'retire-initial-runtime'},
    {'uninstall_finalization':True}, {'compound':{}}, {'staged_rollback':{}},
    {'recovery_parent':{}}, {'recovery':True}])
def test_nonordinary_paths_do_not_publish_removal(change):
    m=module()
    cap={'operation':'uninstall','recovery':False,'uninstall_finalization':False, **change}
    assert m.native_action(cap) is None


def test_owned_cleanup_preserves_foreign_values_and_reports_both_browsers():
    m=module()
    from pc_agent.tests.windows.test_browser_policy import MemoryRegistry, _app, EXTENSION_ID
    from pc_agent.platform.windows.browser_policy import CHROME_POLICY_PATH, YANDEX_POLICY_PATH, MARKER_PATH
    registry=MemoryRegistry(); app=_app(registry)
    app.apply('chrome');app.apply('yandex')
    registry.values[(YANDEX_POLICY_PATH,'2')]='b'*32+';https://foreign.example/update'
    result=m.relinquish_browser_policy(registry=registry, extension_id=EXTENSION_ID)
    assert result=={'browser':'complete','families':{'chrome':'complete','yandex':'complete'}}
    assert registry.read(CHROME_POLICY_PATH,'ExtensionSettings') is None
    assert registry.read(MARKER_PATH,'chrome') is None
    assert registry.read(YANDEX_POLICY_PATH,'2')=='b'*32+';https://foreign.example/update'


def test_cleanup_conflict_is_independent_and_unowned_policy_is_preserved():
    m=module()
    from pc_agent.tests.windows.test_browser_policy import MemoryRegistry, _app, EXTENSION_ID
    from pc_agent.platform.windows.browser_policy import CHROME_POLICY_PATH, YANDEX_POLICY_PATH
    registry=MemoryRegistry();app=_app(registry);app.apply('chrome');app.apply('yandex')
    registry.values[(CHROME_POLICY_PATH,'ExtensionSettings')]='malformed'
    result=m.relinquish_browser_policy(registry=registry, extension_id=EXTENSION_ID)
    assert result['browser']=='conflict' and result['families']['yandex']=='complete'
    assert registry.read(CHROME_POLICY_PATH,'ExtensionSettings')=='malformed'
    assert registry.values_at(YANDEX_POLICY_PATH)=={}
    foreign=MemoryRegistry();foreign.values[(CHROME_POLICY_PATH,'ExtensionSettings')]='unowned'
    assert m.relinquish_browser_policy(registry=foreign,extension_id=EXTENSION_ID)['browser']=='external_preserved'
    assert foreign.read(CHROME_POLICY_PATH,'ExtensionSettings')=='unowned'


def test_delivery_has_no_redirect_or_proxy_authority_and_binds_request(monkeypatch, tmp_path):
    m=notification_module()
    assert hasattr(m,'InstallationHTTPSClient'), 'bounded lifecycle HTTPS sender missing'
    calls=[]
    class Context:
        def load_verify_locations(self, **kw): calls.append(('ca',kw))
    monkeypatch.setattr(m.ssl,'SSLContext',lambda _: Context())
    class Connection:
        sock=None
        def __init__(self, host, port, **kw): calls.append(('connect',host,port,kw['timeout']))
        def request(self, method, path, **kw): calls.append(('request',method,path,kw))
        def getresponse(self): return SimpleNamespace(status=302)
        def close(self): calls.append(('close',))
    monkeypatch.setattr(m.http.client,'HTTPSConnection',Connection)
    sender=m.InstallationHTTPSClient(tmp_path/'ca.crt','x'*43)
    from tests.contracts.test_installation_lifecycle import event_data
    with pytest.raises(ValueError): sender(event_data())
    assert calls[1][1:3]==('endpoint.sosnadmin.local',443)
    assert calls[2][1:3]==('POST','/agent/v1/installation-events')
    assert calls[2][3]['headers']['Authorization']=='Bearer '+'x'*43
    assert calls[-1]==('close',)


def test_support_activation_waits_for_lifecycle_delivery(monkeypatch,tmp_path):
    m=notification_module()
    from pc_agent.platform.windows import setup_entry, provision
    assert hasattr(m,'sync_enrolled_installation'), 'Setup lifecycle delivery missing'
    calls=[]
    monkeypatch.setattr(m,'sync_enrolled_installation',lambda _: calls.append('pending-event') or 'pending')
    monkeypatch.setattr(provision,'install_enrolled_support',lambda _: pytest.fail('Support preceded installed acknowledgement'))
    monkeypatch.setattr(setup_entry,'_write_support_install_result',lambda *a: calls.append(a))
    setup_entry._install_support_after_native(tmp_path)
    assert calls[0]=='pending-event'


def test_fresh_binding_and_retained_retry_deliver_before_support(outbox,monkeypatch,tmp_path):
    m=notification_module()
    from contextlib import nullcontext
    from pc_agent.platform.windows import update_paths, update_transaction
    paths=update_paths.WindowsUpdatePaths(tmp_path/'Agent',tmp_path/'data/updates/pending.json')
    monkeypatch.setattr(update_paths.WindowsUpdatePaths,'production',classmethod(lambda _:paths))
    monkeypatch.setattr(update_transaction,'update_transaction',lambda *a,**k:nullcontext())
    monkeypatch.setattr(m.installer_fence,'read_fence',lambda _:None)
    monkeypatch.setattr(m,'outbox_for',lambda _:outbox)
    monkeypatch.setattr(m,'_identity',lambda _:DEVICE)
    sent=[]
    monkeypatch.setattr(m,'_sender',lambda _:lambda event:sent.append(event) or ack(event))
    monkeypatch.setattr(m,'bounded_delivery',lambda: m.deliver_retained(paths))
    add(outbox,action='installed',device=None)
    assert m.sync_enrolled_installation(tmp_path/'data')=='delivered'
    assert sent[0]['device_id']==DEVICE and sent[0]['sequence']==1
    add(outbox,TX2,'removed')
    add(outbox,'55555555-5555-4555-8555-555555555555','installed')
    assert m.sync_enrolled_installation(tmp_path/'data')=='delivered'
    assert [event['action'] for event in sent]==['installed','removed','installed']
    assert m.sync_enrolled_installation(tmp_path/'data')=='delivered'
    assert len(sent)==3


def test_finish_does_not_treat_unsafe_existing_identity_as_new_enrollment(outbox,monkeypatch,tmp_path):
    m=module()
    from pc_agent.platform.windows.update_paths import WindowsUpdatePaths
    paths=WindowsUpdatePaths(tmp_path/'Agent',tmp_path/'data/updates/pending.json')
    paths.pending_path.parents[1].mkdir()
    (paths.pending_path.parents[1]/'enrollment-identity.json').write_text('broken existing identity')
    monkeypatch.setattr(m,'outbox_for',lambda _:outbox)
    monkeypatch.setattr(m,'_identity',lambda _:(_ for _ in ()).throw(ValueError('unsafe')))
    expected=SimpleNamespace(package=SimpleNamespace(version='3.2.177',product_code=NATIVE['product_code'],sha256='b'*64),identity=SimpleNamespace(source_revision='a'*40))
    with m.durable_state.installer_mutation_checkpoints(lambda:None):
        with pytest.raises(ValueError):
            m.record_native_finish(paths,{'operation':'install','transaction_id':TX1},expected)


def test_installer_spec_bundles_policy_identity_without_removed_service(monkeypatch,tmp_path):
    m=module()
    from pathlib import Path
    from tools.canary import setup_client_payload, tzdata_payload, ssl_payload
    monkeypatch.setattr(setup_client_payload,'signed_setup_client_payload',lambda *a:[])
    monkeypatch.setattr(tzdata_payload,'configure_tzdata_archive',lambda *a:None)
    monkeypatch.setattr(ssl_payload,'configure_ssl_resources',lambda *a:None)
    spec=Path(__file__).resolve().parents[2]/'pyinstaller_windows_installer_host.spec'
    collected={}
    def analysis(*a,**kw):
        collected.update(kw)
        return SimpleNamespace(pure=[],scripts=[],binaries=[],datas=kw['datas'])
    exec(compile(spec.read_text(),str(spec),'exec'),{'SPECPATH':str(spec.parent),
        'workpath':str(tmp_path/'work'),'Analysis':analysis,'PYZ':lambda *a:None,'EXE':lambda *a,**kw:None})
    resources=[Path(source) for source,target in collected['datas'] if target=='browser_sensor']
    assert len(resources)==1 and resources[0].name=='extension-id.txt'
    bundle=tmp_path/'bundle';(bundle/'browser_sensor').mkdir(parents=True)
    (bundle/'browser_sensor'/'extension-id.txt').write_bytes(resources[0].read_bytes())
    monkeypatch.setattr(m.sys,'frozen',True,raising=False)
    monkeypatch.setattr(m.sys,'_MEIPASS',str(bundle),raising=False)
    assert m.packaged_extension_id()==resources[0].read_text().strip()
    assert not (bundle/'EndpointBrowserPolicy.exe').exists()


@pytest.mark.parametrize('phase', ['delayed-dns','slow-headers','acknowledged'])
def test_notification_only_job_bounds_network_and_reaps_descendants(outbox,tmp_path,phase):
    import os
    import sys
    import time
    from pathlib import Path
    if os.name != 'nt':
        pytest.skip('Windows job containment')
    m=notification_module()
    assert hasattr(m,'_run_notification_process'), 'notification-only containment missing'
    add(outbox)
    script=tmp_path/'delayed_notification.py'
    source=Path(__file__).resolve().parents[3]
    marker=tmp_path/'network-stage.json'
    script.write_text('''import json,sys,time,os,subprocess
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from pc_agent.platform.windows import installation_notification as m, installation_lifecycle as facts
facts._assert_private=lambda _:None
facts._protect_private=lambda _:None
facts.installer_fence.assert_state_security=lambda *a,**k:None
root,phase,marker=Path(sys.argv[2]),sys.argv[3],Path(sys.argv[4])
child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(120)'])
def reached():
    marker.write_text(json.dumps({'pid':os.getpid(),'child_pid':child.pid,'stage':phase}))
class Context:
    def load_verify_locations(self,**kw): pass
m.ssl.SSLContext=lambda _:Context()
class Connection:
    sock=None
    def __init__(self,*a,**kw): pass
    def request(self,*a,**kw):
        if phase=='delayed-dns': reached();time.sleep(120)
    def getresponse(self):
        reached();time.sleep(120)
    def close(self): pass
m.http.client.HTTPSConnection=Connection
def ack(event):
    reached()
    return dict(schema_version='endpoint_installation_event_ack_v1',
        **{k:event[k] for k in ('device_id','event_id','generation_id','sequence')},
        state=event['action'],received_at='2026-11-07T09:00:00Z')
sender=ack if phase=='acknowledged' else m.InstallationHTTPSClient(Path('unused-ca'),'x'*43)
status=facts.NativeLifecycleOutbox(root).deliver('11111111-1111-4111-8111-111111111111',sender)
sys.exit(0 if status=='delivered' else 75)
''',encoding='utf-8')
    started=time.monotonic()
    status=m._run_notification_process([sys.executable,str(script),str(source),str(outbox.root),phase,str(marker)],timeout_ms=2500)
    assert time.monotonic()-started < 10
    observed=json.loads(marker.read_text())
    assert observed['stage']==phase
    assert status==('delivered' if phase=='acknowledged' else 'pending')
    assert bool(outbox.pending(DEVICE)) == (phase!='acknowledged')
    import win32api, win32process
    for pid in (observed['pid'],observed['child_pid']):
        try: handle=win32api.OpenProcess(0x1000,False,pid)
        except Exception as error:
            assert getattr(error,'winerror',None)==87, 'Process absence was not established'
            continue
        try: assert win32process.GetExitCodeProcess(handle)!=259
        finally: handle.Close()


def test_source_notification_command_imports_checkout_from_unrelated_cwd(monkeypatch,tmp_path):
    """Run the generated child code; stop at main before any production access."""
    import os
    import subprocess
    from pathlib import Path
    m=notification_module()
    monkeypatch.setattr(m.sys,'frozen',False,raising=False)
    observed=[]
    def run_generated(command):
        assert command[1]=='-c'
        guard='''import sys,json
def before_notification_main(frame,event,arg):
    if event=='call' and frame.f_code.co_name=='main' and frame.f_globals.get('__name__')=='pc_agent.platform.windows.installer_host_entry':
        print(json.dumps({'module':frame.f_globals['__file__'],'argv':frame.f_locals['argv']}))
        raise SystemExit(0)
    return before_notification_main
sys.settrace(before_notification_main)
'''
        environment={key:value for key,value in os.environ.items() if key.upper()!='PYTHONPATH'}
        result=subprocess.run([command[0],'-c',guard+command[2]],cwd=tmp_path,
            env=environment,capture_output=True,text=True,timeout=15)
        observed.append(result)
        return 'delivered' if result.returncode==0 else 'pending'
    monkeypatch.setattr(m,'_run_notification_process',run_generated)
    status=m.bounded_delivery()
    assert len(observed)==1
    assert observed[0].returncode==0,observed[0].stderr
    entered=json.loads(observed[0].stdout)
    assert Path(entered['module']).resolve()==Path(__file__).resolve().parents[3]/'pc_agent/platform/windows/installer_host_entry.py'
    assert entered['argv']==['--installation-events-send']
    assert status=='delivered'


def test_unfrozen_browser_identity_uses_real_checkout_resource(monkeypatch,tmp_path):
    from pathlib import Path
    m=module()
    monkeypatch.setattr(m.sys,'frozen',False,raising=False)
    monkeypatch.chdir(tmp_path)
    expected=Path(__file__).resolve().parents[3]/'browser_sensor/extension-id.txt'
    assert m.packaged_extension_id()==expected.read_text(encoding='ascii').strip()


@pytest.mark.parametrize('action', ['installed', 'removed'])
def test_native_wire_matches_shared_contract(outbox,action):
    from endpoint_contracts.installation_lifecycle import InstallationEventV1,InstallationEventAckV1
    event=add(outbox,action=action)
    assert module()._wire(event)==InstallationEventV1.model_validate(event).model_dump(mode='json')
    received=ack(event)
    assert module()._wire(received,acknowledgement=True)==InstallationEventAckV1.model_validate(received).model_dump(mode='json')


@pytest.mark.parametrize('acknowledgement', [False,True])
@pytest.mark.parametrize('field,value', [
    ('sequence',True),('sequence',1.0),('sequence','1'),('sequence',0),('sequence',2147483648),
    ('device_id','not-a-uuid'),('generation_id',None),('event_id',False),
    ('timestamp','2026-11-07T09:00:00'),('timestamp','invalid'),('extra','value'),
    ('action','unknown'),
])
def test_native_wire_rejects_malformed_contract_fields(outbox,acknowledgement,field,value):
    from endpoint_contracts.installation_lifecycle import InstallationEventV1,InstallationEventAckV1
    event=add(outbox);payload=ack(event) if acknowledgement else event
    if field=='timestamp': field='received_at' if acknowledgement else 'occurred_at'
    if field=='action' and acknowledgement: field='state'
    payload={**payload,field:value}
    with pytest.raises(ValueError): module()._wire(payload,acknowledgement=acknowledgement)
    with pytest.raises(ValueError):
        (InstallationEventAckV1 if acknowledgement else InstallationEventV1).model_validate(payload)


@pytest.mark.parametrize('field,value', [
    ('exit_code',False),('exit_code',0.0),('exit_code','0'),('exit_code',21),
    ('version','01.2.177'),('version','3.2.123456'),('product_code','invalid'),
    ('source_revision','A'*40),('msi_sha256','b'*63),('extra','value'),
])
def test_native_proof_rejects_malformed_contract_fields(field,value):
    from endpoint_contracts.installation_lifecycle import InstallationNativeProof
    proof={**NATIVE,field:value}
    with pytest.raises(ValueError): module()._native(proof)
    with pytest.raises(ValueError): InstallationNativeProof.model_validate(proof)


@pytest.mark.parametrize('change', [
    {'previous_event_id':TX2}, {'sequence':2}, {'sequence':2,'previous_event_id':'invalid'},
    {'native':{}}, {'cleanup':{'support':'complete','browser':'complete','extra':True}},
    {'cleanup':{'support':False,'browser':'complete'}},
])
def test_native_wire_preserves_shared_causality_and_cleanup_checks(outbox,change):
    from endpoint_contracts.installation_lifecycle import InstallationEventV1
    event={**add(outbox),**change}
    with pytest.raises(ValueError): module()._wire(event)
    with pytest.raises(ValueError): InstallationEventV1.model_validate(event)
