"""Synthetic-only bounded probe tests; no native runtime, SQL or IdP request."""
import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def module():
    return load('tools/keycloak/master_token_diagnostic.py', 'master_token_diagnostic')


def backend():
    return load('tools/keycloak/recover_pilot_identity.py', 'recovery_diagnostic_backend')


def snapshot(b,database,oid,label):
    return {'schema':'keycloak_recovery_snapshot_v1','database':database,'database_oid':oid,
        'owner':'keycloak','server_version_num':160015,'port':5544,'schema_sha256':'a'*64,
        'sequence_state':{},'unexpected_functions':0,'unexpected_triggers':0,
        'actual_tables':list(b.TABLE_MANIFEST),'tables':{name:([hashlib.sha256(label.encode()).hexdigest()]
        if name=='server_config' else []) for name in b.TABLE_MANIFEST}}


class FakeOperations:
    def __init__(self, fail=None, cleanup=False):
        self.calls = []
        self.fail = fail
        self.fail_cleanup = cleanup
        self.token = 'synthetic-secret-token'
        self.session = SimpleNamespace(token=self.token, session_id='synthetic-secret-sid')
        self.result = None

    def step(self, phase):
        self.calls.append(phase)
        if phase == self.fail:
            raise ValueError('raw-secret-exception-must-not-escape')

    def preflight(self): self.step('Preflight')
    def start(self): self.step('RuntimeStart')
    def login_once(self): self.step('MasterLogin'); return self.token
    def shape(self, token):
        self.step('TokenShape')
        return dict.fromkeys(module().TOKEN_SHAPE_FIELDS, False)
    def construct_client(self, token): self.step('TokenConstructor'); return self.session
    def lifetime(self, session): self.step('TokenLifetime')
    def realms_once(self, session): self.step('RealmGet')
    def inventory_once(self, session):
        self.step('SessionInventory')
        return {'fresh_session_verified':True,'flags_verified':True,'realms_verified':True,
            'strict_cutoff_order_verified':True,'revocation_not_lowered':True,'offline_inventory_bounded':True}
    def clear_sensitive(self): self.calls.append('ClearSensitive'); self.token = ''
    def cleanup(self):
        self.calls.append('Cleanup')
        if self.fail_cleanup:
            raise ValueError('cleanup-secret-must-not-escape')
        return dict.fromkeys(module().CLEANUP_FIELDS, True)
    def safe_code(self, error): return 'ProbeUnexpectedFailure'
    def record(self, result): self.calls.append('ResultReceipt'); self.result = result


def test_one_probe_stops_without_any_purge_or_browser_and_clears_secrets():
    m = module(); ops = FakeOperations()
    result = m.execute_probe(ops)
    assert ops.calls == ['Preflight','RuntimeStart','MasterLogin','TokenShape','TokenConstructor',
        'TokenLifetime','RealmGet','SessionInventory','ClearSensitive','Cleanup','ResultReceipt']
    assert result['status'] == 'MasterTokenDiagnosticCompleteHold'
    assert result['switch_ready'] is False and result['semantic_reviewed'] is False
    assert ops.session.token == ops.session.session_id == ops.token == ''
    assert 'synthetic-secret' not in json.dumps(result)


@pytest.mark.parametrize('phase', ['Preflight','RuntimeStart','MasterLogin','TokenShape',
    'TokenConstructor','TokenLifetime','RealmGet','SessionInventory'])
def test_every_failed_boundary_stops_once_without_retry_or_secret_export(phase):
    m = module(); ops = FakeOperations(fail=phase)
    result = m.execute_probe(ops)
    assert ops.calls.count('Cleanup') == 1
    assert ops.calls.count('MasterLogin') <= 1 and ops.calls.count('RealmGet') <= 1
    assert result['status'] == 'MasterTokenDiagnosticFailedHold' and result['phase'] == phase
    assert result['refusal_code'] == 'ProbeUnexpectedFailure'
    assert all(secret not in json.dumps(result) for secret in ['raw-secret','synthetic-secret'])


def test_cleanup_uncertainty_overrides_success_and_preserves_primary_failure():
    m = module(); ops = FakeOperations(fail='TokenConstructor', cleanup=True)
    result = m.execute_probe(ops)
    assert result['status'] == 'CleanupUnconfirmedHold'
    assert result['phase'] == 'TokenConstructor' and result['refusal_code'] == 'ProbeUnexpectedFailure'
    assert result['cleanup_code'] == 'ProbeUnexpectedFailure'
    assert 'cleanup-secret' not in json.dumps(result)


def test_receipt_failure_cannot_report_success_or_skip_cleanup():
    m = module(); ops = FakeOperations()
    def refuse(result): raise OSError('receipt-secret')
    ops.record = refuse
    result = m.execute_probe(ops)
    assert result['status'] == 'ProbeReceiptFailedHold'
    assert ops.calls.count('Cleanup') == 1 and 'receipt-secret' not in json.dumps(result)


def test_default_cli_is_inert_and_run_requires_explicit_candidate(capsys,monkeypatch):
    m = module()
    monkeypatch.setattr(m,'run_native',lambda candidate:pytest.fail('native action was not authorized'))
    assert m.main([]) == 0
    assert json.loads(capsys.readouterr().out)['status'] == 'PlanOnly'
    assert m.main(['--run-once']) != 0
    assert 'secret' not in capsys.readouterr().out


def token_fixture():
    claims = {'iat':100,'exp':200,'sid':'00000000-0000-0000-0000-000000000099',
        'iss':'https://sso.sosnadmin.local:18449/realms/master','azp':'admin-cli'}
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip('=')
    return 'header.'+payload+'.signature'


def test_inventory_reducer_keeps_exact_cutoff_guards_without_values():
    m = module(); b = backend()
    client = SimpleNamespace(admin_iat=100)
    value = {'realms':['master','sosnadmin'],'fresh_master_session_count':1,
        'unexpected_offline_flags':0,'maximum_restored_token_iat':99,
        'realm_not_before':{'master':0,'sosnadmin':0},'offline_sessions':[]}
    result = m.reduce_inventory(b,value,client)
    assert result and all(type(item) is bool and item is True for item in result.values())
    assert '99' not in json.dumps(result)
    value['maximum_restored_token_iat'] = 100
    with pytest.raises(b.RecoveryRefused, match='FreshAdminMustPostdateRestoredTokens'):
        m.reduce_inventory(b,value,client)


def test_master_login_capability_consumed_before_uncertain_http_result(monkeypatch):
    m = module(); b = backend(); pilot = load('tools/keycloak/pilot_acceptance.py','probe_pilot_helper')
    pilot.BASE = 'http://127.0.0.1:8089'
    calls=[]
    runtime = SimpleNamespace(proof=lambda:calls.append('Proof'))
    client = m.single_login_client(b,pilot,runtime)
    def uncertain(*args,**kwargs): calls.append('Http'); raise TimeoutError('raw-token')
    monkeypatch.setattr(pilot.LocalAdminClient,'request',uncertain)
    with pytest.raises(TimeoutError): client.login('synthetic-password')
    with pytest.raises(m.ProbeRefused): client.login('synthetic-password')
    assert calls == ['Proof','Http']
    with pytest.raises(m.ProbeRefused): client.request('GET','/admin/realms')


@pytest.mark.parametrize('value', [True,100.0,0,-1])
def test_lifetime_threshold_remains_exact_integer_and_45_seconds(value):
    m = module(); b = backend()
    ops = m.NativeProbe.__new__(m.NativeProbe); ops.backend = b
    with pytest.raises(b.RecoveryRefused,match='FreshMasterTokenLifetimeTooShort'):
        ops.lifetime(SimpleNamespace(expires_at=value),now=100)
    ops.lifetime(SimpleNamespace(expires_at=145),now=100)
    with pytest.raises(b.RecoveryRefused,match='FreshMasterTokenLifetimeTooShort'):
        ops.lifetime(SimpleNamespace(expires_at=144),now=100)


def test_bootstrap_selector_does_not_parse_or_return_other_credentials():
    m = module()
    lines = [b'SSO_LDAP_BIND_PASSWORD=ldap-secret\n',b'SSO_ENDPOINT_CLIENT_SECRET=client-secret\n',
        b'SSO_BOOTSTRAP_PASSWORD=bootstrap-only\n']
    assert m.select_bootstrap(lines) == 'bootstrap-only'
    with pytest.raises(m.ProbeRefused): m.select_bootstrap(lines+[lines[-1]])


def test_unknown_refusal_prefix_or_args_are_never_exported():
    m = module(); ops = m.NativeProbe.__new__(m.NativeProbe); ops.backend = backend()
    ops.pilot = load('tools/keycloak/pilot_acceptance.py','safe_probe_pilot')
    for error in [m.ProbeRefused('CandidateHTTP401-secret'),ValueError('secret'),
                  m.ProbeRefused({'secret':'secret'}),ops.backend.RecoveryRefused('CandidateHTTP401-secret')]:
        assert ops.safe_code(error) == 'ProbeUnexpectedFailure'
    assert ops.safe_code(ops.backend.RecoveryRefused('CandidateHTTP401')) == 'CandidateHTTP401'


@pytest.mark.parametrize('boundary',['TokenShape','SessionInventory','Cleanup'])
def test_invalid_diagnostic_shape_cannot_export_raw_values_even_on_failure(boundary):
    m=module();ops=FakeOperations()
    if boundary=='TokenShape':ops.shape=lambda token:{'raw-secret':'secret-value'}
    if boundary=='SessionInventory':ops.inventory_once=lambda client:{'raw-secret':'secret-value'}
    if boundary=='Cleanup':ops.cleanup=lambda:{'raw-secret':'secret-value'}
    result=m.execute_probe(ops)
    assert result['status']!='MasterTokenDiagnosticCompleteHold'
    assert 'secret' not in json.dumps(result)


def test_native_cleanup_proves_no_candidate_connections_from_json_scalar(monkeypatch,tmp_path):
    m=module();calls=[];real=backend()
    snapshots={name:snapshot(real,name,oid,'forensic-'+name) for name,oid in m.FORENSIC_DATABASES.items()}
    snapshots['keycloak_recovery_20261027_abcdef12']=snapshot(real,'keycloak_recovery_20261027_abcdef12',22222,'fresh')
    def run(argv,*,input_bytes=None,maximum_output=None):
        if input_bytes is not None:
            sql=input_bytes.decode();calls.append(sql)
            assert "to_json(" in sql and "BEGIN READ ONLY" in sql
            return b'true\n'
        return b''
    b=SimpleNamespace(_private_candidate_processes=lambda candidate:[],_run_private=run,
        _psql_argv=lambda database:['readonly',database],
        collect_inventory=lambda candidate:copy.deepcopy(snapshots[candidate]),
        compare_snapshots=real.compare_snapshots,require=real.require,
        _write_private=lambda path,value:calls.append(path.name))
    r=SimpleNamespace(stop=lambda:{'owned_candidate_stopped':True},verify_canonical_reference=lambda:None,candidate_oid=22222)
    ops=m.NativeProbe.__new__(m.NativeProbe)
    ops.backend,ops.runtime,ops.candidate,ops.receipts=b,r,'keycloak_recovery_20261027_abcdef12',tmp_path
    ops.failed_baselines={name:copy.deepcopy(snapshots[name]) for name in m.FORENSIC_DATABASES}
    ops.preserved_files={Path('/root/synthetic-sealed-source'):hashlib.sha256(b'sealed-public-source').hexdigest()}
    monkeypatch.setattr(m,'_read_private',lambda path,maximum:b'sealed-public-source')
    result=ops.cleanup()
    assert all(result.values()) and 'probe-after-full101.json' in calls


def nested_preservation_fixture(m,b):
    candidate='keycloak_recovery_20261027_abcdef12'
    original=snapshot(b,'keycloak_recovery_20261027_55f72537',20856,'original')
    failed={name:{'snapshot':snapshot(b,name,oid,'modified-'+name),'identity':{'candidate_oid':oid}}
        for name,oid in m.FORENSIC_DATABASES.items()}
    before={'schema':'failed_candidate_forensic_preservation_v1','not_original_restore_baseline':True,
        'capture':{'failed_databases':failed},'actual_generated_candidate_name':candidate}
    after=copy.deepcopy(before);after.pop('actual_generated_candidate_name')
    values={
        'original_snapshot':(m.ORIGINAL_ROOT/'candidate-restored.json',original),
        'original_context':(m.ORIGINAL_ROOT/'context.json',{'candidate_oid':20856,'backup_dump_sha256':b.DUMP_SHA256}),
        'original_identity':(m.ORIGINAL_ROOT/'identity-before.json',{'candidate_oid':20856}),
        'prepare_preservation_before':(m.PREPARE_ROOT/'attempt'/'preservation-before.json',before),
        'prepare_preservation_after':(m.PREPARE_ROOT/'attempt'/'preservation-after.json',after),
        'sealed_run7_source':(Path('/root/keycloak-identity-recovery-20261027-executor-v8/recover_pilot_identity.py'),'synthetic-old-source'),
    }
    files={path:json.dumps(value).encode() for path,value in values.values()}
    auth={'schema':'keycloak_master_token_probe_authorization_v1','candidate_database':candidate,
        'candidate_oid':22222,'preserved_artifacts':{name:{'path':path.as_posix(),
        'sha256':hashlib.sha256(files[path]).hexdigest()} for name,(path,value) in values.items()}}
    return auth,files,original


def test_exact_nested_prepare_preservation_is_read_without_new_baseline(monkeypatch):
    m=module();b=backend();auth,files,original=nested_preservation_fixture(m,b)
    ops=m.NativeProbe(auth['candidate_database'],b,None)
    monkeypatch.setattr(m,'_read_private',lambda path,maximum:files[path])
    assert ops._preservation(auth)==original
    actual=copy.deepcopy(ops.failed_baselines)
    ops._verify_failed(actual)
    assert ops._verify_preserved_files() is True
    for name in b.TABLE_MANIFEST:
        changed=copy.deepcopy(actual)
        changed[next(iter(m.FORENSIC_DATABASES))]['tables'][name].append('d'*64)
        with pytest.raises(m.ProbeRefused,match='ProbePreservationInvalid'):ops._verify_failed(changed)
    source=Path(auth['preserved_artifacts']['sealed_run7_source']['path'])
    files[source]=b'changed-sealed-source'
    with pytest.raises(m.ProbeRefused):ops._verify_preserved_files()


def test_nested_preservation_cannot_be_relabelled_to_an_arbitrary_file(monkeypatch):
    m=module();b=backend();auth,files,original=nested_preservation_fixture(m,b)
    key='prepare_preservation_before';entry=auth['preserved_artifacts'][key]
    wrong=m.PREPARE_ROOT/'attempt'/'unrelated.json'
    files[wrong]=files[Path(entry['path'])];entry['path']=wrong.as_posix()
    ops=m.NativeProbe(auth['candidate_database'],b,None)
    monkeypatch.setattr(m,'_read_private',lambda path,maximum:files[path])
    with pytest.raises(m.ProbeRefused,match='ProbePreservationInvalid'):ops._preservation(auth)


def test_second_invocation_after_prestart_failure_cannot_start_or_login(monkeypatch,tmp_path):
    m=module();b=backend();auth,files,original=nested_preservation_fixture(m,b);calls=[]
    seal={'schema':'keycloak_master_token_source_closure_v1','probe_sha256':'e'*64,
        'backend_sha256':m.BACKEND_SHA256,'helper_sha256':m.HELPER_SHA256}
    monkeypatch.setattr(m,'EXECUTOR_ROOT',tmp_path)
    files[tmp_path/'master-token-probe-authorization.json']=json.dumps(auth).encode()
    files[tmp_path/'master-token-source-closure.json']=json.dumps(seal).encode()
    monkeypatch.setattr(m,'_read_private',lambda path,maximum:files[path])
    def exclusive_receipt(path,value):
        with path.open('x',encoding='utf-8') as stream:json.dump(value,stream)
    monkeypatch.setattr(b,'_write_private',exclusive_receipt)
    def fail_before_start(candidate):calls.append('RuntimeConstructor');raise ValueError('prestart-secret')
    monkeypatch.setattr(b,'PrivateCandidateRuntime',fail_before_start)
    monkeypatch.setattr(m.NativeProbe,'start',lambda self:calls.append('StartForbidden'))
    monkeypatch.setattr(m.NativeProbe,'login_once',lambda self:calls.append('LoginForbidden'))
    pilot=load('tools/keycloak/pilot_acceptance.py','once_fence_pilot')
    first=m.execute_probe(m.NativeProbe(auth['candidate_database'],b,pilot,source_seal=seal))
    assert first['status']=='MasterTokenDiagnosticFailedHold'
    assert (tmp_path/'master-token-probe-consumed.json').is_file()
    second=m.execute_probe(m.NativeProbe(auth['candidate_database'],b,pilot,source_seal=seal))
    assert second['refusal_code']=='ProbeAttemptAlreadyConsumed'
    assert calls==['RuntimeConstructor']
    assert 'prestart-secret' not in json.dumps([first,second])


def runtime_proof():
    return {'candidate_database':'keycloak_recovery_20261027_abcdef12','pid':1234,
        'canonical_pid':9876,'uid_matches_keycloak':True,'http_listener':'127.0.0.1:8089',
        'management_listener':'127.0.0.1:9009','socket_pids':[1234],
        'configuration_sha256_matches':True,'private_distribution_sha256_matches':True,
        'private_data_tmp_logs':True,'jdbc_session_database_matches':True,
        'no_jgroups_sockets':True,'no_proxy_routes':True}


def test_real_session_client_capability_allows_one_realm_get_and_no_writes():
    m=module();b=backend();requests=[]
    ops=m.NativeProbe('keycloak_recovery_20261027_abcdef12',b,None)
    ops.runtime=SimpleNamespace(proof=runtime_proof)
    client=ops.construct_client(token_fixture())
    class Response:
        def __enter__(self):return self
        def __exit__(self,*args):return False
        def read(self,maximum):return b'[{"realm":"master"},{"realm":"sosnadmin"}]'
    def send(request,timeout):requests.append(request);return Response()
    client.opener=SimpleNamespace(open=send)
    ops.realms_once(client)
    assert len(requests)==1 and requests[0].get_method()=='GET'
    assert requests[0].full_url=='http://127.0.0.1:8089/admin/realms'
    with pytest.raises(m.ProbeRefused,match='ProbeRealmGetAlreadyConsumed'):ops.realms_once(client)
    with pytest.raises(m.ProbeRefused):client.request('GET','/admin/realms/master')
    with pytest.raises(b.RecoveryRefused):client.request('PUT','/admin/realms/master',payload={'notBefore':100})
    assert len(requests)==1


def test_prior_build_cleanup_uncertainty_never_becomes_confirmed_by_later_stop():
    m=module();ops=FakeOperations(fail='RuntimeStart')
    ops.safe_code=lambda error:'PrivateBuildCleanupHold'
    result=m.execute_probe(ops)
    assert result['status']=='CleanupUnconfirmedHold'
    assert result['refusal_code']==result['cleanup_code']=='PrivateBuildCleanupHold'


def test_cancellation_unwinds_through_sensitive_clear_and_owned_cleanup():
    m=module();ops=FakeOperations()
    def interrupt():raise KeyboardInterrupt('secret-not-exported')
    ops.login_once=interrupt
    result=m.execute_probe(ops)
    assert ops.calls[-3:]==['ClearSensitive','Cleanup','ResultReceipt']
    assert result['status']=='MasterTokenDiagnosticFailedHold'
    assert 'secret' not in json.dumps(result)


@pytest.mark.parametrize('unsafe',['equal-cutoff','revocation-lowered','too-many','duplicate','bad-realm','noncanonical'])
def test_inventory_reducer_never_bypasses_existing_session_purge_preconditions(unsafe):
    m=module();b=backend();sid='00000000-0000-0000-0000-000000000099'
    value={'realms':['master','sosnadmin'],'fresh_master_session_count':1,'unexpected_offline_flags':0,
        'maximum_restored_token_iat':50,'realm_not_before':{'master':0,'sosnadmin':0},'offline_sessions':[]}
    if unsafe=='equal-cutoff':value['maximum_restored_token_iat']=100
    if unsafe=='revocation-lowered':value['realm_not_before']['master']=101
    if unsafe=='too-many':value['offline_sessions']=[{'realm':'master','id':sid}]*101
    if unsafe=='duplicate':value['offline_sessions']=[{'realm':'master','id':sid}]*2
    if unsafe=='bad-realm':value['offline_sessions']=[{'realm':'outside','id':sid}]
    if unsafe=='noncanonical':value['offline_sessions']=[{'realm':'master','id':sid.replace('-','')}]
    with pytest.raises(b.RecoveryRefused):m.reduce_inventory(b,value,SimpleNamespace(admin_iat=100))
