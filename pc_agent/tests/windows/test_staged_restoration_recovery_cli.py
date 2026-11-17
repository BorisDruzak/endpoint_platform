"""New signed-code restoration recovery is distinct from old generic recovery."""
from types import SimpleNamespace
import sys
import pytest

TARGET='11111111-1111-4111-8111-111111111111'
FRESH='22222222-2222-4222-8222-222222222222'
PHASE='finalize-staged-restoration-continuation'


def test_setup_cli_dispatches_restoration_without_install(monkeypatch):
    from pc_agent.platform.windows import setup_entry as setup
    calls=[]
    monkeypatch.setattr(setup,'_run_staged_restoration_recovery',lambda target:calls.append(target) or 0,raising=False)
    assert setup.main(['--recover-staged-restoration',TARGET])==0
    assert calls==[TARGET]


@pytest.mark.parametrize('failure',[False,True])
def test_restoration_phase_dispatches_target_not_fresh_namespace(monkeypatch,failure):
    from pc_agent.platform.windows import installer_transaction_bridge as bridge,durable_state
    calls=[]
    def finalize(client,paths,target):
        durable_state.installer_mutation_checkpoint(required=True)
        calls.append(target)
        if failure:raise ValueError('proof failed')
        return {'result':'restored'}
    monkeypatch.setitem(sys.modules,'pc_agent.platform.windows.staged_restoration_continuation',
        SimpleNamespace(finalize_restoration_continuation=finalize))
    client=SimpleNamespace(phase=PHASE,capability={'transaction_id':FRESH,'restoration_transaction_id':TARGET},
        checkpoint=lambda:calls.append('checkpoint'),request=lambda action,result:calls.append((action,result)))
    if failure:
        with pytest.raises(ValueError,match='proof failed'):bridge.execute_authorized_phase(client,object())
        assert calls==['checkpoint',TARGET]
    else:
        assert bridge.execute_authorized_phase(client,object())=={'result':'restored'}
        assert calls==['checkpoint',TARGET,('complete',{'result':'restored'})]


def test_unfrozen_restoration_cannot_launch_owner(monkeypatch):
    from pc_agent.platform.windows import setup_entry as setup
    monkeypatch.setattr(setup.sys,'frozen',False,raising=False)
    monkeypatch.setattr(setup.subprocess,'run',lambda *args,**kwargs:pytest.fail('unfrozen recovery launched'))
    assert setup._run_staged_restoration_recovery(TARGET)==setup.EXIT_REPAIR_REQUIRED


def test_target_capability_cannot_enter_generic_phases():
    from pc_agent.platform.windows import installer_transaction_bridge as bridge
    client=SimpleNamespace(phase='recover-native-continuation',capability={'restoration_transaction_id':TARGET})
    with pytest.raises(ValueError,match='OWNER_AUTH_FAILED'):
        bridge.execute_authorized_phase(client,object())


def test_actual_owner_requires_genuine_settlement_for_restoration(tmp_path):
    import subprocess
    from pathlib import Path
    source=Path(__file__).resolve().parents[3]/'packaging/windows/Install-EndpointAgentCanary.ps1'
    script=tmp_path/'restoration-policy.ps1'
    script.write_text(r'''param($Source)
$ErrorActionPreference='Stop';$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'parse failure'}
$node=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Initialize-InstallerBridgeTypes'},$true)
Invoke-Expression $node.Extent.Text;Initialize-InstallerBridgeTypes
$owner=[EndpointInstallerBridge.NativeProcess]::new($PID)
try {
 $peer=[EndpointInstallerBridge.Identity]::new(200,2000,('b'*64),'S-1-5-18',$true)
 foreach($authorized in @($false,$true)) {
  $p=[EndpointInstallerBridge.Policy]::new('11111111-1111-4111-8111-111111111111','22222222-2222-4222-8222-222222222222',('c'*64),'install',$owner.Identity,('b'*64),[byte[]](1..32))
  $p.MarkQuiescent()
  if($authorized){$proof=[EndpointInstallerBridge.NativeTransaction]::EstablishSettlement($owner);$p.AuthorizeStagedRecovery($proof)}
  $accepted=$true
  try{$p.RegisterHelper($peer,'finalize-staged-restoration-continuation')}catch{$accepted=$false}
  if($accepted -ne $authorized){throw 'restoration settlement gate mismatch'}
 }
} finally {$owner.Dispose()}
'passed'
''')
    result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-File',str(script),str(source)],capture_output=True,text=True,timeout=30)
    assert result.returncode==0,result.stderr
    assert result.stdout.strip()=='passed'


from pc_agent.tests.windows.test_installer_fence import native_protected_root


@pytest.mark.parametrize('change',[None,'same-id','administrator','recovery','uninstall','combined-extra'])
def test_protected_restoration_capability_scope(native_protected_root,change):
    import json
    from uuid import uuid4
    from pc_agent.platform.windows import installer_transaction_bridge as bridge,installer_fence as fence
    from pc_agent.platform.windows.update_paths import WindowsUpdatePaths
    paths=WindowsUpdatePaths(native_protected_root/'Agent',native_protected_root/'data/updates/pending_update.json')
    root=fence.state_root(paths);root.mkdir();fence.protect_state(root)
    caps=root/'capabilities';caps.mkdir();fence.protect_state(caps,secret=True)
    session=str(uuid4())
    cap={'schema_version':1,'transaction_id':FRESH,'session_id':session,
         'package':{'schema_version':1,'package_sha256':'a'*64,'product_code':'{11111111-1111-4111-8111-111111111111}',
                    'version':'3.2.174','source_revision':'b'*40,'initial_runtime_tree_sha256':'c'*64},
         'operation':'install','pipe_name':'EndpointInstaller-'+session+'-'+('d'*32),
         'owner':{'pid':1,'created':1,'hash':'e'*64,'sid':'S-1-5-18','elevated':True},
         'helper_sha256':'f'*64,'secret':'a'*64,'selected':None,'previous':None,
         'service_states':{'EndpointAgent':'running','EndpointAgentUpdater':'stopped'},
         'recovery':False,'uninstall_finalization':False,'restoration_transaction_id':TARGET}
    if change=='same-id':cap['transaction_id']=TARGET
    if change=='administrator':cap['owner']['sid']='S-1-5-32-544'
    if change=='recovery':cap['recovery']=True
    if change=='uninstall':cap['operation']='uninstall'
    if change=='combined-extra':cap['recovery_parent']=str(uuid4())
    path=caps/(session+'.json');path.write_text(json.dumps(cap));fence.protect_state(path,secret=True)
    if change:
        with pytest.raises(ValueError,match='OWNER_AUTH_FAILED'):bridge._read_capability(paths,session)
    else:assert bridge._read_capability(paths,session)==cap


from pc_agent.tests.windows.test_staged_restoration_continuation import restored,finalizer,staged


@pytest.mark.parametrize('failure',[False,True])
def test_real_finalizer_dispatch_owns_checkpoints_and_single_ack(finalizer,failure):
    from pc_agent.platform.windows import installer_transaction_bridge as bridge,native_setup_continuation as continuation
    module,r=finalizer
    acks=[]
    def request(action,result):
        assert continuation.pending_continuation(r.paths) is None
        acks.append((action,result))
    r.client.request=request
    if failure:r.paths.previous_path.write_bytes(b'unproven previous selector')
    # Deliberately no preinstalled mutation-checkpoint context: real installer
    # entrypoint delegates ownership of this scope to the new dispatch phase.
    if failure:
        with pytest.raises(ValueError):bridge.execute_authorized_phase(r.client,r.paths)
        assert acks==[] and continuation.pending_continuation(r.paths) is not None
    else:
        result=bridge.execute_authorized_phase(r.client,r.paths)
        assert result['operation_id']==r.target
        assert acks==[('complete',result)] and r.calls.count('checkpoint')>0
