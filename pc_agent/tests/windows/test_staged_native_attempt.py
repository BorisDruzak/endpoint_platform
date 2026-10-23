"""A prior reboot can never settle a new, interrupted native attempt."""
from uuid import uuid4

import pytest
from pc_agent.platform.windows import durable_state, staged_recovery as module
from pc_agent.tests.windows.test_staged_recovery import recovery
from pc_agent.tests.windows.test_staged_update_state import staged, move, native_protected_root


@pytest.fixture
def attempt(recovery, staged, monkeypatch):
    from pc_agent.platform.windows import staged_boot_marker as marker
    _, paths, binding, cap = recovery
    move(staged,'preparing','prepared');move(staged,'prepared','switching')
    with durable_state.installer_mutation_checkpoints(lambda:None):
        module._root(paths,binding.operation_id,create=True)
    tokens={}
    def capture(_):
        token='registry-boot-v1:'+str(uuid4());tokens[token]=True;return token
    original=capture(None)
    monkeypatch.setattr(module,'_validate_recovery_inputs',lambda *_:{'boot':original})
    monkeypatch.setattr(marker,'capture',capture)
    monkeypatch.setattr(marker,'present',lambda _,token:tokens[token])
    return paths,binding,cap,tokens,original


def test_pending_attempt_blocks_trial_and_owner_loss_requests_rollback(attempt):
    paths,binding,cap,tokens,original=attempt
    tokens[original]=False  # A real boot already satisfied the original input.
    with durable_state.installer_mutation_checkpoints(lambda:None):
        module.begin_native_attempt(paths,binding.operation_id,cap['owner'])
        assert module.reboot_pending(paths,module.state.read_staged_update(paths))
        assert module.recover_staged_update(paths,binding.operation_id,capability=cap)=='rollback-required'


@pytest.mark.parametrize('exit_code',[3010,1641])
def test_reboot_result_uses_marker_bound_before_native_launch(attempt,exit_code):
    paths,binding,cap,tokens,original=attempt
    tokens[original]=False
    with durable_state.installer_mutation_checkpoints(lambda:None):
        module.begin_native_attempt(paths,binding.operation_id,cap['owner'])
        pending=module._native_attempt(paths,module.state.read_staged_update(paths))
        module.finish_native_attempt(paths,binding.operation_id,exit_code,cap['owner'])
        assert module._native_attempt(paths,module.state.read_staged_update(paths))['boot']==pending['boot']
        assert module.reboot_pending(paths,module.state.read_staged_update(paths))
        tokens[pending['boot']]=False
        assert not module.reboot_pending(paths,module.state.read_staged_update(paths))


@pytest.mark.parametrize('boundary',['before-capture','before-publication','after-publication'])
def test_new_attempt_cannot_inherit_satisfied_reboot_on_owner_loss(attempt,monkeypatch,boundary):
    paths,binding,cap,tokens,_=attempt
    from pc_agent.platform.windows import staged_boot_marker as marker
    with durable_state.installer_mutation_checkpoints(lambda:None):
        module.begin_native_attempt(paths,binding.operation_id,cap['owner'])
        module.finish_native_attempt(paths,binding.operation_id,3010,cap['owner'])
        old=module._native_attempt(paths,module.state.read_staged_update(paths));tokens[old['boot']]=False
        def die(*_a,**_k):raise ValueError('owner lost')
        if boundary=='before-capture':monkeypatch.setattr(marker,'capture',die)
        elif boundary=='before-publication':monkeypatch.setattr(module,'_write',die)
        if boundary!='after-publication':
            with pytest.raises(ValueError,match='owner lost'):
                module.begin_native_attempt(paths,binding.operation_id,cap['owner'])
            # Failure prevents the owner wrapper from launching native work.
            assert module._native_attempt(paths,module.state.read_staged_update(paths))==old
        else:
            module.begin_native_attempt(paths,binding.operation_id,cap['owner'])
            assert module.reboot_pending(paths,module.state.read_staged_update(paths))


def test_success_cannot_resolve_other_owners_or_unsettled_native(attempt,monkeypatch):
    paths,binding,cap,_,_=attempt
    with durable_state.installer_mutation_checkpoints(lambda:None):
        module.begin_native_attempt(paths,binding.operation_id,cap['owner'])
        with pytest.raises(ValueError):
            module.finish_native_attempt(paths,binding.operation_id,0,{**cap['owner'],'pid':999})
        monkeypatch.setattr(module,'_native_settled',lambda *_:False)
        with pytest.raises(ValueError):module.finish_native_attempt(paths,binding.operation_id,0,cap['owner'])


def test_zero_result_needs_exact_native_release_and_atomic_outcome(attempt,monkeypatch):
    paths,binding,cap,_,_=attempt
    with durable_state.installer_mutation_checkpoints(lambda:None):
        module.begin_native_attempt(paths,binding.operation_id,cap['owner'])
        monkeypatch.setattr(module.provenance,'verified_foundation_release',lambda *_:{})
        with pytest.raises(ValueError):module.finish_native_attempt(paths,binding.operation_id,0,cap['owner'])
        monkeypatch.setattr(module.provenance,'verified_foundation_release',lambda *_:binding.new_release)
        original=module._write
        def die(*_a,**_k):raise ValueError('owner lost before outcome publication')
        monkeypatch.setattr(module,'_write',die)
        with pytest.raises(ValueError):module.finish_native_attempt(paths,binding.operation_id,0,cap['owner'])
        assert module.reboot_pending(paths,module.state.read_staged_update(paths))
        monkeypatch.setattr(module,'_write',original)
        module.finish_native_attempt(paths,binding.operation_id,0,cap['owner'])
        assert not module.reboot_pending(paths,module.state.read_staged_update(paths))


@pytest.mark.skipif(__import__('os').name!='nt',reason='actual owner control flow and compiled policy')
def test_owner_requires_pending_publication_before_launch_and_settlement_before_success(tmp_path):
    import subprocess
    from pathlib import Path
    source=Path(__file__).resolve().parents[3]/'packaging/windows/Install-EndpointAgentCanary.ps1'
    script=tmp_path/'native-gate.ps1'
    script.write_text(r'''param($Source)
$ErrorActionPreference='Stop';$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'owner parse failure'}
$init=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Initialize-InstallerBridgeTypes'},$true)
Invoke-Expression $init.Extent.Text;Initialize-InstallerBridgeTypes
$owner=[EndpointInstallerBridge.Identity]::new(100,1000,('a'*64),'S-1-5-18',$true)
$policy=[EndpointInstallerBridge.Policy]::new('11111111-1111-4111-8111-111111111111','22222222-2222-4222-8222-222222222222',('c'*64),'install',$owner,('b'*64),[byte[]](1..32))
$policy.MarkQuiescent()
$peer=[EndpointInstallerBridge.Identity]::new(200,2000,('b'*64),'S-1-5-18',$true)
$policy.RegisterHelper($peer,'record-staged-native-start')
$denied=$false;try{$policy.RegisterHelper([EndpointInstallerBridge.Identity]::new(201,2001,('b'*64),'S-1-5-18',$true),'record-staged-native-success')}catch{$denied=$true}
if(!$denied){throw 'success admitted without actual native settlement'}
$gate=$ast.Find({param($n)$n -is [Management.Automation.Language.IfStatementAst] -and $n.Extent.Text.StartsWith('if($stagedOnline -or $null -ne $stagedRecoveryObserved)')},$true)
if(!$gate){throw 'pending launch barrier missing'}
$sourceText=[IO.File]::ReadAllText($Source)
$native=$sourceText.IndexOf("`n    Start-WindowsInstaller`n    if",$gate.Extent.EndOffset)
if($native -lt $gate.Extent.EndOffset){throw 'pending barrier does not precede native launch'}
$stagedOnline=$true;$stagedRecoveryObserved=$null;$bridge=[pscustomobject]@{TransactionId='33333333-3333-4333-8333-333333333333'}
$fakePolicy=New-Object psobject;$fakePolicy|Add-Member ScriptMethod MarkQuiescent {}
$script:fakeBridge=[pscustomobject]@{Policy=$fakePolicy}
function New-InstallerBridge {return $script:fakeBridge}
function Invoke-InstallerHelper {if($script:failPublication){throw 'publication failed'};return @{operation_id=$bridge.TransactionId;result='native-attempt-unresolved'}}
$script:failPublication=$true;$script:launches=0
try{& ([scriptblock]::Create($gate.Extent.Text));$script:launches++}catch{}
if($script:launches -ne 0){throw 'native launched after gate publication failure'}
$script:failPublication=$false
& ([scriptblock]::Create($gate.Extent.Text));$script:launches++
if($script:launches -ne 1){throw 'published attempt cannot proceed'}
'passed'
''',encoding='utf-8')
    result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-File',str(script),str(source)],capture_output=True,text=True,timeout=30)
    assert result.returncode==0,result.stderr
    assert result.stdout.strip()=='passed'
