"""Production FoD transaction, with native commands isolated under PowerShell5.1."""
import ast
import json
import os
from pathlib import Path

import pytest
from pc_agent.platform.windows import support_access_os as fod
from pc_agent.platform.windows import support_access_native as native

_install_with_isolated_powershell = fod.WindowsFOD.install
STOCK_RULE = (Path(__file__).parent/'fixtures'/'openssh-stock-rule.json').read_text(encoding='utf-8')
LOCALIZED_STATUS = 'Правило было успешно проанализировано из хранилища. (65536)'

FIXTURES = r'''
$script:observed=[Collections.Generic.List[string]]::new();$script:rule=$null
$script:mode=$env:FOD_FIXTURE_MODE
$script:stockMode=$script:mode -like 'stock-*'
$script:serverAdded=$false;$script:disables=0;$script:removes=0
$script:filters=$null
function MakeStock {
 $script:filters=ConvertFrom-Json -InputObject $env:FOD_FIXTURE_STOCK_RULE
 $script:rule=[pscustomobject]@{Description=$script:filters.rule.Description;CimInstanceProperties=@(StockProps $script:filters.rule)}
}
function StockProps($section){foreach($p in $section.PSObject.Properties){Prop $p.Name $p.Value}}
function Prop($name,$value){[pscustomobject]@{Name=$name;Value=$value}}
if($script:mode -eq 'stock-existing-rule'){MakeStock}
function Fixture { [pscustomobject]@{CimInstanceProperties=@((Prop 'Stable' 'same'))} }
function MakeRule($description){[pscustomobject]@{Description=$description;CimInstanceProperties=@((Prop 'Description' $description))}}
function Get-CimInstance { [CmdletBinding()]param($ClassName,$Filter)
 if($script:stockMode -and !$script:serverAdded -and $script:mode -ne 'stock-existing-service'){return}
 [pscustomobject]@{Name='sshd';State=$(if($script:mode -in @('foreign_service','stock-running')){'Running'}else{'Stopped'});StartMode=$(if($env:FOD_FIXTURE_MODE -eq 'foreign_service'){'Auto'}else{'Manual'});PathName=$(if($env:FOD_FIXTURE_MODE -eq 'foreign_service'){'C:\Program Files\OpenSSH\sshd.exe'}else{Join-Path ([Environment]::GetFolderPath('System')) 'OpenSSH\sshd.exe'});StartName='LocalSystem';ProcessId=0}
}
function Get-NetFirewallRule {
 [CmdletBinding()]param($PolicyStore,$Name)
 if($script:mode -eq 'stock-race' -and [IO.File]::Exists((Join-Path $env:ENDPOINT_SUPPORT_FOD_ROOT 'normalization-intent.json'))){
  $script:filters.port.LocalPort=@('2222')
 }
 if($script:rule){$script:rule}
}
function Get-WindowsCapability {
 [CmdletBinding()]param([switch]$Online,[string]$Name)
 if(!$Online -or $Name -cne 'OpenSSH.Server~~~~0.0.1.0'){throw 'Unexpected capability query'}
 [pscustomobject]@{Name=$Name;State=$(if($script:serverAdded -and $script:mode -ne 'stock-not-installed'){'Installed'}else{'NotPresent'})}
}
function Test-Path {
 [CmdletBinding()]param([string]$LiteralPath)
 if($LiteralPath -notin @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')){throw 'Unexpected registry query'}
 return ($script:mode -eq 'stock-pending')
}
function Disable-NetFirewallRule {
 [CmdletBinding(SupportsShouldProcess=$true)]param([Parameter(Mandatory=$true)]$InputObject)
 $script:disables++
 if($InputObject -ne $script:rule){throw 'Wrong rule'}
 if(![IO.File]::Exists((Join-Path $env:ENDPOINT_SUPPORT_FOD_ROOT 'normalization-intent.json'))){throw 'Missing durable intent'}
 if($script:mode -eq 'stock-disable-failed'){throw 'Disable failed'}
 ($script:rule.CimInstanceProperties|Where-Object Name -eq 'Enabled').Value=2
 if($script:mode -eq 'stock-postchange'){$script:filters.port.LocalPort=@('2222')}
 if($script:mode -eq 'stock-poststatus'){($script:rule.CimInstanceProperties|Where-Object Name -eq 'Status').Value='Status changed'}
}
function New-NetFirewallRule { [CmdletBinding()]param($PolicyStore,$Name,$DisplayName,$Description,$Enabled,$Direction,$Action,$Profile,$Protocol,$LocalPort,$Program)
 if(![IO.File]::Exists((Join-Path $env:ENDPOINT_SUPPORT_FOD_ROOT 'baseline.json'))){throw 'Missing baseline before reservation'}
 $baseline=ConvertFrom-Json ([IO.File]::ReadAllText((Join-Path $env:ENDPOINT_SUPPORT_FOD_ROOT 'baseline.json')))
 if($null -ne $baseline.rule){throw 'Baseline captured after reservation'}
 $script:rule=MakeRule $Description;$script:rule
}
function Remove-NetFirewallRule { [CmdletBinding()]param([Parameter(ValueFromPipeline=$true)]$InputObject)
 process {$script:removes++;if($script:rule.Description -eq 'foreign'){throw 'Must preserve foreign rule'};$script:rule=$null}
}
function Add-WindowsCapability { [CmdletBinding()]param([switch]$Online,[string]$Name)
 if(!$Online -or $Name -notin @('OpenSSH.Client~~~~0.0.1.0','OpenSSH.Server~~~~0.0.1.0')){throw 'Unexpected capability'}
 $folder=$env:ENDPOINT_SUPPORT_FOD_ROOT
 $baseline=ConvertFrom-Json ([IO.File]::ReadAllText((Join-Path $folder 'baseline.json')))
 if(!$script:stockMode -and ($null -ne $baseline.rule -or !$baseline.service)){throw 'Wrong baseline'}
 if(!$baseline.rule -and ![IO.File]::Exists((Join-Path $folder 'reservation.json'))){throw 'Missing durable reservation'}
 $script:observed.Add($Name)
 if($env:FOD_FIXTURE_MODE -eq 'slow'){
  [IO.File]::WriteAllText((Join-Path $folder 'entered'),[string]$PID)
  while(![IO.File]::Exists((Join-Path $folder 'release'))){[Threading.Thread]::Sleep(50)}
 }
 if($env:FOD_FIXTURE_MODE -in @('foreign','cbs')){$script:rule=MakeRule $(if($env:FOD_FIXTURE_MODE -eq 'cbs'){'OpenSSH Server (sshd)'}else{'foreign'})}
 if($script:stockMode -and ($Name -eq 'OpenSSH.Server~~~~0.0.1.0' -or $script:mode -eq 'stock-client')){
  $script:serverAdded=$Name -eq 'OpenSSH.Server~~~~0.0.1.0';MakeStock
  if($script:mode -eq 'stock-filter'){$script:filters.security.RemoteUsers='foreign'}
  if($script:mode -eq 'stock-shape'){($script:rule.CimInstanceProperties|Where-Object Name -eq 'Profiles').Value=6}
  if($script:mode -eq 'stock-status-code'){($script:rule.CimInstanceProperties|Where-Object Name -eq 'StatusCode').Value=65537}
  if($script:mode -eq 'stock-localized'){($script:rule.CimInstanceProperties|Where-Object Name -eq 'Status').Value=$env:FOD_FIXTURE_LOCALIZED_STATUS}
 }
 if($script:mode -in @('failure','stock-failed')){throw 'fixture servicing failure'}
 [pscustomobject]@{RestartNeeded=($script:mode -in @('reboot','stock-reboot'))}
}
'''
for _name,_section in {'Port':'port','Address':'address','Application':'app','Service':'service',
        'Security':'security','Interface':'interface','InterfaceType':'interface_type'}.items():
    FIXTURES += ('\nfunction Get-NetFirewall'+_name+'Filter { '
        'param([Parameter(ValueFromPipeline=$true)]$InputObject);process { '
        'if($script:filters){[pscustomobject]@{CimInstanceProperties=@(StockProps $script:filters.'+_section+')}}'
        'else{Fixture} } }\n')


def isolated_script(script):
    return FIXTURES+'\n$production={\n'+script+'\n}\n'+r'''
$allowed=@('ConvertFrom-Json','ConvertTo-Json','Get-CimInstance','Select-Object','Sort-Object','Where-Object','Join-Path','ServiceState','Properties','RuleState','Get-NetFirewallRule','New-NetFirewallRule','Remove-NetFirewallRule','Add-WindowsCapability','Get-NetFirewallPortFilter','Get-NetFirewallAddressFilter','Get-NetFirewallApplicationFilter','Get-NetFirewallServiceFilter','Get-NetFirewallSecurityFilter','Get-NetFirewallInterfaceFilter','Get-NetFirewallInterfaceTypeFilter','ProtectFile','Persist','Complete','Get-FileHash','ReadDefaultRule','IsStockRule','RestartPending','ServerIs','NormalizeStockRule','Test-Path','Get-WindowsCapability','Disable-NetFirewallRule')
foreach($command in $production.Ast.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst]},$true)){
 if(!$command.GetCommandName() -or $command.GetCommandName() -notin $allowed){throw 'Unisolated production command'}
}
# File IO stays on the injected temporary root. Constructors cannot introduce
# a native process or an alternate executable through the method whitelist.
foreach($assignment in $production.Ast.FindAll({param($node) $node -is [Management.Automation.Language.AssignmentStatementAst]},$true)){
 $left=$assignment.Left.Extent.Text;$right=$assignment.Right.Extent.Text
 if(($left -eq '$root' -and $right -cne '$env:ENDPOINT_SUPPORT_FOD_ROOT') -or
    ($left -eq '$path' -and $right -cne 'Join-Path $root $name') -or
    ($left -eq '$temporary' -and $right -cne "$"+"path+'.new'")){throw 'Unisolated persistence path'}
}
$methods=@('GetFolderPath','new','SetSecurityDescriptorSddlForm','SetAccessControl','GetBytes','Open','Write','Flush','Dispose','Move','ToLowerInvariant')
foreach($method in $production.Ast.FindAll({param($node) $node -is [Management.Automation.Language.InvokeMemberExpressionAst]},$true)){
 if($method.Member.Value -notin $methods){throw 'Unisolated production method'}
 $receiver=$method.Expression.Extent.Text;$member=$method.Member.Value
 if($member -eq 'new' -and $receiver -notin @('[Security.AccessControl.FileSecurity]','[Text.UTF8Encoding]')){throw 'Unisolated constructor'}
 if($member -in @('Open','Move','SetAccessControl')){
  if($receiver -cne '[IO.File]'){throw 'Unisolated file receiver'}
  $argument=$method.Arguments[0].Extent.Text
  if(($member -eq 'Open' -and $argument -notin @('$temporary',"(Join-Path `$root 'worker.lock')")) -or
     ($member -eq 'Move' -and $argument -cne '$temporary') -or
     ($member -eq 'SetAccessControl' -and $argument -cne '$path')){throw 'Unisolated file target'}
 }

}
& $production
@{names=@($script:observed.ToArray());powershell=$PSVersionTable.PSVersion.ToString();disables=$script:disables;removes=$script:removes}|ConvertTo-Json -Compress
'''


# The AST guard and native doubles are longer than the Windows command line
# limit. Only the fixture reads a temporary script; the product stays inline.
RUN_ISOLATED = '& ([ScriptBlock]::Create([IO.File]::ReadAllText($env:FOD_FIXTURE_SCRIPT)))'


def capture_isolated(runner, script, variables):
    path = Path(variables['ENDPOINT_SUPPORT_FOD_ROOT']).parent/'fixture.ps1'
    path.write_text(isolated_script(script), encoding='utf-8')
    return runner(RUN_ISOLATED, variables=dict(variables,FOD_FIXTURE_SCRIPT=str(path)), timeout=10)


@pytest.fixture
def fixed_ops(tmp_path,monkeypatch):
    # Only this temporary namespace is normalized; no installed Support path.
    real_namespace=native.assert_namespace
    monkeypatch.setattr(native,'assert_namespace',lambda path:None if path.is_relative_to(tmp_path) else real_namespace(path))
    root=tmp_path/'private';native.WindowsSupportOps().protect(root)
    ops=fod.WindowsFOD(root)
    ops._metadata={'schema_version':2,'operation_id':'a'*32,'nonce':'b'*32,
        'boot_id':'boot-before','capabilities':[fod.CAPABILITIES[1]],'state':'servicing'}
    native.atomic_write(ops.path,json.dumps(ops._metadata));native.WindowsSupportOps().protect(ops.path)
    return ops


@pytest.mark.skipif(os.name!='nt',reason='Windows PowerShell5.1 behavior')
@pytest.mark.parametrize('names',[[fod.CAPABILITIES[1]],list(fod.CAPABILITIES)])
@pytest.mark.parametrize('mode,expected',[('normal',(True,False,True)),('failure',(False,False,True)),
    ('reboot',(True,True,True)),('foreign',(True,False,False)),('cbs',(True,False,False)),('foreign_service',(False,False,True))])
def test_fixed_transaction_has_durable_baseline_and_bound_completion(fixed_ops,monkeypatch,names,mode,expected):
    real_runner=fod.run_fixed_powershell;captured=[]
    def execute(script,**kwargs):
        assert kwargs.pop('durable') is True and kwargs.pop('timeout') is None
        root=Path(kwargs['variables']['ENDPOINT_SUPPORT_FOD_ROOT'])
        assert root.parent==fixed_ops.root
        kwargs['variables']['FOD_FIXTURE_MODE']=mode
        result=capture_isolated(real_runner,script,kwargs['variables'])
        captured.append(result)
    monkeypatch.setattr(fod,'run_fixed_powershell',execute)
    fixed_ops._metadata['capabilities']=names
    result=_install_with_isolated_powershell(fixed_ops,names)
    assert captured[0]['powershell'].startswith('5.1.')
    blocked=mode=='foreign_service' and fod.CAPABILITIES[1] in names
    assert captured[0]['names']==([] if blocked else names[:1] if mode=='failure' else names)
    assert result==dict(zip(('completed','restart_needed','boundary_preserved'),expected))
    root=fixed_ops.operation_root(fixed_ops._metadata)
    for name in ('baseline.json','completion.json','worker.lock'):native.assert_private(root/name)
    if blocked:assert not (root/'reservation.json').exists()
    else:native.assert_private(root/'reservation.json')
    baseline=json.loads((root/'baseline.json').read_bytes())
    assert baseline['rule'] is None
    assert json.loads(baseline['service'])['PathName'].lower().endswith('openssh\\sshd.exe')


@pytest.mark.parametrize('names',[[],['foreign'],[[fod.CAPABILITIES[1]]]])
def test_invalid_or_nested_names_never_enter_powershell(monkeypatch,names):
    monkeypatch.setattr(fod,'run_fixed_powershell',lambda *a,**kw:pytest.fail('invalid capability reached PowerShell'))
    with pytest.raises(ValueError,match='support_dependency_install_failed'):
        _install_with_isolated_powershell(object.__new__(fod.WindowsFOD),names)

@pytest.mark.skipif(os.name!='nt',reason='Windows Job semantics')
@pytest.mark.parametrize('breakaway_allowed',[True,False])
def test_durable_worker_survives_nested_caller_jobs_or_fails_before_add(fixed_ops,tmp_path,breakaway_allowed):
    """Terminate the actual caller Job while the production PS witness is in Add."""
    import subprocess
    import sys
    import time
    import win32api,win32con,win32event,win32job,win32process
    tree=ast.parse(Path(fod.__file__).read_text())
    cls=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='WindowsFOD')
    method=next(n for n in cls.body if isinstance(n,ast.FunctionDef) and n.name=='install')
    call=next(n for n in ast.walk(method) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=='run_fixed_powershell')
    script=isolated_script(ast.literal_eval(call.args[0]))
    script_path=tmp_path/'isolated.ps1';script_path.write_text(script)
    root=fixed_ops.operation_root(fixed_ops._metadata)
    metadata=tmp_path/'metadata.json';metadata.write_text(json.dumps(fixed_ops._metadata))
    caller=tmp_path/'caller.py'
    caller.write_text('''import json,sys
sys.path.insert(0,sys.argv[2])
from pathlib import Path
from pc_agent.platform.windows import support_access_os as fod,support_access_native as native
base=Path(sys.argv[1]);metadata=json.loads((base/'metadata.json').read_bytes())
import win32api,win32job
(base/'job-facts').write_text(str(win32job.IsProcessInJob(win32api.GetCurrentProcess(),None))+' '+str(win32job.QueryInformationJobObject(None,win32job.JobObjectExtendedLimitInformation)))
native.assert_namespace=lambda path:None if path.is_relative_to(base) else (_ for _ in ()).throw(ValueError('outside fixture'))
ops=fod.WindowsFOD(base/'private');ops._metadata=metadata
runner=fod.run_fixed_powershell
def execute(script,**kwargs):
 kwargs['variables']['FOD_FIXTURE_MODE']='slow'
 kwargs['variables']['FOD_FIXTURE_SCRIPT']=str(base/'isolated.ps1')
 wrapped="try { & ([ScriptBlock]::Create([IO.File]::ReadAllText($env:FOD_FIXTURE_SCRIPT))) } catch {[IO.File]::WriteAllText((Join-Path $env:ENDPOINT_SUPPORT_FOD_ROOT 'fixture-error'),($_|Out-String));exit 1}"
 return runner(wrapped,**kwargs)
fod.run_fixed_powershell=execute
try:ops.install(metadata['capabilities'])
except Exception as error:(base/'launch-failed').write_text(repr(error))
''')
    jobs=[];process=thread=None
    try:
        for _ in range(2):
            job=win32job.CreateJobObject(None,'Local\\EndpointFODFixture-'+__import__('uuid').uuid4().hex)
            info=win32job.QueryInformationJobObject(job,win32job.JobObjectExtendedLimitInformation)
            info['BasicLimitInformation']['LimitFlags']=win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            if breakaway_allowed:info['BasicLimitInformation']['LimitFlags']|=win32job.JOB_OBJECT_LIMIT_BREAKAWAY_OK
            win32job.SetInformationJobObject(job,win32job.JobObjectExtendedLimitInformation,info)
            jobs.append(job)
        command=subprocess.list2cmdline([sys.executable,str(caller),str(tmp_path),str(Path.cwd())])
        process,thread,_,_=win32process.CreateProcess(None,command,None,None,False,
            win32con.CREATE_SUSPENDED|win32con.CREATE_NO_WINDOW,None,str(Path.cwd()),win32process.STARTUPINFO())
        for job in jobs:win32job.AssignProcessToJobObject(job,process)
        win32process.ResumeThread(thread)
        deadline=time.monotonic()+15
        while not (root/'entered').exists() and not (tmp_path/'launch-failed').exists() and time.monotonic()<deadline:time.sleep(.05)
        if not breakaway_allowed:
            assert (tmp_path/'launch-failed').exists()
            assert not (root/'baseline.json').exists() and not (root/'entered').exists()
            return
        assert (root/'entered').exists(), 'isolated production Add did not start'
        with pytest.raises(ValueError,match='support_dependency_recovery_required'):
            fixed_ops.completed_operation(fixed_ops._metadata)
        win32job.TerminateJobObject(jobs[-1],77)
        assert win32event.WaitForSingleObject(process,5000)==0
        assert not (root/'completion.json').exists()
        (root/'release').touch()
        deadline=time.monotonic()+15
        while not (root/'completion.json').exists() and time.monotonic()<deadline:time.sleep(.05)
        assert fixed_ops.completed_operation(fixed_ops._metadata)=={
            'completed':True,'restart_needed':False,'boundary_preserved':True}
        fixed_ops.capabilities=lambda:{name:'Installed' for name in fod.CAPABILITIES}
        fixed_ops.verify=lambda:{'profile':fod.PROFILE}
        assert fod.ensure_inbox_openssh(fixed_ops)=={'profile':fod.PROFILE}
        assert fixed_ops.read_receipt()['state']=='complete'
    finally:
        if root.exists():(root/'release').touch()
        if thread:win32api.CloseHandle(thread)
        if process:win32api.CloseHandle(process)
        for job in reversed(jobs):win32api.CloseHandle(job)


@pytest.mark.skipif(os.name!='nt',reason='Windows PowerShell5.1 behavior')
@pytest.mark.parametrize('mode,disabled,preserved',[
    ('stock-exact',1,True),('stock-localized',1,True),('stock-status-code',0,False),
    ('stock-filter',0,False),('stock-shape',0,False),('stock-poststatus',1,False),
    ('stock-race',0,False),('stock-disable-failed',1,False),('stock-postchange',1,False),
    ('stock-reboot',0,False),('stock-pending',0,False),('stock-failed',0,False),
    ('stock-not-installed',0,False),('stock-existing-service',0,False),
    ('stock-existing-rule',0,True),('stock-running',0,False),('stock-client',0,False),
])
def test_only_exact_new_stock_rule_is_disabled(fixed_ops,monkeypatch,mode,disabled,preserved):
    real_runner=fod.run_fixed_powershell
    captured=[]
    def execute(script,**kwargs):
        variables=kwargs['variables']
        assert Path(variables['ENDPOINT_SUPPORT_FOD_ROOT']).parent==fixed_ops.root
        variables.update(FOD_FIXTURE_MODE=mode,FOD_FIXTURE_STOCK_RULE=STOCK_RULE,
            FOD_FIXTURE_LOCALIZED_STATUS=LOCALIZED_STATUS)
        captured.append(capture_isolated(real_runner,script,variables))
    monkeypatch.setattr(fod,'run_fixed_powershell',execute)
    names=[fod.CAPABILITIES[0 if mode=='stock-client' else 1]]
    fixed_ops._metadata['capabilities']=names
    result=_install_with_isolated_powershell(fixed_ops,names)
    assert captured[0]['disables']==disabled
    assert captured[0]['removes']==0
    assert result['boundary_preserved'] is preserved
    root=fixed_ops.operation_root(fixed_ops._metadata)
    intent=root/'normalization-intent.json'
    proof=root/'normalization-proof.json'
    if preserved and disabled:
        import hashlib
        for path in (intent,proof):native.assert_private(path)
        before=json.loads(intent.read_bytes())
        after=json.loads(proof.read_bytes())
        completion=json.loads((root/'completion.json').read_bytes())
        assert before['baseline_sha256']==hashlib.sha256((root/'baseline.json').read_bytes()).hexdigest()
        assert after['intent_sha256']==hashlib.sha256(intent.read_bytes()).hexdigest()
        assert completion['normalization_sha256']==hashlib.sha256(proof.read_bytes()).hexdigest()
        original=json.loads(STOCK_RULE)
        if mode=='stock-localized':original['rule']['Status']=LOCALIZED_STATUS
        assert json.loads(before['rule'])==original
        original['rule']['Enabled']=2
        assert json.loads(after['rule'])==original
        proof.unlink()
        with pytest.raises(ValueError,match='support_dependency_recovery_required'):
            fixed_ops.completed_operation(fixed_ops._metadata)
        original['port']['LocalPort']=['2222']
        after['rule']=json.dumps(original)
        proof.write_bytes(json.dumps(after).encode())
        completion['normalization_sha256']=hashlib.sha256(proof.read_bytes()).hexdigest()
        (root/'completion.json').write_bytes(json.dumps(completion).encode())
        with pytest.raises(ValueError,match='support_dependency_recovery_required'):
            fixed_ops.completed_operation(fixed_ops._metadata)
    else:
        assert not proof.exists()
        assert intent.exists() is (mode in {'stock-race','stock-disable-failed','stock-postchange','stock-poststatus'})
