"""Run the immutable predecessor's authenticated inspection before quarantine."""
import os
from pathlib import Path
import subprocess

import pytest


@pytest.mark.skipif(os.name != 'nt', reason='actual PowerShell orchestration')
@pytest.mark.parametrize('defect', ['none', 'selector', 'previous', 'release', 'restart', 'helper'])
def test_online_predecessor_inspection_preserves_admission_and_revokes(tmp_path, defect):
    source = Path(__file__).resolve().parents[3] / 'packaging/windows/Install-EndpointAgentCanary.ps1'
    script = tmp_path / 'predecessor-inspection.ps1'
    script.write_text(r'''param($Source,$Defect)
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
$node=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Inspect-StagedPredecessorOnline'},$true)
if(!$node){throw 'online predecessor inspection missing'}
Invoke-Expression $node.Extent.Text
$script:events=[Collections.Generic.List[string]]::new()
$resource=[pscustomobject]@{}
$resource|Add-Member ScriptMethod Dispose {$script:events.Add('dispose')}
$policy=[pscustomobject]@{}
$policy|Add-Member ScriptMethod MarkQuiescent {throw 'native authority during online inspection'}
$policy|Add-Member ScriptMethod OwnerLost {$script:events.Add('revoke')}
function Get-StagedAgentObservation {
 if($Defect -ceq 'restart' -and $script:events.Contains('inspect')){return 'changed'}
 return 'original'
}
function New-InstallerBridge {
 param($Manifest,$HelperPath,$HelperHash,$StateRoot,$ServiceStates,$Intent,$Selection)
 if($Intent -cne 'install' -or $Manifest.package_sha256 -cne ('a'*64)){throw 'wrong package admission'}
 return @{Policy=$policy;Channel=$resource;Owner=$resource;Peers=@($resource)}
}
function Invoke-InstallerHelper {
 param($Bridge,$Phase)
 if($Phase -cne 'inspect'){throw 'mutation instead of inspection'}
 $script:events.Add('inspect')
 if($Defect -ceq 'helper'){throw 'helper failed'}
 $selected=if($Defect -ceq 'selector'){'bad'}else{'selected'}
 $previous=if($Defect -ceq 'previous'){'bad'}else{$null}
 $release=if($Defect -ceq 'release'){@{package_sha256=('b'*64)}}else{@{package_sha256=('a'*64)}}
 return [pscustomobject]@{selected=$selected;previous=$previous;foundation_release=$release}
}
function Stop-ManagedAgentServices {throw 'service stop during preparation'}
$denied=$false
try{Inspect-StagedPredecessorOnline -Manifest @{package_sha256=('a'*64)} -HelperPath 'helper' -HelperHash ('c'*64) -StateRoot 'state' -ServiceStates @{} -Selection ([pscustomobject]@{selected='selected';previous=$null})}catch{$denied=$true}
if($denied -ne ($Defect -cne 'none')){throw 'wrong inspection verdict'}
if([string]::Join(',', $script:events) -cne 'inspect,revoke,dispose,dispose,dispose'){throw 'authority not revoked exactly once'}
'passed'
''', encoding='utf-8')
    result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-File', str(script), str(source), defect],
                            capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'passed'


def test_inspection_precedes_service_quarantine_and_keeps_late_prepare():
    source = (Path(__file__).resolve().parents[3] / 'packaging/windows/Install-EndpointAgentCanary.ps1').read_text()
    start = source.index('        $bridge=Invoke-StagedOnlinePreparation')
    main = source[start:]
    assert main.index('Inspect-StagedPredecessorOnline -Manifest') < main.index('Stop-ManagedAgentServices')
    # Immutable predecessor admission still repeats after service quarantine.
    assert main.index('Stop-ManagedAgentServices') < main.index("Invoke-InstallerHelper $oldBridge 'prepare'")
