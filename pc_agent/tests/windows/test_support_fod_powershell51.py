"""Exercise the actual fixed FoD script with Windows PowerShell's real binder.

Every servicing/firewall/service command is replaced before the production
script runs. No installed Windows capability, service or rule is changed.
"""
import os

import pytest

from pc_agent.platform.windows import support_access_os as fod

# The autouse guard forbids uninjected servicing. This test supplies the entire
# isolated PowerShell boundary below, without weakening that guard elsewhere.
_install_with_isolated_powershell = fod.WindowsFOD.install


@pytest.mark.skipif(os.name != 'nt', reason='Windows PowerShell5.1 behavior')
@pytest.mark.parametrize('names', [[fod.CAPABILITIES[1]], list(fod.CAPABILITIES)])
def test_fixed_servicing_passes_each_flat_name_to_the_string_parameter(monkeypatch, names):
    real_runner = fod.run_fixed_powershell
    fixtures = r'''
$script:observed=[Collections.Generic.List[string]]::new()
function Fixture { [pscustomobject]@{CimInstanceProperties=@([pscustomobject]@{Name='Stable';Value='same'})} }
function Get-CimInstance { [CmdletBinding()]param($ClassName,$Filter)
 [pscustomobject]@{Name='sshd';State='Stopped';StartMode='Manual';PathName='fixed';StartName='LocalSystem';ProcessId=0}
}
function Get-NetFirewallRule { [CmdletBinding()]param($PolicyStore,$Name);Fixture }
function New-NetFirewallRule {throw 'Unexpected firewall mutation'}
function Remove-NetFirewallRule {throw 'Unexpected firewall mutation'}
function Add-WindowsCapability { [CmdletBinding()]param([switch]$Online,[string]$Name)
 if(!$Online -or $Name -notin @('OpenSSH.Client~~~~0.0.1.0','OpenSSH.Server~~~~0.0.1.0')){throw 'Unexpected capability'}
 $script:observed.Add($Name);[pscustomobject]@{RestartNeeded=$false}
}
'''
    for name in ('Port', 'Address', 'Application', 'Service', 'Security', 'Interface', 'InterfaceType'):
        fixtures += ('\nfunction Get-NetFirewall'+name+'Filter { '
            'param([Parameter(ValueFromPipeline=$true)]$InputObject);process { Fixture } }\n')
    captured = []
    def execute(script, **kwargs):
        wrapped = fixtures+'\n$production={\n'+script+'\n}\n'+r'''
$allowed=@('ConvertFrom-Json','ConvertTo-Json','Get-CimInstance','Select-Object','Sort-Object','Where-Object','Join-Path','ServiceState','Properties','RuleState','Get-NetFirewallRule','New-NetFirewallRule','Remove-NetFirewallRule','Add-WindowsCapability','Get-NetFirewallPortFilter','Get-NetFirewallAddressFilter','Get-NetFirewallApplicationFilter','Get-NetFirewallServiceFilter','Get-NetFirewallSecurityFilter','Get-NetFirewallInterfaceFilter','Get-NetFirewallInterfaceTypeFilter')
foreach($command in $production.Ast.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst]},$true)){
 if(!$command.GetCommandName() -or $command.GetCommandName() -notin $allowed){throw 'Unisolated production command'}
}
foreach($method in $production.Ast.FindAll({param($node) $node -is [Management.Automation.Language.InvokeMemberExpressionAst]},$true)){
 if($method.Member.Value -ne 'GetFolderPath'){throw 'Unisolated production method'}
}
$captured=& $production
@{result=($captured|ConvertFrom-Json);names=@($script:observed.ToArray());powershell=$PSVersionTable.PSVersion.ToString()}|ConvertTo-Json -Depth 8 -Compress
'''
        result = real_runner(wrapped, **kwargs)
        captured.append(result)
        return result['result']
    monkeypatch.setattr(fod, 'run_fixed_powershell', execute)
    ops = object.__new__(fod.WindowsFOD)
    ops._metadata = {'operation_id':'a'*32}
    result = _install_with_isolated_powershell(ops, names)
    assert captured[0]['powershell'].startswith('5.1.')
    assert result == {'completed':True, 'restart_needed':False, 'boundary_preserved':True}
    assert captured[0]['names'] == names


@pytest.mark.parametrize('names', [[], ['foreign'], [[fod.CAPABILITIES[1]]]])
def test_invalid_or_nested_names_never_enter_powershell(monkeypatch, names):
    monkeypatch.setattr(fod, 'run_fixed_powershell',
        lambda *a, **kw:pytest.fail('invalid capability reached PowerShell'))
    with pytest.raises(ValueError, match='support_dependency_install_failed'):
        _install_with_isolated_powershell(object.__new__(fod.WindowsFOD), names)
