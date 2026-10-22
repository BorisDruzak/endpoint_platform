"""Prepare old immutable media online and retain actual deny-write/delete pins."""
import os
from pathlib import Path
import subprocess

import pytest


@pytest.mark.skipif(os.name != 'nt', reason='actual Windows file sharing and PowerShell')
@pytest.mark.parametrize('fail_guard', [False, True])
def test_preloaded_media_retains_pins_or_releases_them_on_error(tmp_path, fail_guard):
    source = Path(__file__).resolve().parents[2] / 'packaging/windows/Install-EndpointAgentCanary.ps1'
    script = tmp_path / 'preload.ps1'
    script.write_text(r'''param($Source,$Root,[int]$FailGuard)
$ErrorActionPreference='Stop';$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
$node=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Open-StagedPredecessorMedia'},$true)
if($null -eq $node){throw 'MEDIA_PRELOAD_MISSING'};Invoke-Expression $node.Extent.Text
Add-Type -TypeDefinition @'
using System.IO;
namespace EndpointInstallerBridge { public static class PackageHelper {
 public static string Extract(string package,string target) { File.WriteAllBytes(target,new byte[]{1,2,3});return new string('b',64); }
} }
'@
$script:msi=Join-Path $Root 'EndpointAgent.msi';[IO.File]::WriteAllBytes($script:msi,[byte[]](4,5,6))
function Get-CompoundOldMedia {param($Manifest,$StateRoot,$CacheRoot)return $script:msi}
function Assert-CacheArtifactProtection {param($Path)if($FailGuard){throw 'guard failed'}}
$manifest=@{package_sha256=('a'*64)};$value=$null;$failed=$false
try{$value=Open-StagedPredecessorMedia $manifest $Root $Root}catch{$failed=$true}
if($failed -ne [bool]$FailGuard){throw 'wrong preload verdict'}
if($FailGuard){[IO.File]::WriteAllBytes($script:msi,[byte[]](7));'passed';exit 0}
try{
 if($value.PackageHash -cne $manifest.package_sha256 -or $value.HelperHash -cne ('b'*64)){throw 'binding lost'}
 foreach($path in @($value.PackagePath,$value.HelperPath)){
  $denied=$false;try{[IO.File]::WriteAllBytes($path,[byte[]](9))}catch{$denied=$true};if(-not $denied){throw 'write pin absent'}
  $denied=$false;try{[IO.File]::Delete($path)}catch{$denied=$true};if(-not $denied){throw 'delete pin absent'}
 }
}finally{$value.HelperPin.Dispose();$value.PackagePin.Dispose()}
[IO.File]::WriteAllBytes($script:msi,[byte[]](7));'passed'
''', encoding='utf-8')
    result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-File', str(script), str(source), str(tmp_path), str(int(fail_guard))],
                            capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'passed'
