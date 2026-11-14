"""Windows PowerShell 5.1 launches and reaps a read-only preflight tree."""

import os
from pathlib import Path
import subprocess

import pytest


SCRIPT = Path(__file__).resolve().parents[2] / "packaging/windows/EndpointSetupUpdater.ps1"


@pytest.mark.skipif(os.name != "nt", reason="Windows jobs and anonymous pipes")
def test_repeated_preflight_failure_reaps_children_and_bounds_output(tmp_path):
    harness = tmp_path / "preflight-harness.ps1"
    harness.write_text(r"""
param($Script, $Root)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$errors = $null
$tokens = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($Script,[ref]$tokens,[ref]$errors)
if($errors.Count){ throw 'Setup client syntax error' }
foreach($name in @('Initialize-SetupPreflightProcess','Read-SetupPreflight')){
 $function = $ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name},$true)
 Invoke-Expression $function.Extent.Text
}
Initialize-SetupPreflightProcess
$image = Join-Path $Root 'test preflight.exe'
Add-Type -OutputType ConsoleApplication -OutputAssembly $image -TypeDefinition @'
using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Threading;
public static class PreflightFixture {
 public static void Main(string[] args) {
  if(args[0]=="child"){Thread.Sleep(60000);return;}
  if(args[0]!="--preflight" || args[1]!="--quiet")Environment.Exit(2);
  string mode=Environment.GetEnvironmentVariable("ENDPOINT_TEST_PREFLIGHT");
  if(mode=="ok"){Console.Write("{\"ready\":true}");return;}
  string exe=Assembly.GetExecutingAssembly().Location;
  using(var child=Process.Start(new ProcessStartInfo(exe,"child"){UseShellExecute=false,CreateNoWindow=true})) {
   File.WriteAllText(exe+".pids",Process.GetCurrentProcess().Id+":"+child.Id);
  }
  if(mode=="descendant")return;
  if(mode=="stdout")Console.Write(new string('x',65536));
  if(mode=="stderr")Console.Error.Write(new string('x',65536));
  Thread.Sleep(60000);
 }
}
'@
$env:ENDPOINT_TEST_PREFLIGHT = 'ok'
if(!(Read-SetupPreflight $image).ready){throw 'Valid preflight result missing'}
foreach($case in @('hang','descendant','stdout','stderr','hang','stdout')){
 $env:ENDPOINT_TEST_PREFLIGHT = $case
 Remove-Item -LiteralPath ($image+'.pids') -ErrorAction SilentlyContinue
 $clock = [Diagnostics.Stopwatch]::StartNew()
 $observed = $null
 try{ [void][EndpointSetupPreflightProcess]::Run($image,1200) }
 catch{ $observed = $_.Exception.GetBaseException().Message }
 $expected = if($case -in @('hang','descendant')){'preflight_observation_expired'}else{'preflight_unavailable'}
 if($observed -cne $expected -or $clock.ElapsedMilliseconds -gt 6000){throw "Unexpected result for $case : $observed"}
 foreach($pidText in [IO.File]::ReadAllText($image+'.pids').Split(':')){
  $child = Get-Process -Id ([int]$pidText) -ErrorAction SilentlyContinue
  if($child){
   try{if(!$child.WaitForExit(1000)){throw "Leaked process $pidText for $case"}}
   finally{$child.Dispose()}
  }
 }
}
""", encoding="ascii")
    powershell = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    completed = subprocess.run(
        [str(powershell), "-NoProfile", "-NonInteractive", "-File", str(harness), str(SCRIPT), str(tmp_path)],
        capture_output=True, text=True, timeout=40,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
