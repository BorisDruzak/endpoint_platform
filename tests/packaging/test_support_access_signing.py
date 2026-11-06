"""Execute release-signing decisions; do not sign or install real artifacts."""
from pathlib import Path
import subprocess
import json

ROOT=Path(__file__).resolve().parents[2]


def test_existing_valid_support_signature_is_preserved_without_resigning(tmp_path):
    script=tmp_path/'signature.ps1'
    script.write_text(r'''param($Source)
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw $errors[0]}
foreach($node in $ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst]},$true)){Invoke-Expression $node.Extent.Text}
$global:resigned=0
function Get-AuthenticodeSignature {param($LiteralPath) @{Status='Valid';TimeStamperCertificate=@{};SignerCertificate=@{Thumbprint=('a'*40)}}}
function Set-AuthenticodeSignature {$global:resigned++}
Finalize-SupportAccessSignature -Path 'synthetic.exe' -Thumbprint ('a'*40) -Timestamp 'http://timestamp.invalid'
@{resigned=$global:resigned}|ConvertTo-Json -Compress
''',encoding='utf-8')
    result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-File',str(script),str(ROOT/'packaging/windows/build-msi.ps1')],capture_output=True,text=True,timeout=20)
    assert result.returncode==0,result.stdout+result.stderr
    assert json.loads(result.stdout)['resigned']==0
