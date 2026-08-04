[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$desktop = Join-Path $env:USERPROFILE "Desktop"
$caCandidates = @(Get-ChildItem -LiteralPath $desktop -Recurse -File -Filter "sosnadmin-local-ca.crt" -ErrorAction Stop)
if ($caCandidates.Count -ne 1) {
  throw "Expected exactly one Endpoint Platform CA certificate below $desktop; found $($caCandidates.Count)."
}
$caFile = $caCandidates[0].FullName

Set-Location $repositoryRoot
python .\tools\provision_windows_test_agent.py `
  --ca-file $caFile `
  --installation-id "windows-local-pilot-001" `
  --admin-username "osn-admin" `
  --allowed-cidr "192.168.100.1/32"

if ($LASTEXITCODE -ne 0) {
  throw "Windows pilot enrollment failed with exit code $LASTEXITCODE."
}

Write-Host "Windows pilot enrollment completed. Return to Codex."
Read-Host "Press Enter to close"
