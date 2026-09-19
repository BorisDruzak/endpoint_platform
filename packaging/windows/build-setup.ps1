[CmdletBinding()]
param(
    [ValidateSet("Release", "Debug")]
    [string]$Configuration = "Release",
    [ValidateSet("x64")]
    [string]$Platform = "x64",
    [string]$Version,
    [Parameter(Mandatory)][string]$EndpointOrigin,
    [Parameter(Mandatory)][string]$EndpointCaFile,
    [string]$InitialRuntimeManifest,
    [string]$InitialRuntimeStageRoot,
    [string]$InitialRuntimeStageEvidence,
    [switch]$ApproveInitialRuntimeTransition,
    [switch]$ApproveInitialRuntimeSourceChange,
    [switch]$ReusePythonBuild,
    [string]$WixBuildRoot
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Assert-SemVerTriplet {
    param([Parameter(Mandatory)][string]$Value)
    if ($Value -notmatch '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$') {
        throw "Version must be a three-part numeric version suitable for MSI."
    }
}

function Write-Utf8NoBom {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Content)
    [IO.File]::WriteAllText($Path, $Content, [Text.UTF8Encoding]::new($false))
}

$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$packagingRoot = [IO.Path]::GetFullPath($PSScriptRoot)
$python = (Get-Command python -ErrorAction Stop).Source
if (-not $Version) {
    $versionText = [IO.File]::ReadAllText((Join-Path $repositoryRoot 'pc_agent\version.py'))
    $match = [regex]::Match($versionText, 'AGENT_VERSION\s*=\s*"([^"]+)"')
    if (-not $match.Success) { throw "Could not read AGENT_VERSION." }
    $Version = $match.Groups[1].Value
}
Assert-SemVerTriplet -Value $Version
if (-not (Test-Path -LiteralPath $EndpointCaFile -PathType Leaf)) {
    throw "Endpoint CA file is missing."
}
if (-not $EndpointOrigin.StartsWith('https://', [StringComparison]::OrdinalIgnoreCase)) {
    throw "Endpoint origin must use HTTPS."
}

$msiParameters = @{
    Configuration = $Configuration
    Platform = $Platform
    Version = $Version
}
foreach ($optional in @(
    @{ name = 'InitialRuntimeManifest'; value = $InitialRuntimeManifest },
    @{ name = 'InitialRuntimeStageRoot'; value = $InitialRuntimeStageRoot },
    @{ name = 'InitialRuntimeStageEvidence'; value = $InitialRuntimeStageEvidence },
    @{ name = 'WixBuildRoot'; value = $WixBuildRoot }
)) {
    if ($optional.value) { $msiParameters[$optional.name] = $optional.value }
}
if ($ApproveInitialRuntimeTransition) { $msiParameters.ApproveInitialRuntimeTransition = $true }
if ($ApproveInitialRuntimeSourceChange) { $msiParameters.ApproveInitialRuntimeSourceChange = $true }
if ($ReusePythonBuild) { $msiParameters.ReusePythonBuild = $true }
& (Join-Path $PSScriptRoot 'build-msi.ps1') @msiParameters
if ($LASTEXITCODE -ne 0) { throw "MSI build failed." }

$effectiveWixBuildRoot = if ($WixBuildRoot) {
    [IO.Path]::GetFullPath($WixBuildRoot)
} else {
    Join-Path ([IO.Path]::GetPathRoot($repositoryRoot)) "endpoint-platform-wix-build\$Configuration-$Platform"
}
$msiPath = Join-Path $effectiveWixBuildRoot "output\EndpointAgent-$Version-x64.msi"
if (-not (Test-Path -LiteralPath $msiPath -PathType Leaf)) { throw "MSI output is missing." }

$setupRoot = Join-Path $effectiveWixBuildRoot 'setup'
if (Test-Path -LiteralPath $setupRoot) { Remove-Item -LiteralPath $setupRoot -Recurse -Force }
$payloadRoot = Join-Path $setupRoot 'payload'
$distRoot = Join-Path $setupRoot 'dist'
$workRoot = Join-Path $setupRoot 'work'
$releaseRoot = Join-Path $effectiveWixBuildRoot 'releases'
New-Item -ItemType Directory -Path $payloadRoot, $distRoot, $workRoot, $releaseRoot -Force | Out-Null
$setupMsi = Join-Path $payloadRoot 'EndpointAgent.msi'
$setupCa = Join-Path $payloadRoot 'endpoint-ca.crt'
$setupConfig = Join-Path $payloadRoot 'setup-config.json'
Copy-Item -LiteralPath $msiPath -Destination $setupMsi -Force
Copy-Item -LiteralPath $EndpointCaFile -Destination $setupCa -Force
Write-Utf8NoBom $setupConfig (@{
    schema_version = 'endpoint_windows_setup_config_v1'
    endpoint_origin = $EndpointOrigin.TrimEnd('/')
    installer_version = $Version
    installer_release_id = $Version
} | ConvertTo-Json -Compress)

$previousMsi = $env:ENDPOINT_SETUP_MSI
$previousCa = $env:ENDPOINT_SETUP_CA_FILE
$previousConfig = $env:ENDPOINT_SETUP_CONFIG
try {
    $env:ENDPOINT_SETUP_MSI = $setupMsi
    $env:ENDPOINT_SETUP_CA_FILE = $setupCa
    $env:ENDPOINT_SETUP_CONFIG = $setupConfig
    & $python -m PyInstaller --noconfirm --clean --distpath $distRoot --workpath $workRoot (Join-Path $repositoryRoot 'pc_agent\pyinstaller_windows_setup.spec')
    if ($LASTEXITCODE -ne 0) { throw "Windows Setup PyInstaller build failed." }
}
finally {
    $env:ENDPOINT_SETUP_MSI = $previousMsi
    $env:ENDPOINT_SETUP_CA_FILE = $previousCa
    $env:ENDPOINT_SETUP_CONFIG = $previousConfig
}
$setupExe = Join-Path $distRoot 'EndpointAgentSetup.exe'
if (-not (Test-Path -LiteralPath $setupExe -PathType Leaf)) { throw "Windows Setup executable is missing." }
$releaseSetup = Join-Path $releaseRoot "EndpointAgentSetup-$Version-x64.exe"
Copy-Item -LiteralPath $setupExe -Destination $releaseSetup -Force
$setupSha256 = (Get-FileHash -LiteralPath $releaseSetup -Algorithm SHA256).Hash.ToLowerInvariant()
$msiSha256 = (Get-FileHash -LiteralPath $msiPath -Algorithm SHA256).Hash.ToLowerInvariant()
Write-Utf8NoBom (Join-Path $releaseRoot "EndpointAgentSetup-$Version-x64.release.json") (@{
    schema_version = 'endpoint_windows_setup_release_v1'
    version = $Version
    setup_sha256 = $setupSha256
    msi_sha256 = $msiSha256
} | ConvertTo-Json -Compress)
Write-Host "Setup: $releaseSetup"
