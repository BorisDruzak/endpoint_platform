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
    [string]$CodeSigningCertificateThumbprint,
    [string]$TimestampServer,
    [string]$ExistingMsi,
    [string]$ExistingMsiReleaseManifest,
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

function Assert-SecretFreeSetupArtifact {
    param([Parameter(Mandatory)][string]$Path)
    $bytes = [IO.File]::ReadAllBytes($Path)
    $content = [Text.Encoding]::GetEncoding(28591).GetString($bytes)
    if ([regex]::IsMatch($content, '(?i)\b(?:ic|ec)_[0-9a-f]{32}\.[A-Za-z0-9_-]{43}\b')) {
        throw "Windows Setup artifact contains an enrollment bearer pattern."
    }
}

function Set-SetupAuthenticodeSignature {
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$Thumbprint,
        [string]$Timestamp
    )
    if (-not $Thumbprint) { return }
    if ($Thumbprint -notmatch '^[A-Fa-f0-9]{40}$') {
        throw "Code-signing certificate thumbprint is invalid."
    }
    if ($Timestamp -and -not $Timestamp.StartsWith('https://', [StringComparison]::OrdinalIgnoreCase)) {
        throw "Authenticode timestamp server must use HTTPS."
    }
    $certificate = Get-ChildItem -LiteralPath ("Cert:\\CurrentUser\\My\\" + $Thumbprint)
    if (-not $certificate -or -not $certificate.HasPrivateKey) {
        throw "Code-signing certificate is unavailable."
    }
    $parameters = @{ FilePath = $Path; Certificate = $certificate }
    if ($Timestamp) { $parameters.TimestampServer = $Timestamp }
    $result = Set-AuthenticodeSignature @parameters
    if ($result.Status -ne 'Valid') { throw "Authenticode signing failed." }
}

function Resolve-VerifiedExistingMsi {
    param(
        [Parameter(Mandatory)][string]$MsiPath,
        [Parameter(Mandatory)][string]$ReleaseManifestPath,
        [Parameter(Mandatory)][string]$ExpectedVersion
    )
    if (-not (Test-Path -LiteralPath $MsiPath -PathType Leaf)) {
        throw "Existing MSI is missing."
    }
    if (-not (Test-Path -LiteralPath $ReleaseManifestPath -PathType Leaf)) {
        throw "Existing MSI release manifest is missing."
    }
    try {
        $manifest = Get-Content -LiteralPath $ReleaseManifestPath -Raw | ConvertFrom-Json
    }
    catch {
        throw "Existing MSI release manifest is invalid."
    }
    if (
        $manifest.schema_version -ne 'endpoint_windows_setup_release_v1' -or
        [string]$manifest.agent_version -ne $ExpectedVersion -or
        [string]$manifest.source_commit -notmatch '^[0-9a-f]{40}$' -or
        [string]$manifest.msi_sha256 -notmatch '^[0-9a-f]{64}$'
    ) {
        throw "Existing MSI release manifest is invalid."
    }
    $actualSha256 = (Get-FileHash -LiteralPath $MsiPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualSha256 -ne [string]$manifest.msi_sha256) {
        throw "Existing MSI SHA-256 does not match its release manifest."
    }
    return [pscustomobject]@{
        Path = [IO.Path]::GetFullPath($MsiPath)
        SourceCommit = [string]$manifest.source_commit
    }
}

$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$packagingRoot = [IO.Path]::GetFullPath($PSScriptRoot)
$python = (Get-Command python -ErrorAction Stop).Source
$sourceCommit = (& git -C $repositoryRoot rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $sourceCommit -notmatch '^[0-9a-f]{40}$') {
    throw "Could not determine release source commit."
}
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

$effectiveWixBuildRoot = if ($WixBuildRoot) {
    [IO.Path]::GetFullPath($WixBuildRoot)
} else {
    Join-Path ([IO.Path]::GetPathRoot($repositoryRoot)) "endpoint-platform-wix-build\$Configuration-$Platform"
}
$msiPath = Join-Path $effectiveWixBuildRoot "output\EndpointAgent-$Version-x64.msi"
$hasExistingMsi = -not [string]::IsNullOrWhiteSpace($ExistingMsi)
$hasExistingMsiManifest = -not [string]::IsNullOrWhiteSpace($ExistingMsiReleaseManifest)
if ($hasExistingMsi -ne $hasExistingMsiManifest) {
    throw "Existing MSI and release manifest must be supplied together."
}
$msiSourceCommit = $sourceCommit
if ($hasExistingMsi) {
    $existingMsi = Resolve-VerifiedExistingMsi `
        -MsiPath $ExistingMsi `
        -ReleaseManifestPath $ExistingMsiReleaseManifest `
        -ExpectedVersion $Version
    New-Item -ItemType Directory -Path (Split-Path -Parent $msiPath) -Force | Out-Null
    Copy-Item -LiteralPath $existingMsi.Path -Destination $msiPath -Force
    $msiSourceCommit = $existingMsi.SourceCommit
}
else {
    & (Join-Path $PSScriptRoot 'build-msi.ps1') @msiParameters
    if ($LASTEXITCODE -ne 0) { throw "MSI build failed." }
}
if (-not (Test-Path -LiteralPath $msiPath -PathType Leaf)) { throw "MSI output is missing." }
Set-AuthenticodeSignature -Path $msiPath -Thumbprint $CodeSigningCertificateThumbprint -Timestamp $TimestampServer

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
Assert-SecretFreeSetupArtifact -Path $releaseSetup
Set-SetupAuthenticodeSignature -Path $releaseSetup -Thumbprint $CodeSigningCertificateThumbprint -Timestamp $TimestampServer
$signature = Get-AuthenticodeSignature -FilePath $releaseSetup
$authenticodeStatus = switch ($signature.Status.ToString()) {
    'Valid' { 'valid' }
    'NotSigned' { 'unsigned' }
    default { 'invalid' }
}
$authenticodePublisher = if ($signature.SignerCertificate) {
    $signature.SignerCertificate.Subject
} else {
    $null
}
$msiSignature = Get-AuthenticodeSignature -FilePath $msiPath
$msiAuthenticodeStatus = switch ($msiSignature.Status.ToString()) {
    'Valid' { 'valid' }
    'NotSigned' { 'unsigned' }
    default { 'invalid' }
}
$msiAuthenticodePublisher = if ($msiSignature.SignerCertificate) {
    $msiSignature.SignerCertificate.Subject
} else {
    $null
}
$setupSha256 = (Get-FileHash -LiteralPath $releaseSetup -Algorithm SHA256).Hash.ToLowerInvariant()
$msiSha256 = (Get-FileHash -LiteralPath $msiPath -Algorithm SHA256).Hash.ToLowerInvariant()
Write-Utf8NoBom (Join-Path $releaseRoot "EndpointAgentSetup-$Version-x64.release.json") (@{
    schema_version = 'endpoint_windows_setup_release_v1'
    version = $Version
    agent_version = $Version
    source_commit = $sourceCommit
    msi_source_commit = $msiSourceCommit
    filename = [IO.Path]::GetFileName($releaseSetup)
    setup_sha256 = $setupSha256
    msi_sha256 = $msiSha256
    authenticode_status = $authenticodeStatus
    authenticode_publisher = $authenticodePublisher
    msi_authenticode_status = $msiAuthenticodeStatus
    msi_authenticode_publisher = $msiAuthenticodePublisher
} | ConvertTo-Json -Compress)
Write-Host "Setup: $releaseSetup"
