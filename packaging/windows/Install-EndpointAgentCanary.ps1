[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$MsiPath,
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ReleaseManifest
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Assert-RegularNonReparseFile {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string]$Label)
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer -or [bool]($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "$Label must be a regular non-reparse file."
    }
}

function Assert-ExistingPathChain {
    param([Parameter(Mandatory = $true)][string]$Path)
    $candidate = [IO.Path]::GetFullPath($Path)
    while (-not (Test-Path -LiteralPath $candidate)) {
        $parent = Split-Path -Parent $candidate
        if (-not $parent -or $parent -eq $candidate) { break }
        $candidate = $parent
    }
    while ($candidate) {
        $item = Get-Item -LiteralPath $candidate -Force
        if ([bool]($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw "Installer path contains a reparse point."
        }
        $parent = Split-Path -Parent $candidate
        if (-not $parent -or $parent -eq $candidate) { break }
        $candidate = $parent
    }
}

function Read-ReleaseManifest {
    param([Parameter(Mandatory = $true)][string]$Path)
    Assert-RegularNonReparseFile -Path $Path -Label 'Release manifest'
    try {
        $value = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    }
    catch {
        throw 'Release manifest is unreadable.'
    }
    $expected = @(
        'initial_runtime_tree_sha256', 'package_sha256', 'product_code',
        'schema_version', 'source_revision', 'version'
    )
    $actual = @($value.PSObject.Properties.Name | Sort-Object)
    if ([string]::Join('|', $actual) -ne [string]::Join('|', $expected)) {
        throw 'Release manifest schema is invalid.'
    }
    if (
        [string]$value.schema_version -ne 'endpoint_windows_release_v1' -or
        [string]$value.version -notmatch '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' -or
        [string]$value.product_code -notmatch '^\{[0-9A-F-]{36}\}$' -or
        [string]$value.source_revision -notmatch '^[0-9a-f]{40}$' -or
        [string]$value.initial_runtime_tree_sha256 -notmatch '^[0-9a-f]{64}$' -or
        [string]$value.package_sha256 -notmatch '^[0-9a-f]{64}$'
    ) {
        throw 'Release manifest values are invalid.'
    }
    return $value
}

function Assert-ProgramDataProtection {
    param([Parameter(Mandatory = $true)][string]$Path)
    $acl = Get-Acl -LiteralPath $Path
    $identities = @($acl.Access | ForEach-Object { $_.IdentityReference.Value })
    $required = @(
        'NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators',
        'NT SERVICE\EndpointAgent', 'NT SERVICE\EndpointAgentUpdater'
    )
    if (
        -not $acl.AreAccessRulesProtected -or
        @($required | Where-Object { $identities -contains $_ }).Count -ne $required.Count -or
        $identities -contains 'BUILTIN\Users' -or
        $identities -contains 'Everyone' -or
        $identities -contains 'NT AUTHORITY\Authenticated Users'
    ) {
        throw 'Installed ProgramData protection is invalid.'
    }
}

$principal = [Security.Principal.WindowsPrincipal]([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Administrator rights are required.'
}

Assert-RegularNonReparseFile -Path $MsiPath -Label 'MSI'
Assert-ExistingPathChain -Path $MsiPath
Assert-ExistingPathChain -Path $ReleaseManifest
$manifest = Read-ReleaseManifest -Path $ReleaseManifest
$inputHash = (Get-FileHash -LiteralPath $MsiPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($inputHash -ne [string]$manifest.package_sha256) {
    throw 'MSI SHA-256 does not match release manifest.'
}

$programData = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
$dataRoot = Join-Path $programData 'Endpoint Platform\Agent'
$cacheRoot = Join-Path $dataRoot 'installer-cache'
$cachePath = Join-Path $cacheRoot 'EndpointAgent.msi'
$provenancePath = Join-Path $cacheRoot 'installer-provenance.json'
Assert-ExistingPathChain -Path $programData
New-Item -ItemType Directory -Path $cacheRoot -Force | Out-Null
Assert-ExistingPathChain -Path $dataRoot
Assert-ExistingPathChain -Path $cacheRoot

if (Test-Path -LiteralPath $cachePath) {
    Assert-RegularNonReparseFile -Path $cachePath -Label 'Existing MSI cache'
    if ((Get-FileHash -LiteralPath $cachePath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $inputHash) {
        throw 'Existing MSI cache does not match release manifest.'
    }
}
else {
    Copy-Item -LiteralPath $MsiPath -Destination $cachePath
}
Assert-RegularNonReparseFile -Path $cachePath -Label 'MSI cache'
if ((Get-FileHash -LiteralPath $cachePath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $inputHash) {
    throw 'MSI cache SHA-256 does not match release manifest.'
}

$installer = Start-Process -FilePath 'msiexec.exe' -ArgumentList @('/i', $cachePath, '/qn', '/norestart') -Wait -PassThru
if ($installer.ExitCode -ne 0) {
    throw "MSI installation failed with exit code $($installer.ExitCode)."
}
Assert-ProgramDataProtection -Path $dataRoot

$provenance = [ordered]@{
    cache_file = 'EndpointAgent.msi'
    initial_runtime_tree_sha256 = [string]$manifest.initial_runtime_tree_sha256
    package_sha256 = [string]$manifest.package_sha256
    product_code = [string]$manifest.product_code
    release_manifest_schema_version = [string]$manifest.schema_version
    schema_version = 'endpoint_windows_installer_provenance_v1'
    source_revision = [string]$manifest.source_revision
    version = [string]$manifest.version
}
[IO.File]::WriteAllText(
    $provenancePath,
    ($provenance | ConvertTo-Json -Compress),
    [Text.UTF8Encoding]::new($false)
)
Assert-RegularNonReparseFile -Path $provenancePath -Label 'Installer provenance'
