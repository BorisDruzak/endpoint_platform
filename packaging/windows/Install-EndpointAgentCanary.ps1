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

$SystemSid = 'S-1-5-18'
$AdministratorsSid = 'S-1-5-32-544'
$CacheSids = @($SystemSid, $AdministratorsSid)

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
            throw 'Installer path contains a reparse point.'
        }
        $parent = Split-Path -Parent $candidate
        if (-not $parent -or $parent -eq $candidate) { break }
        $candidate = $parent
    }
}

function Get-SidValue {
    param([Parameter(Mandatory = $true)]$Identity)
    try {
        return $Identity.Translate([Security.Principal.SecurityIdentifier]).Value
    }
    catch {
        throw 'Installer path identity cannot be resolved to a SID.'
    }
}

function Assert-TrustedOwner {
    param([Parameter(Mandatory = $true)][string]$Path)
    $acl = Get-Acl -LiteralPath $Path
    $ownerSid = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($ownerSid -notin $CacheSids) {
        throw 'Installer path owner is not trusted.'
    }
}

function Assert-ProtectedAcl {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string[]]$AllowedSids,
        [Parameter(Mandatory = $true)][string[]]$RequiredSids,
        [switch]$RequireProtected
    )
    $acl = Get-Acl -LiteralPath $Path
    if ($RequireProtected -and -not $acl.AreAccessRulesProtected) {
        throw 'Installer path DACL is not protected.'
    }
    Assert-TrustedOwner -Path $Path
    $actual = @()
    foreach ($rule in $acl.Access) {
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) {
            throw 'Installer path contains a deny ACL rule.'
        }
        $sid = Get-SidValue -Identity $rule.IdentityReference
        if ($sid -notin $AllowedSids) {
            throw 'Installer path contains an untrusted ACL rule.'
        }
        $actual += $sid
    }
    if (@($RequiredSids | Where-Object { $_ -notin $actual }).Count -ne 0) {
        throw 'Installer path is missing a required ACL rule.'
    }
}

function New-InstallerCacheSecurity {
    $security = [Security.AccessControl.DirectorySecurity]::new()
    $security.SetAccessRuleProtection($true, $false)
    $security.SetOwner([Security.Principal.SecurityIdentifier]::new($AdministratorsSid))
    $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
    foreach ($sid in $CacheSids) {
        $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($sid),
            [Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow
        ))
    }
    return $security
}

function New-ProtectedDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)
    Assert-ExistingPathChain -Path (Split-Path -Parent $Path)
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
    Set-Acl -LiteralPath $Path -AclObject (New-InstallerCacheSecurity)
    Assert-ExistingPathChain -Path $Path
    Assert-ProtectedAcl -Path $Path -AllowedSids $CacheSids -RequiredSids $CacheSids -RequireProtected
}

function Assert-InstallerCacheProtection {
    param([Parameter(Mandatory = $true)][string]$Path)
    Assert-ExistingPathChain -Path $Path
    Assert-ProtectedAcl -Path $Path -AllowedSids $CacheSids -RequiredSids $CacheSids -RequireProtected
}

function Get-AgentServiceSids {
    $sids = @()
    foreach ($name in @('NT SERVICE\EndpointAgent', 'NT SERVICE\EndpointAgentUpdater')) {
        try {
            $sids += Get-SidValue -Identity ([Security.Principal.NTAccount]::new($name))
        }
        catch {
            continue
        }
    }
    return $sids
}

function Assert-InstalledDataProtection {
    param([Parameter(Mandatory = $true)][string]$Path)
    $serviceSids = Get-AgentServiceSids
    if ($serviceSids.Count -ne 2) { throw 'Installed service SIDs cannot be resolved.' }
    $allowed = @($CacheSids + $serviceSids)
    Assert-ProtectedAcl -Path $Path -AllowedSids $allowed -RequiredSids $allowed -RequireProtected
}

function Assert-CacheArtifactProtection {
    param([Parameter(Mandatory = $true)][string]$Path)
    Assert-RegularNonReparseFile -Path $Path -Label 'Installer cache artifact'
    Assert-ProtectedAcl -Path $Path -AllowedSids $CacheSids -RequiredSids $CacheSids
}

function Set-CacheArtifactProtection {
    param([Parameter(Mandatory = $true)][string]$Path)
    Assert-RegularNonReparseFile -Path $Path -Label 'Installer cache artifact'
    $security = [Security.AccessControl.FileSecurity]::new()
    $security.SetAccessRuleProtection($true, $false)
    $security.SetOwner([Security.Principal.SecurityIdentifier]::new($AdministratorsSid))
    foreach ($sid in $CacheSids) {
        $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($sid),
            [Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.AccessControlType]::Allow
        ))
    }
    Set-Acl -LiteralPath $Path -AclObject $security
    Assert-CacheArtifactProtection -Path $Path
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

$programFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
$packageRoot = Join-Path $programFiles 'Endpoint Platform'
$executionCacheRoot = Join-Path $packageRoot 'installer-cache'
$executionCacheDirectory = Join-Path $executionCacheRoot "msi-$($manifest.package_sha256)"
$executionCachePath = Join-Path $executionCacheDirectory 'EndpointAgent.msi'
Assert-ExistingPathChain -Path $programFiles
if (-not (Test-Path -LiteralPath $packageRoot)) {
    New-Item -ItemType Directory -Path $packageRoot -Force | Out-Null
}
Assert-ExistingPathChain -Path $packageRoot
if (-not (Test-Path -LiteralPath $executionCacheRoot)) {
    New-ProtectedDirectory -Path $executionCacheRoot
}
Assert-InstallerCacheProtection -Path $executionCacheRoot
if (-not (Test-Path -LiteralPath $executionCacheDirectory)) {
    New-ProtectedDirectory -Path $executionCacheDirectory
}
Assert-InstallerCacheProtection -Path $executionCacheDirectory

if (Test-Path -LiteralPath $executionCachePath) {
    Assert-CacheArtifactProtection -Path $executionCachePath
    if ((Get-FileHash -LiteralPath $executionCachePath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $inputHash) {
        throw 'Existing MSI cache does not match release manifest.'
    }
}
else {
    Copy-Item -LiteralPath $MsiPath -Destination $executionCachePath
}
Set-CacheArtifactProtection -Path $executionCachePath
if ((Get-FileHash -LiteralPath $executionCachePath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $inputHash) {
    throw 'MSI cache SHA-256 does not match release manifest.'
}
Assert-InstallerCacheProtection -Path $executionCacheRoot
Assert-InstallerCacheProtection -Path $executionCacheDirectory
Assert-CacheArtifactProtection -Path $executionCachePath

$installer = Start-Process -FilePath 'msiexec.exe' -ArgumentList @('/i', $executionCachePath, '/qn', '/norestart') -Wait -PassThru
if ($installer.ExitCode -ne 0) {
    throw "MSI installation failed with exit code $($installer.ExitCode)."
}

$programData = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
$dataRoot = Join-Path $programData 'Endpoint Platform\Agent'
$cacheRoot = Join-Path $dataRoot 'installer-cache'
$cacheDirectory = Join-Path $cacheRoot "msi-$($manifest.package_sha256)"
$cachePath = Join-Path $cacheDirectory 'EndpointAgent.msi'
$provenancePath = Join-Path $cacheRoot 'installer-provenance.json'
Assert-InstalledDataProtection -Path $dataRoot
if (-not (Test-Path -LiteralPath $cacheRoot)) {
    New-ProtectedDirectory -Path $cacheRoot
}
Assert-InstallerCacheProtection -Path $cacheRoot
if (-not (Test-Path -LiteralPath $cacheDirectory)) {
    New-ProtectedDirectory -Path $cacheDirectory
}
Assert-InstallerCacheProtection -Path $cacheDirectory
Copy-Item -LiteralPath $executionCachePath -Destination $cachePath
Set-CacheArtifactProtection -Path $cachePath
if ((Get-FileHash -LiteralPath $cachePath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $inputHash) {
    throw 'Installed MSI cache SHA-256 does not match release manifest.'
}

$provenance = [ordered]@{
    cache_file = "msi-$($manifest.package_sha256)/EndpointAgent.msi"
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
Set-CacheArtifactProtection -Path $provenancePath
