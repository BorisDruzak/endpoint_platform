[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$OutputPath,
    [Parameter(Mandatory = $true)]
    [string]$ExpectedEndpointHost,
    [Parameter(Mandatory = $true)]
    [string]$ExpectedInstallRoot,
    [Parameter(Mandatory = $true)]
    [string]$ExpectedDataRoot,
    [switch]$RequireCompletion,
    [string]$ExpectedCommandId,
    [string]$ExpectedCapability,
    [string]$SetupPath,
    [string]$TargetVersion,
    [switch]$FleetEligibilityOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$AgentServiceName = 'EndpointAgent'
$UpdaterServiceName = 'EndpointAgentUpdater'
$CanaryCapability = 'context.diagnostic.collect'
$SystemSid = 'S-1-5-18'
$AdministratorsSid = 'S-1-5-32-544'
$LocalServiceSid = 'S-1-5-19'
$ConsoleHostPath = Join-Path $env:WINDIR 'System32\conhost.exe'

function Assert-ExactFleetKeys {
    param($Value, [string[]]$Keys)
    if ($null -eq $Value -or $Value -isnot [pscustomobject] -or
        [string]::Join('|', @($Value.PSObject.Properties.Name | Sort-Object)) -ne
        [string]::Join('|', @($Keys | Sort-Object))) { throw 'Canonical fleet fact schema is invalid.' }
}

function Assert-FleetPreflightSchema {
    param($Value, [string]$TargetVersion)
    Assert-ExactFleetKeys $Value @('schema_version','target_version','eligibility','snapshot_scope','core','foundation','msi','origin','wss','update_lane','pending','provenance','credential','ca','disk','services')
    foreach ($field in @('schema_version','target_version','eligibility','snapshot_scope')) {
        if ($Value.$field -isnot [string]) { throw 'Canonical header type is invalid.' }
    }
    if ($Value.schema_version -ne 'endpoint_windows_fleet_preflight_v1' -or
        $Value.target_version -cne $TargetVersion -or $TargetVersion -notmatch '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' -or
        $Value.snapshot_scope -ne 'local_non_atomic_read_only' -or
        $Value.eligibility -notin @('READY_FOR_SETUP_UPGRADE','ALREADY_CURRENT','UPDATE_IN_PROGRESS','PROVENANCE_CONFLICT','FOUNDATION_UNKNOWN','DISK_INSUFFICIENT','DISK_UNKNOWN','SERVICE_INVALID','CREDENTIAL_REPAIR_REQUIRED','TLS_REPAIR_REQUIRED')) { throw 'Canonical fleet header is invalid.' }
    $groups = @{
        core = @('version','source_revision','minimum_launcher_version','origin','verified','package_sha256','package_size','compatibility_scope')
        foundation = @('version','source_revision','package_sha256','product_code','native_verified','feature_state')
        msi = @('version','product_code','native_verified')
        origin = @('present','https_shape_valid','scope')
        wss = @('status_present','historical_proof','live_connected','scope')
        update_lane = @('commands','updates','migration_http_pull_fallback','live_owner')
        pending = @('active_or_degraded','state','installer_phase')
        provenance = @('conflict','verified')
        credential = @('present','shape_valid','enrollment_shape_valid','authenticated')
        ca = @('present','parseable','strict_live_tls')
        disk = @('sufficient','scope','free_bytes')
        services = @('EndpointAgent','EndpointAgentUpdater')
    }
    foreach ($key in $groups.Keys) { Assert-ExactFleetKeys $Value.$key $groups[$key] }
    $strings = @{
        core = @('version','source_revision','package_sha256','minimum_launcher_version','origin','compatibility_scope')
        foundation = @('version','source_revision','package_sha256','product_code','feature_state')
        msi = @('version','product_code'); origin = @('scope'); wss = @('scope')
        update_lane = @('commands','updates'); pending = @('state','installer_phase'); disk = @('scope')
    }
    foreach ($group in $strings.Keys) {
        foreach ($field in $strings[$group]) {
            if ($null -ne $Value.$group.$field -and $Value.$group.$field -isnot [string]) { throw 'Canonical string fact is invalid.' }
        }
    }
    foreach ($group in @($Value.core,$Value.foundation,$Value.msi)) {
        if ($null -ne $group.version -and [string]$group.version -notmatch '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$') { throw 'Canonical version is invalid.' }
    }
    foreach ($group in @($Value.core,$Value.foundation)) {
        if (($null -ne $group.source_revision -and [string]$group.source_revision -notmatch '^[0-9a-f]{40}$') -or
            ($null -ne $group.package_sha256 -and [string]$group.package_sha256 -notmatch '^[0-9a-f]{64}$')) { throw 'Canonical release identity is invalid.' }
    }
    foreach ($group in @($Value.foundation,$Value.msi)) {
        if ($group.native_verified -isnot [bool] -or ($null -ne $group.product_code -and [string]$group.product_code -notmatch '^\{[0-9A-Fa-f-]{36}\}$')) { throw 'Canonical native identity is invalid.' }
    }
    foreach ($field in @('present','shape_valid','enrollment_shape_valid')) {
        if ($Value.credential.$field -isnot [bool]) { throw 'Canonical credential fact is invalid.' }
    }
    foreach ($field in @('present','parseable')) {
        if ($Value.ca.$field -isnot [bool]) { throw 'Canonical CA fact is invalid.' }
    }
    if ($null -ne $Value.credential.authenticated -or $null -ne $Value.ca.strict_live_tls -or
        $null -ne $Value.wss.live_connected -or $null -ne $Value.update_lane.live_owner) { throw 'Canonical live proof scope is invalid.' }
    if ($Value.core.verified -isnot [bool] -or $Value.pending.active_or_degraded -isnot [bool] -or
        $Value.provenance.conflict -isnot [bool] -or $Value.provenance.verified -isnot [bool] -or
        $Value.origin.present -isnot [bool] -or
        ($null -ne $Value.origin.https_shape_valid -and $Value.origin.https_shape_valid -isnot [bool]) -or
        ($null -ne $Value.disk.sufficient -and $Value.disk.sufficient -isnot [bool]) -or
        ($null -ne $Value.wss.status_present -and $Value.wss.status_present -isnot [bool]) -or
        ($null -ne $Value.wss.historical_proof -and $Value.wss.historical_proof -isnot [bool])) { throw 'Canonical boolean fact is invalid.' }
    if (($null -ne $Value.core.origin -and $Value.core.origin -notin @('zip','msi','retained_msi')) -or
        ($null -ne $Value.core.compatibility_scope -and $Value.core.compatibility_scope -notin @('payload_contract','immutable_legacy_identity')) -or
        ($null -ne $Value.core.minimum_launcher_version -and [string]$Value.core.minimum_launcher_version -notmatch '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$') -or
        ($null -ne $Value.foundation.feature_state -and $Value.foundation.feature_state -notin @('complete','foundation_only')) -or
        $Value.origin.scope -notin @('compiled_default','protected_override') -or
        $Value.wss.scope -ne 'historical_status_only' -or $Value.disk.scope -notin @('setup_allocation_unknown','verified_allocations') -or
        $Value.update_lane.commands -ne 'wss' -or $Value.update_lane.updates -ne 'https' -or
        $Value.update_lane.migration_http_pull_fallback -isnot [bool] -or $Value.update_lane.migration_http_pull_fallback) { throw 'Canonical factual scope is invalid.' }
    if (($null -ne $Value.core.package_size -and ($Value.core.package_size -isnot [int] -and $Value.core.package_size -isnot [long] -or $Value.core.package_size -le 0 -or $Value.core.package_size -gt 536870912)) -or
        ($null -ne $Value.disk.free_bytes -and ($Value.disk.free_bytes -isnot [int] -and $Value.disk.free_bytes -isnot [long] -or $Value.disk.free_bytes -lt 0))) { throw 'Canonical size fact is invalid.' }
    if (($null -ne $Value.pending.state -and $Value.pending.state -notin @('pending','verifying','terminal-report-pending','recovery-pending','installer-recovery-required','state-invalid')) -or
        ($null -ne $Value.pending.installer_phase -and $Value.pending.installer_phase -notin @('prepared','msi-starting','msi-executing','msi-returned','reconciling','complete'))) { throw 'Canonical recovery fact is invalid.' }
    foreach ($name in @('EndpointAgent','EndpointAgentUpdater')) {
        $service = $Value.services.$name
        Assert-ExactFleetKeys $service @('present','state','start_mode','identity_valid')
        if (($null -ne $service.present -and $service.present -isnot [bool]) -or
            ($null -ne $service.identity_valid -and $service.identity_valid -isnot [bool]) -or
            ($null -ne $service.state -and $service.state -isnot [string]) -or
            ($null -ne $service.start_mode -and $service.start_mode -isnot [string]) -or
            ($null -ne $service.state -and $service.state -notin @('running','stopped','transitioning')) -or
            ($null -ne $service.start_mode -and $service.start_mode -notin @('automatic','manual','disabled','invalid'))) { throw 'Canonical service fact is invalid.' }
    }
}

function Invoke-BoundedSetupPreflight {
    param([string]$Path)
    $process = [Diagnostics.Process]::new()
    $process.StartInfo.FileName = $Path
    $process.StartInfo.Arguments = '--preflight'
    $process.StartInfo.UseShellExecute = $false
    $process.StartInfo.CreateNoWindow = $true
    $process.StartInfo.RedirectStandardOutput = $true
    $process.StartInfo.RedirectStandardError = $true
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $started = $false
    try {
        if (-not $process.Start()) { throw 'Canonical preflight could not start.' }
        $started = $true
        $output = [Text.StringBuilder]::new()
        $buffer = [char[]]::new(16385)
        while ($true) {
            $read = $process.StandardOutput.ReadAsync($buffer, 0, 16385 - $output.Length)
            while (-not $read.Wait(100)) {
                if ($clock.ElapsedMilliseconds -gt 60000) { throw 'Canonical preflight timed out.' }
            }
            $count = $read.Result
            if ($count -eq 0) { break }
            [void]$output.Append($buffer, 0, $count)
            if ($output.Length -gt 16384) { throw 'Canonical preflight exceeds bound.' }
        }
        if (-not $process.WaitForExit([Math]::Max(1, 60000 - [int]$clock.ElapsedMilliseconds))) { throw 'Canonical preflight timed out.' }
        return @{ exit_code = $process.ExitCode; stdout = $output.ToString() }
    }
    finally {
        # Own read-only child only; never touch managed services or other PIDs.
        if ($started -and -not $process.HasExited) { $process.Kill() }
        $process.Dispose()
    }
}

function Initialize-SetupPreflightPinType {
    if ($null -ne ('EndpointSetupPreflightNative' -as [type])) { return }
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class EndpointSetupPreflightNative {
    [StructLayout(LayoutKind.Sequential)]
    private struct FileInformation {
        public uint Attributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME Creation, Access, Write;
        public uint VolumeSerial, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern SafeFileHandle CreateFileW(string path, uint access,
        uint sharing, IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileInformation information);
    public static SafeFileHandle Open(string path, bool directory) {
        // OPEN_EXISTING only. Deny WRITE and DELETE sharing for the image AND
        // each namespace ancestor; check attributes on the acquired handle.
        SafeFileHandle handle = CreateFileW(path, directory ? 0x80u : 0x80000000u,
            1u, IntPtr.Zero, 3u, 0x00200000u | (directory ? 0x02000000u : 0u), IntPtr.Zero);
        if (handle.IsInvalid) { handle.Dispose(); throw new Win32Exception(); }
        try {
            FileInformation info;
            if (!GetFileInformationByHandle(handle, out info)) { throw new Win32Exception(); }
            if ((info.Attributes & 0x400u) != 0 || ((info.Attributes & 0x10u) != 0) != directory ||
                (!directory && info.Links != 1u)) { throw new InvalidOperationException("Setup path identity is invalid."); }
            return handle;
        } catch { handle.Dispose(); throw; }
    }
}
'@
}

function Open-SetupPathHandle {
    param([string]$Path, [bool]$Directory)
    Initialize-SetupPreflightPinType
    return [EndpointSetupPreflightNative]::Open($Path, $Directory)
}

function Close-SetupPreflightPin {
    param($Pin)
    for ($i = $Pin.handles.Count - 1; $i -ge 0; $i--) { $Pin.handles[$i].Dispose() }
}

function Open-SetupPreflightPin {
    param([string]$Path)
    $full = [IO.Path]::GetFullPath($Path)
    if ($full.Length -gt 32767) { throw 'Canonical Setup path exceeds bound.' }
    $names = [Collections.Generic.List[string]]::new()
    $current = $full
    while (-not [string]::IsNullOrEmpty($current)) {
        $names.Add($current)
        if ($names.Count -gt 128) { throw 'Canonical Setup path exceeds bound.' }
        $current = [IO.Path]::GetDirectoryName($current)
    }
    $handles = [Collections.Generic.List[IDisposable]]::new()
    try {
        # Root first: each later open resolves under an already held namespace.
        for ($i = $names.Count - 1; $i -ge 0; $i--) {
            $handle = Open-SetupPathHandle -Path $names[$i] -Directory ($i -ne 0)
            $handles.Add($handle)
        }
        return [pscustomobject]@{path=$full;handles=$handles.ToArray()}
    } catch {
        Close-SetupPreflightPin ([pscustomobject]@{handles=$handles.ToArray()})
        throw
    }
}

function Read-CanonicalSetupPreflight {
    param([string]$Path, [string]$TargetVersion)
    $fact = Get-SafeFileFact -Path $Path
    if (-not $fact.regular -or $fact.reparse) { throw 'Canonical Setup path is invalid.' }
    $pin = Open-SetupPreflightPin -Path $fact.path
    try {
        $fact = Get-SafeFileFact -Path $pin.path
        if (-not $fact.regular -or $fact.reparse -or
            -not $fact.path.Equals($pin.path,[StringComparison]::OrdinalIgnoreCase)) { throw 'Canonical Setup path identity is invalid.' }
        $signature = Get-AuthenticodeSignature -FilePath $pin.path
        if ([string]$signature.Status -ne 'Valid' -or $null -eq $signature.TimeStamperCertificate) { throw 'Canonical Setup must have a valid timestamped signature.' }
        $record = Invoke-BoundedSetupPreflight -Path $pin.path
    } finally { Close-SetupPreflightPin $pin }
    if ($record.exit_code -ne 0 -or [string]::IsNullOrWhiteSpace($record.stdout) -or
        [Text.Encoding]::UTF8.GetByteCount($record.stdout) -gt 16384) { throw 'Canonical Setup preflight failed.' }
    try { $value = $record.stdout | ConvertFrom-Json } catch { throw 'Canonical Setup preflight JSON is invalid.' }
    Assert-FleetPreflightSchema -Value $value -TargetVersion $TargetVersion
    return $value
}

function Write-PreflightReport {
    param($Payload)
    $destination = [IO.Path]::GetFullPath($OutputPath)
    $nativeInstallParent = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'Endpoint Platform'
    $nativeDataRoot = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'Endpoint Platform\Agent'
    foreach ($root in @($ExpectedInstallRoot, $ExpectedDataRoot,
        (Join-Path (Split-Path -Parent $ExpectedInstallRoot) 'installer-state'),
        (Join-Path (Split-Path -Parent $ExpectedInstallRoot) 'installer-cache'),
        $nativeInstallParent, $nativeDataRoot)) {
        $fixed = [IO.Path]::GetFullPath($root).TrimEnd('\')
        if ($destination.Equals($fixed,[StringComparison]::OrdinalIgnoreCase) -or
            $destination.StartsWith($fixed+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Report destination overlaps machine state.' }
    }
    if (Test-Path -LiteralPath $destination) { throw 'Report destination must be a new artifact.' }
    $json = $Payload | ConvertTo-Json -Depth 8
    if ([Text.Encoding]::UTF8.GetByteCount($json) -gt 65536) { throw 'Preflight report exceeds bound.' }
    $directory = Split-Path -Parent $destination
    $existing = $directory
    while (-not (Test-Path -LiteralPath $existing)) { $existing = Split-Path -Parent $existing }
    Assert-NoReparsePointInPath -Path $existing
    New-Item -ItemType Directory -Force -Path $directory | Out-Null
    Assert-NoReparsePointInPath -Path $directory
    $stream = [IO.File]::Open($destination, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $bytes = [Text.UTF8Encoding]::new($false).GetBytes($json); $stream.Write($bytes,0,$bytes.Length) } finally { $stream.Dispose() }
}

function Assert-NoReparsePointInPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    $current = Get-Item -LiteralPath $Path -Force
    while ($null -ne $current) {
        if ([bool]($current.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'A required path contains a reparse point.'
        }
        $parentPath = Split-Path -Parent $current.FullName
        if ([string]::IsNullOrEmpty($parentPath) -or $parentPath -eq $current.FullName) { break }
        $current = Get-Item -LiteralPath $parentPath -Force
    }
}

function Get-SafeFileFact {
    param([Parameter(Mandatory = $true)][string]$Path)
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer) { throw 'Expected a regular file.' }
    Assert-NoReparsePointInPath -Path $item.FullName
    [ordered]@{
        path = $item.FullName
        regular = -not [bool]($item.Attributes -band [IO.FileAttributes]::ReparsePoint)
        reparse = [bool]($item.Attributes -band [IO.FileAttributes]::ReparsePoint)
    }
}

function Get-FileSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    $stream = [IO.File]::OpenRead($Path)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        return [BitConverter]::ToString($algorithm.ComputeHash($stream)).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $algorithm.Dispose()
        $stream.Dispose()
    }
}

function ConvertTo-CanonicalServiceStartMode {
    param([Parameter(Mandatory = $true)][string]$Value)
    if ($Value -eq 'Auto') { return 'Automatic' }
    if ($Value -in @('Automatic', 'Manual', 'Disabled', 'Boot', 'System')) { return $Value }
    throw 'Windows service start mode is unsupported.'
}

function Get-ServiceFact {
    param([Parameter(Mandatory = $true)][string]$Name)
    $service = Get-CimInstance Win32_Service -Filter "Name='$Name'"
    if ($null -eq $service) { throw 'Required service is missing.' }
    [ordered]@{
        name = $Name
        start_mode = ConvertTo-CanonicalServiceStartMode -Value ([string]$service.StartMode)
        state = [string]$service.State
        account = [string]$service.StartName
        pid_present = [int]$service.ProcessId -gt 0
        path_name = [string]$service.PathName
        pid = [int]$service.ProcessId
    }
}

function Get-SidValue {
    param([Parameter(Mandatory = $true)]$Identity)
    try { return $Identity.Translate([Security.Principal.SecurityIdentifier]).Value }
    catch { throw 'Evidence ACL identity cannot be resolved to a SID.' }
}

function Get-AgentServiceSids {
    $sids = @()
    foreach ($name in @('NT SERVICE\EndpointAgent', 'NT SERVICE\EndpointAgentUpdater')) {
        $sids += Get-SidValue -Identity ([Security.Principal.NTAccount]::new($name))
    }
    return $sids
}

function Assert-ProtectedEvidenceAcl {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string[]]$AllowedSids,
        [Parameter(Mandatory = $true)][string[]]$RequiredSids,
        [Parameter(Mandatory = $true)][string[]]$AllowedOwnerSids,
        [switch]$RequireProtectedDacl
    )
    $acl = Get-Acl -LiteralPath $Path
    if ($RequireProtectedDacl -and -not $acl.AreAccessRulesProtected) {
        throw 'Evidence ACL inheritance is unsafe.'
    }
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($owner -notin $AllowedOwnerSids) { throw 'Evidence owner is unsafe.' }
    $actual = @()
    foreach ($rule in $acl.Access) {
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) {
            throw 'Evidence contains a deny ACL rule.'
        }
        $sid = Get-SidValue -Identity $rule.IdentityReference
        if ($sid -notin $AllowedSids) { throw 'Evidence contains an untrusted ACL rule.' }
        $actual += $sid
    }
    if (@($RequiredSids | Where-Object { $_ -notin $actual }).Count -ne 0) {
        throw 'Evidence ACL is missing a required rule.'
    }
}

function Get-AclSummary {
    param([Parameter(Mandatory = $true)][string]$DataRoot)
    $serviceSids = Get-AgentServiceSids
    $dataSids = @($SystemSid, $AdministratorsSid) + $serviceSids
    Assert-ProtectedEvidenceAcl -Path $DataRoot -AllowedSids $dataSids -RequiredSids $dataSids -AllowedOwnerSids @($SystemSid, $AdministratorsSid) -RequireProtectedDacl
    Assert-ProtectedEvidenceAcl -Path (Join-Path $DataRoot 'device-credential') -AllowedSids $dataSids -RequiredSids @($SystemSid, $AdministratorsSid) -AllowedOwnerSids @($SystemSid, $AdministratorsSid, $LocalServiceSid)
    Assert-ProtectedEvidenceAcl -Path (Join-Path $DataRoot 'canary-status.json') -AllowedSids $dataSids -RequiredSids @($SystemSid, $AdministratorsSid, $serviceSids[0]) -AllowedOwnerSids @($SystemSid, $AdministratorsSid, $LocalServiceSid)
    [ordered]@{
        data_root_protected = $true
        required_principals = $true
        ordinary_user_read = $false
        protected_file_regular = $true
        protected_file_reparse = $false
        status_artifact_protected = $true
    }
}

function Read-ExactJsonObject {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string[]]$ExpectedProperties,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $fact = Get-SafeFileFact -Path $Path
    if (-not $fact.regular -or $fact.reparse) { throw "$Label is unsafe." }
    try { $value = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json }
    catch { throw "$Label is unreadable." }
    $actual = @($value.PSObject.Properties.Name | Sort-Object)
    $expected = @($ExpectedProperties | Sort-Object)
    if ([string]::Join('|', $actual) -ne [string]::Join('|', $expected)) {
        throw "$Label schema is invalid."
    }
    return $value
}

function Read-CanaryStatus {
    param(
        [Parameter(Mandatory = $true)][string]$DataRoot,
        [Parameter(Mandatory = $true)][string]$ExpectedEndpointHost
    )
    $statusPath = Join-Path $DataRoot 'canary-status.json'
    $status = Read-ExactJsonObject -Path $statusPath -ExpectedProperties @('schema_version', 'release', 'transport', 'capability', 'completion_proof') -Label 'Canary status'
    if ([string]$status.schema_version -ne 'endpoint_windows_canary_status_v1' -or [string]$status.capability -ne $CanaryCapability) {
        throw 'Canary status values are invalid.'
    }
    $releaseProperties = @($status.release.PSObject.Properties.Name | Sort-Object)
    $transportProperties = @($status.transport.PSObject.Properties.Name | Sort-Object)
    if (
        [string]::Join('|', $releaseProperties) -ne 'source_revision|version' -or
        [string]::Join('|', $transportProperties) -ne 'endpoint_host|gateway_wss|hostname_valid|http_fallback|redirected|strict_tls' -or
        [string]$status.release.version -notmatch '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' -or
        [string]$status.release.source_revision -notmatch '^[0-9a-f]{40}$' -or
        -not ($status.transport.strict_tls -is [bool]) -or
        -not ($status.transport.hostname_valid -is [bool]) -or
        -not ($status.transport.redirected -is [bool]) -or
        -not ($status.transport.gateway_wss -is [bool]) -or
        -not ($status.transport.http_fallback -is [bool]) -or
        -not ([string]$status.transport.endpoint_host.Equals($ExpectedEndpointHost, [StringComparison]::OrdinalIgnoreCase))
    ) {
        throw 'Canary status values are invalid.'
    }
    return $status
}

function Read-InstallerProvenance {
    param([Parameter(Mandatory = $true)][string]$DataRoot)
    $cacheRoot = Join-Path $DataRoot 'installer-cache'
    $provenancePath = Join-Path $cacheRoot 'installer-provenance.json'
    $provenance = Read-ExactJsonObject -Path $provenancePath -ExpectedProperties @('cache_file', 'initial_runtime_tree_sha256', 'package_sha256', 'product_code', 'release_manifest_schema_version', 'schema_version', 'source_revision', 'version') -Label 'Installer provenance'
    if (
        [string]$provenance.schema_version -ne 'endpoint_windows_installer_provenance_v1' -or
        [string]$provenance.release_manifest_schema_version -ne 'endpoint_windows_release_v1' -or
        [string]$provenance.cache_file -notmatch '^msi-[0-9a-f]{64}/EndpointAgent\.msi$' -or
        [string]$provenance.version -notmatch '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' -or
        [string]$provenance.product_code -notmatch '^\{[0-9A-F-]{36}\}$' -or
        [string]$provenance.source_revision -notmatch '^[0-9a-f]{40}$' -or
        [string]$provenance.initial_runtime_tree_sha256 -notmatch '^[0-9a-f]{64}$' -or
        [string]$provenance.package_sha256 -notmatch '^[0-9a-f]{64}$'
    ) {
        throw 'Installer provenance values are invalid.'
    }
    $cacheDirectory = Join-Path $cacheRoot ([string]$provenance.cache_file).Split('/')[0]
    $cachePath = Join-Path $cacheDirectory 'EndpointAgent.msi'
    $cacheFact = Get-SafeFileFact -Path $cachePath
    if (-not $cacheFact.regular -or $cacheFact.reparse) { throw 'Installer cache is unsafe.' }
    Assert-ProtectedEvidenceAcl -Path $provenancePath -AllowedSids @($SystemSid, $AdministratorsSid) -RequiredSids @($SystemSid, $AdministratorsSid) -AllowedOwnerSids @($SystemSid, $AdministratorsSid)
    Assert-ProtectedEvidenceAcl -Path $cachePath -AllowedSids @($SystemSid, $AdministratorsSid) -RequiredSids @($SystemSid, $AdministratorsSid) -AllowedOwnerSids @($SystemSid, $AdministratorsSid)
    $hash = Get-FileSha256 -Path $cachePath
    if ($hash -ne [string]$provenance.package_sha256) { throw 'Installer cache hash is invalid.' }
    $installer = New-Object -ComObject WindowsInstaller.Installer
    if ($installer.ProductState([string]$provenance.product_code) -ne 5) { throw 'MSI product is not installed.' }
    if ([string]$installer.ProductInfo([string]$provenance.product_code, 'VersionString') -ne [string]$provenance.version) {
        throw 'Installed MSI version is invalid.'
    }
    return [ordered]@{ provenance = $provenance; cache_fact = $cacheFact; hash = $hash }
}

function Assert-TrustedRuntimeAcl {
    param([Parameter(Mandatory = $true)][string]$Path)
    $acl = Get-Acl -LiteralPath $Path
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($owner -notin @($SystemSid, $AdministratorsSid)) {
        throw 'Selected runtime owner is unsafe.'
    }
    $trustedInstallerSid = Get-SidValue -Identity ([Security.Principal.NTAccount]::new('NT SERVICE\TrustedInstaller'))
    $trustedWriters = @($SystemSid, $AdministratorsSid, $trustedInstallerSid, 'S-1-3-0')
    $writeRights = [Security.AccessControl.FileSystemRights]::WriteData -bor
        [Security.AccessControl.FileSystemRights]::AppendData -bor
        [Security.AccessControl.FileSystemRights]::WriteAttributes -bor
        [Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
        [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership
    foreach ($rule in $acl.Access) {
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) {
            throw 'Selected runtime ACL contains a deny rule.'
        }
        try { $sid = Get-SidValue -Identity $rule.IdentityReference }
        catch {
            if ([bool]($rule.FileSystemRights -band $writeRights)) {
                throw 'Selected runtime ACL permits untrusted writes.'
            }
            continue
        }
        if ($sid -notin $trustedWriters -and
            [bool]($rule.FileSystemRights -band $writeRights)) {
            throw 'Selected runtime ACL permits untrusted writes.'
        }
    }
}

function Read-SelectedRuntimeEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$InstallRoot,
        [Parameter(Mandatory = $true)]$SelectorValue,
        [Parameter(Mandatory = $true)]$InstallerProvenance
    )
    $versionsRoot = Join-Path $InstallRoot 'versions'
    $runtimeDirectory = Join-Path $versionsRoot ([string]$SelectorValue.version)
    foreach ($path in @($InstallRoot, $versionsRoot, $runtimeDirectory)) {
        Assert-NoReparsePointInPath -Path $path
        Assert-TrustedRuntimeAcl -Path $path
    }
    $msiMarker = Join-Path $runtimeDirectory '.endpoint-msi-runtime.json'
    $receiptPath = Join-Path $runtimeDirectory '.endpoint-update.json'
    $manifestPath = Join-Path $runtimeDirectory 'endpoint-update-manifest.json'
    $hasMsiMarker = Test-Path -LiteralPath $msiMarker
    $hasReceipt = Test-Path -LiteralPath $receiptPath
    $hasManifest = Test-Path -LiteralPath $manifestPath
    if ($hasMsiMarker) {
        if ($hasReceipt -or $hasManifest) { throw 'Selected runtime provenance is ambiguous.' }
        $marker = Read-ExactJsonObject -Path $msiMarker -ExpectedProperties @('component_guid', 'schema_version', 'version') -Label 'MSI runtime marker'
        Assert-TrustedRuntimeAcl -Path $msiMarker
        if (
            $marker.schema_version -ne 1 -or
            [string]$marker.component_guid -notmatch '^[0-9A-Fa-f-]{36}$' -or
            [string]$marker.version -ne [string]$SelectorValue.version -or
            [string]$SelectorValue.version -ne [string]$InstallerProvenance.version -or
            [string]$SelectorValue.source_revision -ne [string]$InstallerProvenance.source_revision
        ) { throw 'MSI-selected runtime provenance is invalid.' }
        return [ordered]@{ origin = 'msi' }
    }
    if (-not $hasReceipt -or -not $hasManifest) {
        throw 'Selected ZIP runtime evidence is incomplete.'
    }
    $receipt = Read-ExactJsonObject -Path $receiptPath -ExpectedProperties @('sha256', 'size', 'version') -Label 'ZIP runtime receipt'
    $manifest = Read-ExactJsonObject -Path $manifestPath -ExpectedProperties @('files', 'schema_version', 'source_revision', 'version') -Label 'ZIP runtime manifest'
    Assert-TrustedRuntimeAcl -Path $receiptPath
    Assert-TrustedRuntimeAcl -Path $manifestPath
    if (
        [string]$receipt.sha256 -notmatch '^[0-9a-f]{64}$' -or
        -not ($receipt.size -is [int] -or $receipt.size -is [long]) -or
        $receipt.size -le 0 -or
        [string]$receipt.version -ne [string]$SelectorValue.version -or
        $manifest.schema_version -ne 1 -or
        [string]$manifest.version -ne [string]$SelectorValue.version -or
        [string]$manifest.source_revision -notmatch '^[0-9a-f]{40}$' -or
        [string]$manifest.source_revision -ne [string]$SelectorValue.source_revision -or
        -not ($manifest.files -is [array]) -or
        @($manifest.files).Count -eq 0
    ) { throw 'Selected ZIP runtime metadata is invalid.' }
    $listed = @{}
    foreach ($file in @($manifest.files)) {
        if ($null -eq $file -or
            [string]::Join('|', @($file.PSObject.Properties.Name | Sort-Object)) -ne 'path|sha256|size' -or
            [string]$file.path -notmatch '^[^/\\:]+(?:/[^/\\:]+)*$' -or
            @(([string]$file.path).Split('/') | Where-Object { $_ -in @('.', '..') }).Count -gt 0 -or
            [string]$file.path -in @('endpoint-update-manifest.json', '.endpoint-update.json', '.endpoint-msi-runtime.json') -or
            [string]$file.sha256 -notmatch '^[0-9a-f]{64}$' -or
            -not ($file.size -is [int] -or $file.size -is [long]) -or $file.size -lt 0 -or
            $listed.ContainsKey([string]$file.path)
        ) { throw 'Selected ZIP runtime manifest is invalid.' }
        $listed[[string]$file.path] = $true
        $filePath = Join-Path $runtimeDirectory (([string]$file.path).Replace('/', '\'))
        $fact = Get-SafeFileFact -Path $filePath
        Assert-TrustedRuntimeAcl -Path $filePath
        if (-not $fact.regular -or $fact.reparse -or
            (Get-Item -LiteralPath $filePath).Length -ne $file.size -or
            (Get-FileSha256 -Path $filePath) -ne [string]$file.sha256
        ) { throw 'Selected ZIP runtime manifest file mismatch.' }
    }
    if (-not $listed.ContainsKey('pc_agent.exe')) {
        throw 'Selected ZIP runtime manifest lacks the executable.'
    }
    $actual = @{}
    foreach ($item in @(Get-ChildItem -LiteralPath $runtimeDirectory -Recurse -Force)) {
        if ($item.PSIsContainer) {
            Assert-NoReparsePointInPath -Path $item.FullName
            Assert-TrustedRuntimeAcl -Path $item.FullName
            continue
        }
        $relative = $item.FullName.Substring($runtimeDirectory.Length).TrimStart('\').Replace('\', '/')
        $actual[$relative] = $true
    }
    if ($actual.Count -ne $listed.Count + 2 -or
        -not $actual.ContainsKey('.endpoint-update.json') -or
        -not $actual.ContainsKey('endpoint-update-manifest.json') -or
        @($listed.Keys | Where-Object { -not $actual.ContainsKey($_) }).Count -ne 0
    ) { throw 'Selected ZIP runtime inventory mismatch.' }
    return [ordered]@{
        origin = 'zip'
        bundle_sha256 = [string]$receipt.sha256
        bundle_size = [long]$receipt.size
        bundle_manifest_verified = $true
        bundle_receipt_verified = $true
        bundle_acl_protected = $true
    }
}

function Assert-ExpectedCompletion {
    param($Completion)
    if ($null -eq $Completion) { throw 'Expected completion proof is missing.' }
    $fields = @($Completion.PSObject.Properties.Name | Sort-Object)
    $parsedTimestamp = [DateTimeOffset]::MinValue
    if ([string]::Join('|', $fields) -ne 'capability|command_id|duration_ms|result_item_count|status|timestamp') { throw 'Expected completion proof schema is invalid.' }
    if (
        [string]$Completion.command_id -ne $ExpectedCommandId -or
        [string]$Completion.capability -ne $ExpectedCapability -or
        [string]$Completion.status -ne 'succeeded' -or
        -not ($Completion.duration_ms -is [int] -or $Completion.duration_ms -is [long]) -or $Completion.duration_ms -lt 0 -or
        -not ($Completion.result_item_count -is [int] -or $Completion.result_item_count -is [long]) -or $Completion.result_item_count -lt 0 -or
        -not [DateTimeOffset]::TryParse([string]$Completion.timestamp, [ref]$parsedTimestamp)
    ) { throw 'Expected completion proof is invalid.' }
}

try {
    $fleet = $null
    if (-not [string]::IsNullOrEmpty($SetupPath)) {
        if ([string]::IsNullOrEmpty($TargetVersion)) { throw 'TargetVersion is required with SetupPath.' }
        $fleet = Read-CanonicalSetupPreflight -Path $SetupPath -TargetVersion $TargetVersion
    } elseif ($FleetEligibilityOnly -or -not [string]::IsNullOrEmpty($TargetVersion)) {
        throw 'Canonical SetupPath is required for fleet eligibility.'
    }
    if ($FleetEligibilityOnly) { Write-PreflightReport -Payload $fleet; return }
    if ($RequireCompletion -and ([string]::IsNullOrEmpty($ExpectedCommandId) -or [string]::IsNullOrEmpty($ExpectedCapability))) {
        throw 'Completion requirement is incomplete.'
    }
    if (-not $RequireCompletion -and (-not [string]::IsNullOrEmpty($ExpectedCommandId) -or -not [string]::IsNullOrEmpty($ExpectedCapability))) {
        throw 'Completion expectation requires RequireCompletion.'
    }
    if ($RequireCompletion -and $ExpectedCapability -ne $CanaryCapability) { throw 'Completion capability is invalid.' }

    $agent = Get-ServiceFact -Name $AgentServiceName
    $updater = Get-ServiceFact -Name $UpdaterServiceName
    $serviceHost = Join-Path $ExpectedInstallRoot 'endpoint-agent-service.exe'
    $selector = Join-Path $ExpectedInstallRoot 'current.json'
    $selectorFact = Get-SafeFileFact -Path $selector
    $selectorValue = Read-ExactJsonObject -Path $selector -ExpectedProperties @('schema_version', 'source_revision', 'version') -Label 'Runtime selector'
    if ($selectorValue.schema_version -ne 1 -or [string]$selectorValue.version -notmatch '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' -or [string]$selectorValue.source_revision -notmatch '^[0-9a-f]{40}$') {
        throw 'Runtime selector values are invalid.'
    }
    $runtimePath = Join-Path (Join-Path (Join-Path $ExpectedInstallRoot 'versions') $selectorValue.version) 'pc_agent.exe'
    $runtimeFact = Get-SafeFileFact -Path $runtimePath
    $children = @(
        Get-CimInstance Win32_Process -Filter "ParentProcessId=$($agent.pid)" | Where-Object {
            -not ([string]$_.ExecutablePath).Equals($ConsoleHostPath, [StringComparison]::OrdinalIgnoreCase)
        } | ForEach-Object {
            $childFact = Get-SafeFileFact -Path $_.ExecutablePath
            [ordered]@{
                path = $_.ExecutablePath
                regular = $childFact.regular
                reparse = $childFact.reparse
                service_child = $_.CommandLine -match '--windows-service-child'
                safe_command = $_.CommandLine -notmatch '(?i)(token|claim|password|helpdesk|gateway_http_pull)'
            }
        }
    )
    $hostFact = Get-SafeFileFact -Path $serviceHost
    $dataAcl = Get-AclSummary -DataRoot $ExpectedDataRoot
    $protectedFile = Get-SafeFileFact -Path (Join-Path $ExpectedDataRoot 'device-credential')
    $identityFile = Get-SafeFileFact -Path (Join-Path $ExpectedDataRoot 'enrollment-identity.json')
    $statusFile = Get-SafeFileFact -Path (Join-Path $ExpectedDataRoot 'canary-status.json')
    $status = Read-CanaryStatus -DataRoot $ExpectedDataRoot -ExpectedEndpointHost $ExpectedEndpointHost
    if ($null -ne $fleet) {
        if ($fleet.pending.active_or_degraded -or $fleet.provenance.conflict -or -not $fleet.provenance.verified -or
            -not $fleet.foundation.native_verified -or -not $fleet.core.verified -or
            $fleet.core.version -cne $selectorValue.version -or $fleet.core.source_revision -cne $selectorValue.source_revision) { throw 'Canonical installed ownership is not coherent.' }
        $provenance = $fleet.foundation
        $installerEvidence = @{ hash = $fleet.foundation.package_sha256; cache_fact = @{ regular = $true; reparse = $false } }
        $selectedEvidence = @{ origin = $fleet.core.origin }
        if ($fleet.core.origin -eq 'zip') {
            $selectedEvidence.bundle_sha256 = $fleet.core.package_sha256
            $selectedEvidence.bundle_size = $fleet.core.package_size
            $selectedEvidence.bundle_manifest_verified = $true
            $selectedEvidence.bundle_receipt_verified = $true
            $selectedEvidence.bundle_acl_protected = $true
        }
    } else {
        if (Test-Path -LiteralPath (Join-Path (Split-Path -Parent $ExpectedInstallRoot) 'installer-state\foundation.json')) { throw 'Modern ownership requires canonical SetupPath.' }
        $installerEvidence = Read-InstallerProvenance -DataRoot $ExpectedDataRoot
        $provenance = $installerEvidence.provenance
        if ([string]$selectorValue.version -notin @('3.2.79','3.2.81') -or
            [string]$provenance.version -notin @('3.2.79','3.2.81')) { throw 'Unsupported historical ownership requires canonical SetupPath.' }
        $legacy = @{
            '3.2.79' = @{ package = '2f7d778799f1e32645af7936dfaf3f090d6ad4df5bb883827ea8a0a5d859f72a'; source = 'd9b0fea2b14e34b05e25058e4ee004ea61643ca6'; tree = '06200efd1ee8b2914828e71eef65db8e6dd803318b44047672b8b9dc40c950c4' }
            '3.2.81' = @{ package = 'ad4dc49703513d6dee6fd3e51ac94a09c5967112d58aed4e60a63cf6966251f5'; source = 'c05bb0a528527ed1544c88fb0b1570c64b32084d'; tree = 'a4db007c0e313f6d5b34633aeaad10a2a47f01aeed6444b97021b3e222a580e2' }
        }[[string]$provenance.version]
        if ($installerEvidence.hash -cne $legacy.package -or $provenance.source_revision -cne $legacy.source -or
            $provenance.initial_runtime_tree_sha256 -cne $legacy.tree) { throw 'Unknown legacy package requires canonical SetupPath.' }
        $selectedEvidence = Read-SelectedRuntimeEvidence -InstallRoot $ExpectedInstallRoot -SelectorValue $selectorValue -InstallerProvenance $provenance
    }
    if ([string]$status.release.version -ne [string]$selectorValue.version -or [string]$status.release.source_revision -ne [string]$selectorValue.source_revision) {
        throw 'Canary status does not match the selected runtime.'
    }
    $completionStatus = $status
    if ($RequireCompletion) {
        # An atomic runtime status publication can briefly race this collector.
        # Re-read the same protected fixed path a bounded number of times; do
        # not accept a missing or mismatched terminal marker.
        for ($attempt = 0; $attempt -lt 5; $attempt++) {
            $completionStatus = Read-CanaryStatus -DataRoot $ExpectedDataRoot -ExpectedEndpointHost $ExpectedEndpointHost
            if ($null -ne $completionStatus.completion_proof) { break }
            Start-Sleep -Seconds 1
        }
        Assert-ExpectedCompletion -Completion $completionStatus.completion_proof
    }

    $runtimeProjection = [ordered]@{ origin = [string]$selectedEvidence.origin; selector_regular = $selectorFact.regular; selector_reparse = $selectorFact.reparse; selector_version = [string]$selectorValue.version; selector_source_revision = [string]$selectorValue.source_revision; selected_runtime_present = $runtimeFact.regular -and -not $runtimeFact.reparse; http_fallback = [bool]$status.transport.http_fallback; helpdesk_reference = $false }
    if ($selectedEvidence.origin -eq 'zip') {
        foreach ($key in @('bundle_sha256', 'bundle_size', 'bundle_manifest_verified', 'bundle_receipt_verified', 'bundle_acl_protected')) {
            $runtimeProjection[$key] = $selectedEvidence[$key]
        }
    }
    $payload = [ordered]@{
        schema_version = 'windows_agent_preflight_v1'
        agent = [ordered]@{ platform = 'windows_amd64'; source_revision = [string]$selectorValue.source_revision; version = [string]$selectorValue.version }
        services = [ordered]@{
            agent = [ordered]@{ name = $agent.name; start_mode = $agent.start_mode; state = $agent.state; account = $agent.account; pid_present = $agent.pid_present; host = [ordered]@{ path = $hostFact.path; regular = $hostFact.regular; reparse = $hostFact.reparse; fixed_entrypoint = $agent.path_name -match 'endpoint-agent-service\.exe' }; runtime_children = $children }
            updater = [ordered]@{ name = $updater.name; start_mode = $updater.start_mode; state = $updater.state; account = $updater.account; regular = $true; listener = $false; safe_command = $updater.path_name -notmatch '(?i)https?://' }
        }
        runtime = $runtimeProjection
        msi = [ordered]@{ version = [string]$provenance.version; source_revision = [string]$provenance.source_revision; product_code = [string]$provenance.product_code; sha256 = [string]$installerEvidence.hash; owned_files = $installerEvidence.cache_fact.regular -and -not $installerEvidence.cache_fact.reparse }
        acl = [ordered]@{ data_root_protected = $dataAcl.data_root_protected; required_principals = $dataAcl.required_principals; ordinary_user_read = $dataAcl.ordinary_user_read; protected_file_regular = $protectedFile.regular; protected_file_reparse = $protectedFile.reparse; status_artifact_protected = $dataAcl.status_artifact_protected; provenance_artifact_protected = $true; msi_artifact_protected = $true }
        safe_status = [ordered]@{ service = $agent.state.ToLowerInvariant(); identity_present = $identityFile.regular -and -not $identityFile.reparse; regular = $statusFile.regular; reparse = $statusFile.reparse; release_version = [string]$status.release.version; release_source_revision = [string]$status.release.source_revision }
        network = [ordered]@{ strict_tls = [bool]$status.transport.strict_tls; hostname_valid = [bool]$status.transport.hostname_valid; redirected = [bool]$status.transport.redirected; gateway_wss = [bool]$status.transport.gateway_wss; http_fallback = [bool]$status.transport.http_fallback; capability = [string]$status.capability }
        completion_proof = $completionStatus.completion_proof
    }
    if ($null -ne $fleet) { $payload.fleet_preflight = $fleet }
    Write-PreflightReport -Payload $payload
}
catch {
    Write-Error 'Windows agent preflight collection failed.'
    exit 2
}
