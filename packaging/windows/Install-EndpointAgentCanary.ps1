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
$ManagedServiceNames = @('EndpointAgent', 'EndpointAgentUpdater')
$WindowsInstallerServiceName = 'msiserver'
$ManagedServiceTimeout = [TimeSpan]::FromSeconds(45)

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

function Stop-ManagedAgentServices {
    $previousStates = @{}
    foreach ($serviceName in $ManagedServiceNames) {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($null -eq $service) {
            continue
        }
        $previousStates[$serviceName] = $service.Status
        if ($service.Status -eq [ServiceProcess.ServiceControllerStatus]::Stopped) {
            continue
        }
        Stop-Service -Name $serviceName -ErrorAction Stop
        $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, $ManagedServiceTimeout)
        $service.Refresh()
        if ($service.Status -ne [ServiceProcess.ServiceControllerStatus]::Stopped) {
            throw "Managed service $serviceName did not stop before MSI installation."
        }
    }
    return $previousStates
}

function Start-ManagedEndpointAgent {
    $service = Get-Service -Name 'EndpointAgent' -ErrorAction SilentlyContinue
    if ($null -eq $service) {
        return
    }
    if ($service.Status -ne [ServiceProcess.ServiceControllerStatus]::Running) {
        Start-Service -Name 'EndpointAgent' -ErrorAction Stop
        $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running, $ManagedServiceTimeout)
        $service.Refresh()
    }
    if ($service.Status -ne [ServiceProcess.ServiceControllerStatus]::Running) {
        throw 'EndpointAgent did not start after MSI installation.'
    }
}

function Start-WindowsInstaller {
    $service = Get-Service -Name $WindowsInstallerServiceName -ErrorAction Stop
    if ($service.Status -ne [ServiceProcess.ServiceControllerStatus]::Running) {
        Start-Service -Name $WindowsInstallerServiceName -ErrorAction Stop
        $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running, $ManagedServiceTimeout)
        $service.Refresh()
    }
    if ($service.Status -ne [ServiceProcess.ServiceControllerStatus]::Running) {
        throw 'Windows Installer service did not start before MSI installation.'
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

function New-UpdateTransaction {
    $name = 'Global\EndpointPlatform.Agent.UpdateTransaction'
    $serviceSids = @('S-1-5-80-1102781572-1373263041-1070489469-7526906-1468061691', 'S-1-5-80-327494974-20047353-929432329-1920152597-707704661')
    $script:UpdateMutexRights = @{'S-1-5-18'=0x1f0001; 'S-1-5-32-544'=0x1f0001; 'S-1-3-4'=0x20000}
    foreach ($sid in $serviceSids) { $script:UpdateMutexRights[$sid] = 0x120001 }
    $script:UpdateTrustedOwners = @('S-1-5-18','S-1-5-32-544','S-1-5-19') + $serviceSids
    $sddl = 'D:P(A;;0x1f0001;;;S-1-5-18)(A;;0x1f0001;;;S-1-5-32-544)(A;;0x120001;;;S-1-5-80-1102781572-1373263041-1070489469-7526906-1468061691)(A;;0x120001;;;S-1-5-80-327494974-20047353-929432329-1920152597-707704661)(A;;0x20000;;;S-1-3-4)'
    $security = [Security.AccessControl.MutexSecurity]::new()
    $security.SetSecurityDescriptorSddlForm($sddl)
    $security.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    $created = $false
    return [Threading.Mutex]::new($false, $name, [ref]$created, $security)
}

function Assert-UpdateTransactionSecurity {
    param($Mutex)
    $security = $Mutex.GetAccessControl()
    $raw = [Security.AccessControl.RawSecurityDescriptor]::new($security.GetSecurityDescriptorBinaryForm(), 0)
    if ($raw.Owner.Value -notin $script:UpdateTrustedOwners -or -not $security.AreAccessRulesProtected -or $null -eq $raw.DiscretionaryAcl -or $raw.DiscretionaryAcl.Count -ne 5) { throw 'Invalid update mutex security.' }
    $seen = @{}
    foreach ($ace in $raw.DiscretionaryAcl) {
        $sid = $ace.SecurityIdentifier.Value
        if ($ace.AceType -ne [Security.AccessControl.AceType]::AccessAllowed -or $ace.AceFlags -ne 0 -or $seen.ContainsKey($sid) -or -not $script:UpdateMutexRights.ContainsKey($sid) -or $ace.AccessMask -ne $script:UpdateMutexRights[$sid]) { throw 'Invalid update mutex ACE.' }
        $seen[$sid] = $true
    }
}

function Assert-UpdateGateAcl {
    param([string]$Path)
    $acl = Get-Acl -LiteralPath $Path
    $raw = [Security.AccessControl.RawSecurityDescriptor]::new($acl.GetSecurityDescriptorBinaryForm(),0)
    if ($null -eq $raw.DiscretionaryAcl) { throw 'Update state has a null DACL.' }
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($owner -notin $script:UpdateTrustedOwners) { throw 'Invalid update state owner.' }
    foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or (([int64]$rule.FileSystemRights -band 0x500d0156) -ne 0 -and $rule.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544','S-1-5-80-1102781572-1373263041-1070489469-7526906-1468061691','S-1-5-80-327494974-20047353-929432329-1920152597-707704661'))) { throw 'Invalid update state writer.' }
    }
}

function Read-UpdateGateState {
    param([string]$Path, [int]$Limit)
    Assert-ExistingPathChain -Path $Path
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    Assert-RegularNonReparseFile -Path $Path -Label 'Update state'
    Assert-UpdateGateAcl -Path $Path
    $stream = [IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        if ($stream.Length -le 0 -or $stream.Length -gt $Limit) { throw 'Invalid update state length.' }
        $bytes = [byte[]]::new([int]$stream.Length)
        $count = 0
        while ($count -lt $bytes.Length) {
            $read = $stream.Read($bytes,$count,$bytes.Length-$count)
            if ($read -le 0) { throw 'Short update state read.' }
            $count += $read
        }
    } finally { $stream.Dispose() }
    # The XML JSON reader retains duplicate object keys, unlike ConvertFrom-Json.
    Add-Type -AssemblyName System.Runtime.Serialization
    Add-Type -AssemblyName System.Web.Extensions
    $reader = [Runtime.Serialization.Json.JsonReaderWriterFactory]::CreateJsonReader($bytes,[Xml.XmlDictionaryReaderQuotas]::Max)
    try {
        $document = [Xml.XmlDocument]::new()
        $document.Load($reader)
        foreach ($node in $document.SelectNodes('//*[@type="object"]')) {
            $keys = @{}
            foreach ($child in $node.ChildNodes) {
                if ($keys.ContainsKey($child.LocalName)) { throw 'Duplicate update state key.' }
                $keys[$child.LocalName] = $true
            }
        }
    } finally { $reader.Close() }
    $json = [Web.Script.Serialization.JavaScriptSerializer]::new()
    $json.MaxJsonLength = 4194304
    $json.RecursionLimit = 64
    return @{ Value = $json.DeserializeObject([Text.UTF8Encoding]::new($false,$true).GetString($bytes)) }
}

function Test-UpdateDeliveryTime {
    param($Value)
    if ($null -eq $Value) { return $true }
    $parsed = [DateTimeOffset]::MinValue
    return ($Value -is [string] -and $Value -match '(Z|[+-][0-9]{2}:[0-9]{2})$' -and [DateTimeOffset]::TryParse($Value,[ref]$parsed))
}

function Test-ActiveUpdateState {
    param([string]$InstallRoot,[string]$DataRoot)
    $updates = Join-Path $DataRoot 'updates'
    foreach ($root in @($InstallRoot,$DataRoot,$updates)) {
        Assert-ExistingPathChain -Path $root
        if (Test-Path -LiteralPath $root) { Assert-UpdateGateAcl -Path $root }
    }
    $active = $false
    $versionPattern = '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:[-+][0-9A-Za-z.-]+)?$'
    $leaves = @(
        @((Join-Path $updates 'pending_update.json'),16384,@('operation_id','version')),
        @((Join-Path $updates 'startup-attempt.json'),4096,@('operation_id','version','attempt_id')),
        @((Join-Path $updates 'terminal-outcome.json'),4096,@('operation_id','reported_version','status','safe_code')),
        @((Join-Path $InstallRoot 'current-restore.json'),4096,@('version')),
        @((Join-Path $InstallRoot 'selector-transition.json'),16384,@('operation_id','attempt_id','candidate','previous_bytes','status'))
    )
    foreach ($leaf in $leaves) {
        $state = Read-UpdateGateState -Path $leaf[0] -Limit $leaf[1]
        if ($null -ne $state) {
            if ($state.Value -isnot [Collections.IDictionary]) { throw 'Invalid lifecycle state.' }
            foreach ($key in $leaf[2]) {
                if (-not $state.Value.ContainsKey($key) -or $null -eq $state.Value[$key] -or $state.Value[$key] -ceq '') { throw 'Invalid lifecycle identity.' }
            }
            foreach ($key in $leaf[2]) {
                $value = $state.Value[$key]
                if ($key -eq 'candidate') {
                    if ($value -isnot [Collections.IDictionary] -or -not $value.ContainsKey('version') -or $value.version -isnot [string] -or $value.version -cnotmatch $versionPattern) { throw 'Invalid candidate identity.' }
                } elseif ($value -isnot [string] -or $value.Length -lt 1 -or $value.Length -gt 8192) { throw 'Invalid lifecycle field.' }
            }
            foreach ($key in @('version','reported_version')) {
                if ($state.Value.ContainsKey($key) -and ($state.Value[$key] -isnot [string] -or $state.Value[$key] -cnotmatch $versionPattern)) { throw 'Invalid lifecycle version.' }
            }
            if ($state.Value.ContainsKey('status')) {
                $allowed = if ($leaf[0] -eq (Join-Path $InstallRoot 'selector-transition.json')) { @('prepared','accepted') } else { @('failed','rolled_back') }
                if ($state.Value.status -cnotin $allowed) { throw 'Invalid lifecycle status.' }
            }
            $active = $true
        }
    }
    $idPattern = '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    $versionPattern = '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:[-+][0-9A-Za-z.-]+)?$'
    $codes = @{failed='launcher_apply_failed'; rolled_back='launcher_rolled_back'; applied='post_restart_handshake_confirmed'}
    $delivered = @{}; $keys = @{}; $identities = @{}
    $state = Read-UpdateGateState -Path (Join-Path $updates 'endpoint_update_reports.json') -Limit 4194304
    if ($null -ne $state) {
        if ($state.Value -isnot [array]) { throw 'Invalid report journal.' }
        foreach ($record in $state.Value) {
            if ($record -isnot [Collections.IDictionary] -or [string]::Join('|',@($record.Keys | Sort-Object)) -ne 'delivered_at|operation_id|report_key|reported_version|safe_code|status') { throw 'Invalid report fields.' }
            $identity = [string]::Join('|',@($record.operation_id,$record.status,$record.reported_version,$record.safe_code))
            if ($record.operation_id -isnot [string] -or $record.operation_id -cnotmatch $idPattern -or $record.report_key -isnot [string] -or $record.report_key -cnotmatch '^[0-9a-f]{32}$' -or $record.reported_version -isnot [string] -or $record.reported_version -cnotmatch $versionPattern -or $record.status -isnot [string] -or -not $codes.ContainsKey($record.status) -or $record.safe_code -cne $codes[$record.status] -or -not (Test-UpdateDeliveryTime $record.delivered_at) -or $keys.ContainsKey($record.report_key) -or $identities.ContainsKey($identity)) { throw 'Invalid report identity.' }
            $keys[$record.report_key]=$true; $identities[$identity]=$true
            if ($null -eq $record.delivered_at) { $active=$true } else { $delivered[$record.operation_id]=$true }
        }
    }
    $seen = @{}
    $state = Read-UpdateGateState -Path (Join-Path $updates 'endpoint_update_state.json') -Limit 262144
    if ($null -ne $state) {
        if ($state.Value -isnot [array]) { throw 'Invalid handoff journal.' }
        foreach ($record in $state.Value) {
            if ($record -isnot [Collections.IDictionary] -or [string]::Join('|',@($record.Keys | Sort-Object)) -ne 'assigned_version|operation_id|rollback_version|scheduled_ack_delivered_at') { throw 'Invalid handoff fields.' }
            if ($record.operation_id -isnot [string] -or $record.operation_id -cnotmatch $idPattern -or $record.assigned_version -isnot [string] -or $record.assigned_version -cnotmatch $versionPattern -or $record.rollback_version -isnot [string] -or $record.rollback_version -cnotmatch $versionPattern -or -not (Test-UpdateDeliveryTime $record.scheduled_ack_delivered_at) -or $seen.ContainsKey($record.operation_id)) { throw 'Invalid handoff identity.' }
            $seen[$record.operation_id]=$true
            if (-not $delivered.ContainsKey($record.operation_id)) { $active=$true }
        }
    }
    return $active
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

$updateMutex = $null
$transactionOwned = $false
try {
    try {
        $updateMutex = New-UpdateTransaction
        Assert-UpdateTransactionSecurity -Mutex $updateMutex
        try { $transactionOwned = $updateMutex.WaitOne(30000) }
        catch [Threading.AbandonedMutexException] { $transactionOwned = $true }
        if (-not $transactionOwned) { exit 61 }
        Assert-UpdateTransactionSecurity -Mutex $updateMutex
        $gateInstallRoot = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)) 'Endpoint Platform\Agent'
        $gateDataRoot = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)) 'Endpoint Platform\Agent'
        if (Test-ActiveUpdateState -InstallRoot $gateInstallRoot -DataRoot $gateDataRoot) { exit 61 }
    } catch { Write-Error 'UPDATE_STATE_INVALID' -ErrorAction Continue; exit 62 }

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

$serviceHost = Join-Path $gateInstallRoot 'endpoint-agent-service.exe'
if (Test-Path -LiteralPath $serviceHost) {
    Assert-ExistingPathChain -Path $serviceHost
    Assert-RegularNonReparseFile -Path $serviceHost -Label 'Canonical service host'
    $trayStop = Start-Process -FilePath $serviceHost -ArgumentList '--stop-tray-companions' -WindowStyle Hidden -Wait -PassThru
    if ($trayStop.ExitCode -ne 0) { throw 'TRAY_SHUTDOWN_FAILED' }
}
$previousServiceStates = Stop-ManagedAgentServices
$installationCompleted = $false
try {
    Start-WindowsInstaller
    $quotedExecutionCachePath = '"{0}"' -f $executionCachePath
    $installer = Start-Process -FilePath 'msiexec.exe' -ArgumentList @('/i', $quotedExecutionCachePath, '/qn', '/norestart') -Wait -PassThru
    if ($installer.ExitCode -ne 0) {
        throw "MSI installation failed with exit code $($installer.ExitCode)."
    }
    $installedMsi = New-Object -ComObject WindowsInstaller.Installer
    if ($installedMsi.ProductState([string]$manifest.product_code) -ne 5) {
        throw 'Installed MSI product code does not match release manifest.'
    }
    if ([string]$installedMsi.ProductInfo([string]$manifest.product_code, 'VersionString') -ne [string]$manifest.version) {
        throw 'Installed MSI version does not match release manifest.'
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
    if (Test-Path -LiteralPath $cachePath) {
        Assert-CacheArtifactProtection -Path $cachePath
    }
    else {
        $cacheStagePath = Join-Path $cacheDirectory ("EndpointAgent-" + [guid]::NewGuid().ToString('N') + '.tmp')
        try {
            Copy-Item -LiteralPath $executionCachePath -Destination $cacheStagePath
            Set-CacheArtifactProtection -Path $cacheStagePath
            if ((Get-FileHash -LiteralPath $cacheStagePath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $inputHash) {
                throw 'Installed MSI cache SHA-256 does not match release manifest.'
            }
            [IO.File]::Move($cacheStagePath, $cachePath)
        }
        finally {
            if (Test-Path -LiteralPath $cacheStagePath) { Remove-Item -LiteralPath $cacheStagePath -Force }
        }
    }
    if ((Get-FileHash -LiteralPath $cachePath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $inputHash) {
        throw 'Installed MSI cache SHA-256 does not match release manifest.'
    }
    Assert-CacheArtifactProtection -Path $cachePath

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
    $provenanceStagePath = Join-Path $cacheRoot ("installer-provenance-" + [guid]::NewGuid().ToString('N') + '.tmp')
    $provenanceBackupPath = Join-Path $cacheRoot ("installer-provenance-" + [guid]::NewGuid().ToString('N') + '.bak')
    $hadPreviousProvenance = Test-Path -LiteralPath $provenancePath
    try {
        [IO.File]::WriteAllText(
            $provenanceStagePath,
            ($provenance | ConvertTo-Json -Compress),
            [Text.UTF8Encoding]::new($false)
        )
        Set-CacheArtifactProtection -Path $provenanceStagePath
        Assert-CacheArtifactProtection -Path $provenanceStagePath
        if ($hadPreviousProvenance) { Assert-CacheArtifactProtection -Path $provenancePath }
        Start-ManagedEndpointAgent
        if ($hadPreviousProvenance) {
            [IO.File]::Replace($provenanceStagePath, $provenancePath, $provenanceBackupPath)
        }
        else {
            [IO.File]::Move($provenanceStagePath, $provenancePath)
        }
        Assert-CacheArtifactProtection -Path $provenancePath
        $installationCompleted = $true
    }
    catch {
        if (Test-Path -LiteralPath $provenanceBackupPath) {
            [IO.File]::Replace($provenanceBackupPath, $provenancePath, $null)
        }
        elseif (-not $hadPreviousProvenance -and (Test-Path -LiteralPath $provenancePath)) {
            Remove-Item -LiteralPath $provenancePath -Force
        }
        throw
    }
    finally {
        if (Test-Path -LiteralPath $provenanceStagePath) { Remove-Item -LiteralPath $provenanceStagePath -Force }
        if (Test-Path -LiteralPath $provenanceBackupPath) { Remove-Item -LiteralPath $provenanceBackupPath -Force }
    }
}
finally {
    if (-not $installationCompleted -and $previousServiceStates['EndpointAgent'] -eq [ServiceProcess.ServiceControllerStatus]::Running) {
        Start-ManagedEndpointAgent
    }
}

} finally {
    if ($transactionOwned) { $updateMutex.ReleaseMutex() }
    if ($null -ne $updateMutex) { $updateMutex.Dispose() }
}
