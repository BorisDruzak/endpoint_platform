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
    [string]$ExpectedCapability
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$AgentServiceName = 'EndpointAgent'
$UpdaterServiceName = 'EndpointAgentUpdater'
$CanaryCapability = 'context.diagnostic.collect'
$SystemSid = 'S-1-5-18'
$AdministratorsSid = 'S-1-5-32-544'
$LocalServiceSid = 'S-1-5-19'

function Assert-NoReparsePointInPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    $current = Get-Item -LiteralPath $Path -Force
    while ($null -ne $current) {
        if ([bool]($current.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'A required path contains a reparse point.'
        }
        $parent = $current.Parent
        if ($null -eq $parent -or $parent.FullName -eq $current.FullName) { break }
        $current = $parent
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
    $hash = (Get-FileHash -LiteralPath $cachePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($hash -ne [string]$provenance.package_sha256) { throw 'Installer cache hash is invalid.' }
    $installer = New-Object -ComObject WindowsInstaller.Installer
    if ($installer.ProductState([string]$provenance.product_code) -ne 5) { throw 'MSI product is not installed.' }
    if ([string]$installer.ProductInfo([string]$provenance.product_code, 'VersionString') -ne [string]$provenance.version) {
        throw 'Installed MSI version is invalid.'
    }
    return [ordered]@{ provenance = $provenance; cache_fact = $cacheFact; hash = $hash }
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
        -not ($Completion.duration_ms -is [long]) -or $Completion.duration_ms -lt 0 -or
        -not ($Completion.result_item_count -is [long]) -or $Completion.result_item_count -lt 0 -or
        -not [DateTimeOffset]::TryParse([string]$Completion.timestamp, [ref]$parsedTimestamp)
    ) { throw 'Expected completion proof is invalid.' }
}

try {
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
        Get-CimInstance Win32_Process -Filter "ParentProcessId=$($agent.pid)" | ForEach-Object {
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
    $installerEvidence = Read-InstallerProvenance -DataRoot $ExpectedDataRoot
    $provenance = $installerEvidence.provenance
    if ([string]$provenance.version -ne [string]$selectorValue.version -or [string]$provenance.source_revision -ne [string]$selectorValue.source_revision) {
        throw 'Installer provenance does not match the selected runtime.'
    }
    if ([string]$status.release.version -ne [string]$selectorValue.version -or [string]$status.release.source_revision -ne [string]$selectorValue.source_revision) {
        throw 'Canary status does not match the selected runtime.'
    }
    if ($RequireCompletion) { Assert-ExpectedCompletion -Completion $status.completion_proof }

    $payload = [ordered]@{
        schema_version = 'windows_agent_preflight_v1'
        agent = [ordered]@{ platform = 'windows_amd64'; source_revision = [string]$selectorValue.source_revision; version = [string]$selectorValue.version }
        services = [ordered]@{
            agent = [ordered]@{ name = $agent.name; start_mode = $agent.start_mode; state = $agent.state; account = $agent.account; pid_present = $agent.pid_present; host = [ordered]@{ path = $hostFact.path; regular = $hostFact.regular; reparse = $hostFact.reparse; fixed_entrypoint = $agent.path_name -match 'endpoint-agent-service\.exe' }; runtime_children = $children }
            updater = [ordered]@{ name = $updater.name; start_mode = $updater.start_mode; state = $updater.state; account = $updater.account; regular = $true; listener = $false; safe_command = $updater.path_name -notmatch '(?i)https?://' }
        }
        runtime = [ordered]@{ selector_regular = $selectorFact.regular; selector_reparse = $selectorFact.reparse; selector_version = [string]$selectorValue.version; selector_source_revision = [string]$selectorValue.source_revision; selected_runtime_present = $runtimeFact.regular -and -not $runtimeFact.reparse; http_fallback = [bool]$status.transport.http_fallback; helpdesk_reference = $false }
        msi = [ordered]@{ version = [string]$provenance.version; sha256 = [string]$installerEvidence.hash; owned_files = $installerEvidence.cache_fact.regular -and -not $installerEvidence.cache_fact.reparse }
        acl = [ordered]@{ data_root_protected = $dataAcl.data_root_protected; required_principals = $dataAcl.required_principals; ordinary_user_read = $dataAcl.ordinary_user_read; protected_file_regular = $protectedFile.regular; protected_file_reparse = $protectedFile.reparse; status_artifact_protected = $dataAcl.status_artifact_protected; provenance_artifact_protected = $true; msi_artifact_protected = $true }
        safe_status = [ordered]@{ service = $agent.state.ToLowerInvariant(); identity_present = $identityFile.regular -and -not $identityFile.reparse; regular = $statusFile.regular; reparse = $statusFile.reparse; release_version = [string]$status.release.version; release_source_revision = [string]$status.release.source_revision }
        network = [ordered]@{ strict_tls = [bool]$status.transport.strict_tls; hostname_valid = [bool]$status.transport.hostname_valid; redirected = [bool]$status.transport.redirected; gateway_wss = [bool]$status.transport.gateway_wss; http_fallback = [bool]$status.transport.http_fallback; capability = [string]$status.capability }
        completion_proof = $status.completion_proof
    }
    $directory = Split-Path -Parent $OutputPath
    New-Item -ItemType Directory -Force -Path $directory | Out-Null
    [IO.File]::WriteAllText($OutputPath, ($payload | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
}
catch {
    Write-Error 'Windows agent preflight collection failed.'
    exit 2
}
