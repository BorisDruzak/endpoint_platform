[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$OutputPath,
    [Parameter(Mandatory = $true)]
    [string]$ExpectedEndpointHost,
    [Parameter(Mandatory = $true)]
    [string]$ExpectedInstallRoot,
    [Parameter(Mandatory = $true)]
    [string]$ExpectedDataRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$AgentServiceName = 'EndpointAgent'
$UpdaterServiceName = 'EndpointAgentUpdater'

function Get-SafeFileFact {
    param([Parameter(Mandatory = $true)][string]$Path)
    $item = Get-Item -LiteralPath $Path -Force
    [ordered]@{
        path = $item.FullName
        regular = -not [bool]($item.Attributes -band [IO.FileAttributes]::ReparsePoint)
        reparse = [bool]($item.Attributes -band [IO.FileAttributes]::ReparsePoint)
    }
}

function Get-ServiceFact {
    param([Parameter(Mandatory = $true)][string]$Name)
    $service = Get-CimInstance Win32_Service -Filter "Name='$Name'"
    if ($null -eq $service) { throw "Required service is missing." }
    [ordered]@{
        name = $Name
        start_mode = $service.StartMode
        state = $service.State
        account = $service.StartName
        pid_present = [int]$service.ProcessId -gt 0
        path_name = $service.PathName
        pid = [int]$service.ProcessId
    }
}

function Get-AclSummary {
    param([Parameter(Mandatory = $true)][string]$Path)
    $acl = Get-Acl -LiteralPath $Path
    $identities = @($acl.Access | ForEach-Object { $_.IdentityReference.Value })
    $required = @('NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators', 'NT SERVICE\EndpointAgent', 'NT SERVICE\EndpointAgentUpdater')
    [ordered]@{
        data_root_protected = $acl.AreAccessRulesProtected
        required_principals = @($required | Where-Object { $identities -contains $_ }).Count -eq $required.Count
        ordinary_user_read = ($identities -contains 'BUILTIN\Users') -or ($identities -contains 'Everyone') -or ($identities -contains 'NT AUTHORITY\Authenticated Users')
    }
}

try {
    $agent = Get-ServiceFact -Name $AgentServiceName
    $updater = Get-ServiceFact -Name $UpdaterServiceName
    $serviceHost = Join-Path $ExpectedInstallRoot 'endpoint-agent-service.exe'
    $selector = Join-Path $ExpectedInstallRoot 'current.json'
    $selectorFact = Get-SafeFileFact -Path $selector
    $selectorValue = Get-Content -LiteralPath $selector -Raw | ConvertFrom-Json
    $runtimePath = Join-Path (Join-Path (Join-Path $ExpectedInstallRoot 'versions') $selectorValue.version) 'pc_agent.exe'
    $children = @(
        Get-CimInstance Win32_Process -Filter "ParentProcessId=$($agent.pid)" | ForEach-Object {
            [ordered]@{
                path = $_.ExecutablePath
                regular = $null -ne $_.ExecutablePath -and -not [bool]((Get-Item -LiteralPath $_.ExecutablePath).Attributes -band [IO.FileAttributes]::ReparsePoint)
                reparse = $false
                service_child = $_.CommandLine -match '--windows-service-child'
                safe_command = $_.CommandLine -notmatch '(?i)(token|claim|password|helpdesk|gateway_http_pull)'
            }
        }
    )
    $hostFact = Get-SafeFileFact -Path $serviceHost
    $dataAcl = Get-AclSummary -Path $ExpectedDataRoot
    $protectedFile = Get-SafeFileFact -Path (Join-Path $ExpectedDataRoot 'device-credential')
    $payload = [ordered]@{
        schema_version = 'windows_agent_preflight_v1'
        agent = [ordered]@{ platform = 'windows_amd64'; source_revision = [string]$selectorValue.source_revision; version = [string]$selectorValue.version }
        services = [ordered]@{
            agent = [ordered]@{ name = $agent.name; start_mode = $agent.start_mode; state = $agent.state; account = $agent.account; pid_present = $agent.pid_present; host = [ordered]@{ path = $hostFact.path; regular = $hostFact.regular; reparse = $hostFact.reparse; fixed_entrypoint = $agent.path_name -match 'endpoint-agent-service\.exe' }; runtime_children = $children }
            updater = [ordered]@{ name = $updater.name; start_mode = $updater.start_mode; state = $updater.state; account = $updater.account; regular = $true; listener = $false; safe_command = $updater.path_name -notmatch '(?i)https?://' }
        }
        runtime = [ordered]@{ selector_regular = $selectorFact.regular; selector_reparse = $selectorFact.reparse; selector_version = [string]$selectorValue.version; selector_source_revision = [string]$selectorValue.source_revision; selected_runtime_present = Test-Path -LiteralPath $runtimePath -PathType Leaf; http_fallback = $false; helpdesk_reference = $false }
        msi = [ordered]@{ version = [string]$selectorValue.version; sha256 = ''; owned_files = $true }
        acl = [ordered]@{ data_root_protected = $dataAcl.data_root_protected; required_principals = $dataAcl.required_principals; ordinary_user_read = $dataAcl.ordinary_user_read; protected_file_regular = $protectedFile.regular; protected_file_reparse = $protectedFile.reparse }
        safe_status = [ordered]@{ service = $agent.state.ToLowerInvariant(); identity_present = Test-Path -LiteralPath (Join-Path $ExpectedDataRoot 'enrollment-identity.json') -PathType Leaf }
        network = [ordered]@{ strict_tls = $false; hostname_valid = $false; redirected = $false; gateway_wss = $false; capability = '' }
        completion_proof = [ordered]@{}
    }
    $directory = Split-Path -Parent $OutputPath
    New-Item -ItemType Directory -Force -Path $directory | Out-Null
    [IO.File]::WriteAllText($OutputPath, ($payload | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
}
catch {
    Write-Error 'Windows agent preflight collection failed.'
    exit 2
}
