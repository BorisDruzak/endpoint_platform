[CmdletBinding()]
param(
    [ValidateSet('Observe', 'ArchivePointer')][string]$Mode = 'Observe',
    [string]$VerifiedServerAttempt
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$assignment = 'c6facd92-88f2-40f3-ab4b-79c33015d34d'
$attempt = '0f57adb5-af9b-4861-b1c0-124774ff3742'
$operation = 'cf85346d-b6af-47f4-bcc3-a815e6aca448'
$machine = 'ec9fbf25104ef29081d96ad0e3a54f3634a592e042e7288652e473049b0e1512'
$expectedActive = 'a8bdabbcd03005feed8dc40a0fe48d89d7f0118ac1f60830efcaefd75b8c3f93'
$expectedJob = '9b54648a84b871f2ee59f94de89f7750407481e89201f8ce5554697bb23efe98'
$program = 'C:\Program Files\Endpoint Platform'
$state = Join-Path $program 'installer-state'
$archive = Join-Path $state "signed-pre-native-abort\$operation"
$observer = 'C:\ProgramData\EndpointPlatformSetupUpdates'
$jobRoot = Join-Path $observer "jobs\$assignment"
$active = Join-Path $observer 'active.json'
$savedActive = Join-Path $jobRoot 'active-before-verified-pre-msi-recovery.json'

function Read-Hash([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer) { throw 'Expected regular recovery evidence file' }
    for ($node = $item; $null -ne $node; $node = $(if ($node -is [IO.FileInfo]) {$node.Directory} else {$node.Parent})) {
        if ($node.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Unsafe recovery evidence path' }
    }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

$sha = [Security.Cryptography.SHA256]::Create()
try {
    $id = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Cryptography').MachineGuid.ToLowerInvariant()
    $fingerprint = [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::ASCII.GetBytes($id))).Replace('-', '').ToLowerInvariant()
} finally {
    $sha.Dispose()
}
if ($env:COMPUTERNAME -cne 'ANTARES' -or $fingerprint -cne $machine) { throw 'Wrong recovery host' }

$security = [Security.AccessControl.MutexSecurity]::new()
$security.SetAccessRuleProtection($true, $false)
foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
    $rule = [Security.AccessControl.MutexAccessRule]::new(
        [Security.Principal.SecurityIdentifier]::new($sid), 'FullControl', 'Allow')
    $security.AddAccessRule($rule)
}
[bool]$created = $false
$mutex = [Threading.Mutex]::new($false, 'Global\EndpointSetupUpdater-v1', [ref]$created, $security)
$held = $false
try {
    $held = $mutex.WaitOne([TimeSpan]::FromSeconds(35))
    if (!$held) { throw 'Setup observer owns the active pointer' }
    $stagePath = Join-Path $state 'staged-update.json'
    $stageHash = Read-Hash $stagePath
    $stage = Get-Content -LiteralPath $stagePath -Raw | ConvertFrom-Json
    $jobPath = Join-Path $jobRoot 'job.json'
    $jobHash = Read-Hash $jobPath
    $job = Get-Content -LiteralPath $jobPath -Raw | ConvertFrom-Json
    if ($stage.binding.operation_id -cne $operation -or $stage.phase -cne 'rolled-back' -or
        $stage.safe_code -cne 'native_not_started_restored' -or $job.assignment_id -cne $assignment -or
        $job.attempt_id -cne $attempt -or $job.native_exit -ne 21 -or $job.native_started -ne $true -or
        $jobHash -cne $expectedJob) { throw 'Unmatched local native outcome' }
    $msi = New-Object -ComObject 'WindowsInstaller.Installer'
    $sourceProduct = [int]$msi.ProductState($stage.binding.old_release.product_code)
    $targetProduct = [int]$msi.ProductState($stage.binding.new_release.product_code)
    $paths = @('transaction.json', 'upgrade.json', 'upgrade-history',
               "children\$operation\transaction.json", "staged-recovery\$operation\reboot.json")
    $busy = [bool]($paths | Where-Object { Test-Path -LiteralPath (Join-Path $state $_) })
    $busy = $busy -or (Test-Path -LiteralPath 'C:\ProgramData\Endpoint Platform\Agent\updates\pending_update.json') -or
        [bool](Get-ScheduledTask -TaskName "EndpointStagedRecovery-$operation" -ErrorAction SilentlyContinue)
    if ($busy -or $sourceProduct -ne 5 -or $targetProduct -ne -1) { throw 'Native operation is still active' }
    $activeHash = Read-Hash $active
    $facts = [ordered]@{
        host = $env:COMPUTERNAME
        operation_id = $operation
        phase = $stage.phase
        safe_code = $stage.safe_code
        native_exit = $job.native_exit
        source_product_state = $sourceProduct
        target_product_state = $targetProduct
        native_busy = $busy
        setup_sha256 = Read-Hash (Join-Path $jobRoot 'Setup.exe')
        target_msi_sha256 = $stage.binding.new_release.package_sha256
        observer_job_sha256 = $jobHash
        observer_start_sha256 = Read-Hash (Join-Path $jobRoot 'native-started.json')
        active_pointer_sha256 = $activeHash
        signed_recovery_sha256 = Read-Hash (Join-Path $program 'recovery-6772674d\EndpointSetupAbort-202-ANTARES.exe')
        terminal_stage_sha256 = $stageHash
        archived_stage_sha256 = Read-Hash (Join-Path $archive 'staged-update.before.json')
        archived_fence_sha256 = Read-Hash (Join-Path $archive 'transaction.json')
        archived_child_sha256 = Read-Hash (Join-Path $archive "children\$operation\transaction.json")
        archived_barrier_sha256 = Read-Hash (Join-Path $archive 'upgrade.json')
        archived_watchdog_sha256 = Read-Hash (Join-Path $archive 'watchdog.xml')
        observed_at = [DateTimeOffset]::UtcNow.ToString('o')
    }
    if ($Mode -ceq 'Observe') {
        $facts | ConvertTo-Json -Compress
    } else {
        if ($VerifiedServerAttempt -cne $attempt -or $activeHash -cne $expectedActive -or
            (Get-Content -LiteralPath $active -Raw | ConvertFrom-Json).assignment_id -cne $assignment) {
            throw 'Exact server settlement and local active pointer required'
        }
        [IO.File]::Move($active, $savedActive)
        if ((Read-Hash $savedActive) -cne $expectedActive -or (Read-Hash $jobPath) -cne $expectedJob -or
            (Test-Path -LiteralPath $active)) { throw 'Active pointer archive verification failed' }
        'ANTARES_202_POINTER_ARCHIVED'
    }
} finally {
    if ($held) { $mutex.ReleaseMutex() }
    $mutex.Dispose()
}
