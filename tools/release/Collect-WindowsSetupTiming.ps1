# Read-only projection from the named Windows Lab guest. Output is JSON on stdout.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][guid]$AssignmentId,
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9-]{1,63}$')][string]$ExpectedComputer,
    [Parameter(Mandatory)][guid]$ExpectedHardwareId
)
$ErrorActionPreference = 'Stop'

function Read-SetupReceipt([string]$Path) {
    $file = Get-Item -LiteralPath $Path -Force
    if ($file.PSIsContainer -or $file.Length -lt 1 -or $file.Length -gt 262144) {
        throw 'Windows Setup receipt has an invalid type or size'
    }
    for ($entry = $file; $null -ne $entry; ) {
        if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw 'Windows Setup receipt cannot use a reparse point'
        }
        if ($entry -is [IO.FileInfo]) { $entry = $entry.Directory } else { $entry = $entry.Parent }
    }
    $written = $file.LastWriteTimeUtc
    $record = Get-Content -LiteralPath $Path -Encoding UTF8 -Raw | ConvertFrom-Json
    $file.Refresh()
    if ($file.LastWriteTimeUtc -ne $written) { throw 'Windows Setup receipt changed during collection' }
    return @{ record = $record; last_write_at = $written.ToString('o') }
}

function Get-TransactionDigest([string]$Value) {
    $hash = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($Value.ToUpperInvariant())
        return [BitConverter]::ToString($hash.ComputeHash($bytes)).Replace('-', '').ToLowerInvariant()
    } finally {
        $hash.Dispose()
    }
}

if ($AssignmentId -eq [guid]::Empty -or $ExpectedHardwareId -eq [guid]::Empty -or
    $env:COMPUTERNAME -ine $ExpectedComputer -or
    [guid](Get-CimInstance Win32_ComputerSystemProduct).UUID -ne $ExpectedHardwareId) {
    throw 'Windows Setup timing collector is on the wrong Lab guest'
}
$path = Join-Path $env:ProgramData "EndpointPlatformSetupUpdates\jobs\$AssignmentId\job.json"
$job = (Read-SetupReceipt $path).record
if ($job.assignment_id -ne $AssignmentId.ToString() -or $job.phase -cne 'applied' -or
    $job.native_stage -cne 'accepted' -or $job.native_started -ne $true -or
    $null -eq $job.native_exit -or $job.native_exit -ne 0) {
    throw 'Windows Setup job does not have a settled native exit 0'
}
$journal = Read-SetupReceipt (Join-Path $env:ProgramFiles 'Endpoint Platform\installer-state\staged-update.json')
$stage = $journal.record
$os = Get-CimInstance Win32_OperatingSystem
$version = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$created = [DateTimeOffset]::Parse($job.native_created, [Globalization.CultureInfo]::InvariantCulture)
$ended = [DateTimeOffset]::Parse($job.native_ended, [Globalization.CultureInfo]::InvariantCulture)
if ($created.UtcDateTime -lt $os.LastBootUpTime.ToUniversalTime() -or
    $ended -le $created -or ($ended - $created).TotalDays -gt 1) {
    throw 'Windows Setup job does not fit the current boot and a bounded event window'
}
$filter = @{
    LogName = 'Application'
    ProviderName = 'MsiInstaller'
    Id = @(1033, 1034, 1040, 1042)
    StartTime = $created.LocalDateTime
    EndTime = $ended.LocalDateTime
}
$events = @(Get-WinEvent -FilterHashtable $filter -MaxEvents 257 | Sort-Object RecordId)
if ($events.Count -gt 256) { throw 'Windows Installer event window is too large' }
$projected = @(foreach ($event in $events) {
    $properties = @($event.Properties.Value)
    $row = @{
        record_id = $event.RecordId
        event_id = $event.Id
        at = $event.TimeCreated.ToUniversalTime().ToString('o')
        pid = $event.ProcessId
    }
    if ($event.Id -in @(1033, 1034)) {
        if ($properties.Count -lt 4) { throw 'Unexpected Windows Installer product event' }
        if ($properties[0] -cne 'Endpoint Agent') { continue }
        if ([string]$properties[3] -cnotmatch '^[0-9]{1,9}$') { throw 'Missing Windows Installer result' }
        $row.version = [string]$properties[1]
        $row.result = [int]$properties[3]
    } else {
        if ($properties.Count -lt 1 -or [string]::IsNullOrWhiteSpace($properties[0])) {
            throw 'Missing Windows Installer transaction name'
        }
        $row.transaction_sha256 = Get-TransactionDigest $properties[0]
    }
    $row
})
@{
    schema_version = 1
    assignment_id = $job.assignment_id
    attempt_id = $job.attempt_id
    device_id = $job.device_id
    phase = $job.phase
    release = $job.release | Select-Object id, version, sha256, msi_sha256, source_revision
    edition = $version.EditionID
    build = "$($version.CurrentBuild).$($version.UBR)"
    boot_at = $os.LastBootUpTime.ToUniversalTime().ToString('o')
    native = @{
        pid = $job.native_pid
        started = $job.native_started
        exit_code = $job.native_exit
        phase = $job.native_stage
        created_at = $job.native_created
        ended_at = $job.native_ended
    }
    source = $job.before.foundation | Select-Object version, source_revision, package_sha256, product_code, native_verified
    staged = @{
        schema = $stage.schema_version
        phase = $stage.phase
        operation_id = $stage.binding.operation_id
        previous_operation_id = $job.previous_native_id
        owner_pid = $stage.owner.pid
        owner_created_at = [DateTime]::FromFileTimeUtc([long]$stage.owner.created).ToString('o')
        last_write_at = $journal.last_write_at
        old = $stage.binding.old_release | Select-Object version, source_revision, package_sha256, product_code
        new = $stage.binding.new_release | Select-Object version, source_revision, package_sha256, product_code
    }
    events = $projected
} | ConvertTo-Json -Depth 6 -Compress
