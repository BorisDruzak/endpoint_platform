[CmdletBinding()]
param(
    [ValidateSet("Release", "Debug")]
    [string]$Configuration = "Release",
    [ValidateSet("x64")]
    [string]$Platform = "x64",
    [string]$Version,
    [string]$InitialRuntimeManifest,
    [string]$InitialRuntimeStageRoot,
    [string]$InitialRuntimeStageEvidence,
    [switch]$ApproveInitialRuntimeTransition,
    [switch]$ApproveInitialRuntimeSourceChange,
    [switch]$ReusePythonBuild,
    [switch]$PrepareOnly,
    [string]$WixBuildRoot
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Assert-SemVerTriplet {
    param([Parameter(Mandatory)][string]$Value, [Parameter(Mandatory)][string]$Label)
    if ($Value -notmatch '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$') {
        throw "$Label must be a three-part numeric version suitable for MSI."
    }
}

function Get-AgentVersion {
    param([Parameter(Mandatory)][string]$VersionFile)
    $match = [regex]::Match(
        [IO.File]::ReadAllText($VersionFile),
        'AGENT_VERSION\s*=\s*"([^"]+)"'
    )
    if (-not $match.Success) {
        throw "Could not read AGENT_VERSION from $VersionFile"
    }
    return $match.Groups[1].Value
}

function Get-SourceRevision {
    param([Parameter(Mandatory)][string]$RepositoryRoot)
    $revision = (& git -C $RepositoryRoot rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $revision -notmatch '^[0-9a-f]{40}$') {
        throw "Could not read the exact Git source revision for the MSI selector."
    }
    return $revision
}

function Assert-CleanSourceTree {
    param([Parameter(Mandatory)][string]$RepositoryRoot)
    $changes = @(git -C $RepositoryRoot status --porcelain --untracked-files=all)
    if ($LASTEXITCODE -ne 0 -or $changes.Count -ne 0) {
        throw "Refusing to build an MSI whose source revision cannot exactly identify its bytes."
    }
}

function Get-StableId {
    param([Parameter(Mandatory)][string]$Prefix, [Parameter(Mandatory)][string]$Value)
    $bytes = [Text.Encoding]::UTF8.GetBytes($Value.ToLowerInvariant())
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        $hash = $algorithm.ComputeHash($bytes)
    }
    finally {
        $algorithm.Dispose()
    }
    $suffix = -join ($hash[0..9] | ForEach-Object { $_.ToString("x2") })
    return "${Prefix}_${suffix}"
}

function Escape-Xml {
    param([Parameter(Mandatory)][string]$Value)
    return [Security.SecurityElement]::Escape($Value)
}

function Write-Utf8NoBom {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Content)
    [IO.File]::WriteAllText($Path, $Content, [Text.UTF8Encoding]::new($false))
}

function Get-RelativePath {
    param([Parameter(Mandatory)][string]$BasePath, [Parameter(Mandatory)][string]$TargetPath)
    $baseFull = [IO.Path]::GetFullPath($BasePath).TrimEnd('\') + '\'
    $targetFull = [IO.Path]::GetFullPath($TargetPath)
    $baseUri = [Uri]::new($baseFull)
    $targetUri = [Uri]::new($targetFull)
    return [Uri]::UnescapeDataString($baseUri.MakeRelativeUri($targetUri).ToString()).Replace('/', '\')
}

function Get-ReparsePointInPath {
    param([Parameter(Mandatory)][string]$Path)
    $candidate = [IO.Path]::GetFullPath($Path)
    while (-not (Test-Path -LiteralPath $candidate)) {
        $parent = Split-Path -Parent $candidate
        if (-not $parent -or $parent -eq $candidate) {
            break
        }
        $candidate = $parent
    }
    while ($candidate) {
        if (Test-Path -LiteralPath $candidate) {
            $item = Get-Item -LiteralPath $candidate -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                return $item.FullName
            }
        }
        $parent = Split-Path -Parent $candidate
        if (-not $parent -or $parent -eq $candidate) {
            break
        }
        $candidate = $parent
    }
    return $null
}

function Assert-SafeWixBuildRoot {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$RepositoryRoot
    )
    $root = [IO.Path]::GetFullPath($Path).TrimEnd([char]0x5c)
    $volumeRoot = [IO.Path]::GetPathRoot($root).TrimEnd([char]0x5c)
    if ($root -eq $volumeRoot) {
        throw "Refusing to use a filesystem root for WiX build output."
    }
    $repository = [IO.Path]::GetFullPath($RepositoryRoot).TrimEnd([char]0x5c)
    if ($root -eq $repository -or $root.StartsWith($repository + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to use a WiX build directory inside the repository."
    }
    $reparsePoint = Get-ReparsePointInPath $root
    if ($reparsePoint) {
        throw "Refusing to use a WiX build directory through a reparse point: $reparsePoint"
    }
    if ((Test-Path -LiteralPath $root) -and -not (Test-Path -LiteralPath $root -PathType Container)) {
        throw "WiX build directory must be a directory: $root"
    }
    return $root
}

function Invoke-Checked {
    param(
        [Parameter(Mandatory)][string]$Executable,
        [Parameter(Mandatory)][string[]]$Arguments,
        [Parameter(Mandatory)][string]$WorkingDirectory
    )
    Write-Host "RUN: $Executable $($Arguments -join ' ')"
    Push-Location $WorkingDirectory
    try {
        & $Executable @Arguments
        if ($LASTEXITCODE -ne 0) {
            throw "$Executable exited with code $LASTEXITCODE"
        }
    }
    finally {
        Pop-Location
    }
}

function Write-GeneratedPayloadWix {
    param(
        [Parameter(Mandatory)][string]$RuntimeRoot,
        [Parameter(Mandatory)][string]$OutputPath
    )
    $builder = [Text.StringBuilder]::new()
    [void]$builder.AppendLine('<?xml version="1.0" encoding="utf-8"?>')
    [void]$builder.AppendLine('<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs">')
    [void]$builder.AppendLine('  <Fragment>')
    $directoryIds = @{}
    $directories = Get-ChildItem -LiteralPath $RuntimeRoot -Recurse -Directory | Sort-Object FullName
    foreach ($directory in $directories) {
        $relative = Get-RelativePath $RuntimeRoot $directory.FullName
        $directoryIds[$relative] = Get-StableId -Prefix 'dirPayload' -Value $relative
    }
    foreach ($directory in $directories) {
        $relative = Get-RelativePath $RuntimeRoot $directory.FullName
        $parent = [IO.Path]::GetDirectoryName($relative)
        $parentId = if ($parent) { $directoryIds[$parent] } else { 'INITIALRUNTIMEDIR' }
        [void]$builder.AppendLine('    <DirectoryRef Id="' + $parentId + '">')
        [void]$builder.AppendLine('      <Directory Id="' + $directoryIds[$relative] + '" Name="' + (Escape-Xml $directory.Name) + '" />')
        [void]$builder.AppendLine('    </DirectoryRef>')
    }
    [void]$builder.AppendLine('    <ComponentGroup Id="EndpointAgentGeneratedPayload">')
    $cleanupDirectories = @{}
    $items = Get-ChildItem -LiteralPath $RuntimeRoot -Recurse -File |
        Where-Object { $_.FullName -ne (Join-Path $RuntimeRoot 'pc_agent.exe') } |
        Sort-Object FullName
    foreach ($item in $items) {
        $relative = Get-RelativePath $RuntimeRoot $item.FullName
        $componentId = Get-StableId -Prefix 'cmpPayload' -Value $relative
        $fileId = Get-StableId -Prefix 'filPayload' -Value $relative
        $subdirectory = [IO.Path]::GetDirectoryName($relative)
        $directoryId = if ($subdirectory) { $directoryIds[$subdirectory] } else { 'INITIALRUNTIMEDIR' }
        [void]$builder.AppendLine(
            "      <Component Id=`"$componentId`" Directory=`"$directoryId`" Guid=`"*`" Bitness=`"always64`">"
        )
        $cleanup = $subdirectory
        while ($cleanup) {
            if (-not $cleanupDirectories.ContainsKey($cleanup)) {
                $cleanupDirectories[$cleanup] = $true
                $cleanupId = Get-StableId -Prefix 'rmRuntimeDir' -Value $cleanup
                [void]$builder.AppendLine('        <RemoveFolder Id="' + $cleanupId + '" Directory="' + $directoryIds[$cleanup] + '" On="uninstall" />')
            }
            $cleanup = [IO.Path]::GetDirectoryName($cleanup)
        }
        [void]$builder.AppendLine(
            '        <File Id="' + $fileId + '" Source="' + (Escape-Xml $item.FullName) +
            '" Name="' + (Escape-Xml $item.Name) + '" KeyPath="yes" />'
        )
        [void]$builder.AppendLine('      </Component>')
    }
    [void]$builder.AppendLine('    </ComponentGroup>')
    [void]$builder.AppendLine('  </Fragment>')
    [void]$builder.AppendLine('</Wix>')
    [IO.File]::WriteAllText($OutputPath, $builder.ToString(), [Text.UTF8Encoding]::new($false))
    return $items
}

function Read-MsiTable {
    param(
        [Parameter(Mandatory)]$Database,
        [Parameter(Mandatory)][string]$Query,
        [Parameter(Mandatory)][string[]]$Columns
)
    $view = $Database.OpenView($Query)
    $record = $null
    [void]$view.Execute()
    $rows = @()
    try {
        while ($record = $view.Fetch()) {
            $row = [ordered]@{}
            for ($index = 0; $index -lt $Columns.Count; $index++) {
                $row[$Columns[$index]] = $record.StringData($index + 1)
            }
            $rows += [pscustomobject]$row
        }
    }
    finally {
        [void]$view.Close()
        if ($record) {
            [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($record)
        }
        [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($view)
    }
    return $rows
}

function Assert-UninstallFinalizationSequence {
    param([Parameter(Mandatory)]$Inspection)
    # This is an allowlist of actions allowed to execute with all features absent.
    # A newly linked extension or standard action must fail packaging until reviewed.
    $readOnly = @('FindRelatedProducts', 'LaunchConditions', 'ValidateProductID',
        'CostInitialize', 'FileCost', 'CostFinalize', 'InstallValidate',
        'InstallInitialize', 'InstallExecute', 'InstallFinalize')
    $guardTypes = @{ InstallerOwnerPreflight = 8194; InstallerOwnerEnter = 11266; InstallerOwnerComplete = 11778 }
    $suppressedConditions = @('NOT ENDPOINT_UNINSTALL_FINALIZE',
        'NOT ENDPOINT_UNINSTALL_FINALIZE AND NOT ENDPOINT_RUNTIME_RETIRE',
        'NOT ENDPOINT_UNINSTALL_FINALIZE AND &EndpointAgentFeature = 3 AND NOT ENDPOINT_RUNTIME_RETIRE AND NOT REMOVE~="ALL"',
        'NOT ENDPOINT_UNINSTALL_FINALIZE AND (!EndpointAgentInitialRuntimeFeature = 3 OR !EndpointAgentInitialRuntimeFeature = 2) AND &EndpointAgentInitialRuntimeFeature = 2 AND &EndpointAgentFeature = 3')
    $rows = @{}
    foreach ($row in $Inspection.execute_sequence) {
        $name = [string]$row.action
        if ($rows.ContainsKey($name)) { throw "Duplicate execute action: $name" }
        $rows[$name] = $row
        if ($guardTypes.ContainsKey($name)) {
            if (-not [string]::IsNullOrEmpty([string]$row.condition)) { throw "Conditional owner guard: $name" }
        } elseif ($name -in $readOnly) {
            if (@($Inspection.custom_actions | Where-Object action -eq $name).Count) { throw "Custom action shadows a standard action: $name" }
        } elseif ([string]$row.condition -cnotin $suppressedConditions) {
            throw "Unreviewed action reachable during uninstall finalization: $name"
        }
    }
    foreach ($name in @('ProcessComponents', 'RegisterUser', 'RegisterProduct', 'PublishFeatures', 'PublishProduct', 'RemoveExistingProducts')) {
        if (-not $rows.ContainsKey($name) -or [string]$rows[$name].condition -cne 'NOT ENDPOINT_UNINSTALL_FINALIZE') {
            throw "Missing finalization suppression: $name"
        }
    }
    foreach ($name in $guardTypes.Keys) {
        $actions = @($Inspection.custom_actions | Where-Object action -eq $name)
        if (-not $rows.ContainsKey($name) -or $actions.Count -ne 1 -or
            [int]$actions[0].type -ne $guardTypes[$name] -or [string]$actions[0].source -cne 'EndpointInstallerHost') {
            throw "Invalid checked Binary owner guard: $name"
        }
    }
    $previous = -1
    foreach ($name in @('CostFinalize', 'InstallerOwnerPreflight', 'InstallInitialize', 'InstallerOwnerEnter', 'ProcessComponents', 'InstallerOwnerComplete', 'InstallFinalize')) {
        if (-not $rows.ContainsKey($name) -or [int]$rows[$name].sequence -le $previous) { throw "Unsafe owner guard ordering: $name" }
        $previous = [int]$rows[$name].sequence
    }
    foreach ($name in @('StopServices', 'RemoveFiles')) {
        if ($rows.ContainsKey($name) -and [int]$rows[$name].sequence -le [int]$rows['InstallerOwnerEnter'].sequence) { throw "Mutation precedes owner guard: $name" }
    }
    $featureNames = @('EndpointAgentFeature', 'EndpointAgentInitialRuntimeFeature')
    if (@($Inspection.features).Count -ne 2 -or @($Inspection.feature_conditions).Count -ne 2) { throw 'Unexpected finalization feature topology.' }
    foreach ($name in $featureNames) {
        $features = @($Inspection.features | Where-Object feature -eq $name)
        $conditions = @($Inspection.feature_conditions | Where-Object feature -eq $name)
        if ($features.Count -ne 1 -or [int]$features[0].level -ne 1 -or $conditions.Count -ne 1 -or
            [int]$conditions[0].level -ne 0 -or [string]$conditions[0].condition -cne 'ENDPOINT_UNINSTALL_FINALIZE = 1') {
            throw "Feature can become installed during uninstall finalization: $name"
        }
    }
}

function Export-MsiInspection {
    param([Parameter(Mandatory)][string]$MsiPath, [Parameter(Mandatory)][string]$OutputPath)
    $installer = $null
    $database = $null
    try {
        $installer = New-Object -ComObject WindowsInstaller.Installer
        $database = $installer.OpenDatabase($MsiPath, 0)
        $inspection = [ordered]@{
            files = Read-MsiTable $database 'SELECT `File`, `Component_`, `FileName`, `FileSize` FROM `File`' @('file', 'component', 'name', 'size')
            components = Read-MsiTable $database 'SELECT `Component`, `ComponentId`, `Directory_`, `Attributes`, `KeyPath` FROM `Component`' @('component', 'guid', 'directory', 'attributes', 'key_path')
            services = Read-MsiTable $database 'SELECT `ServiceInstall`, `Name`, `DisplayName`, `ServiceType`, `StartType`, `ErrorControl`, `LoadOrderGroup`, `Dependencies`, `StartName`, `Password`, `Arguments`, `Component_` FROM `ServiceInstall`' @('id', 'name', 'display_name', 'service_type', 'start_type', 'error_control', 'load_order_group', 'dependencies', 'account', 'password', 'arguments', 'component')
            properties = Read-MsiTable $database 'SELECT `Property`, `Value` FROM `Property`' @('property', 'value')
            features = Read-MsiTable $database 'SELECT `Feature`, `Feature_Parent`, `Level`, `Attributes` FROM `Feature`' @('feature', 'parent', 'level', 'attributes')
            feature_components = Read-MsiTable $database 'SELECT `Feature_`, `Component_` FROM `FeatureComponents`' @('feature', 'component')
            remove_files = Read-MsiTable $database 'SELECT `FileKey`, `Component_`, `FileName`, `DirProperty`, `InstallMode` FROM `RemoveFile`' @('id', 'component', 'name', 'directory', 'mode')
            custom_actions = Read-MsiTable $database 'SELECT `Action`, `Type`, `Source`, `Target` FROM `CustomAction`' @('action', 'type', 'source', 'target')
            execute_sequence = Read-MsiTable $database 'SELECT `Action`, `Condition`, `Sequence` FROM `InstallExecuteSequence`' @('action', 'condition', 'sequence')
            feature_conditions = Read-MsiTable $database 'SELECT `Feature_`, `Level`, `Condition` FROM `Condition`' @('feature', 'level', 'condition')
            binaries = Read-MsiTable $database 'SELECT `Name` FROM `Binary`' @('name')
            cleanup_rows = Read-MsiTable $database 'SELECT `RemoveFolderEx`, `Component_`, `Property`, `InstallMode`, `Condition` FROM `Wix4RemoveFolderEx`' @('id','component','property','mode','condition')
            cleanup_columns = Read-MsiTable $database 'SELECT `Number`, `Name`, `Type` FROM `_Columns` WHERE `Table` = ''Wix4RemoveFolderEx''' @('number','name','type')
            cleanup_validation = Read-MsiTable $database 'SELECT `Column`, `Nullable`, `MinValue`, `MaxValue`, `KeyTable`, `KeyColumn`, `Category` FROM `_Validation` WHERE `Table` = ''Wix4RemoveFolderEx''' @('column','nullable','minimum','maximum','key_table','key_column','category')
            upgrades = Read-MsiTable $database 'SELECT `VersionMin`, `VersionMax`, `Language`, `Attributes`, `Remove`, `ActionProperty` FROM `Upgrade`' @('minimum','maximum','language','attributes','remove','property')
        }
        $inspection.all_sequences = @{}
        $tables = @(Read-MsiTable $database 'SELECT `Name` FROM `_Tables`' @('name'))
        foreach ($name in @('InstallExecuteSequence','InstallUISequence','AdminExecuteSequence','AdminUISequence','AdvtExecuteSequence')) {
            if (@($tables | Where-Object name -eq $name).Count) {
                $inspection.all_sequences[$name] = @(Read-MsiTable $database ("SELECT ``Action``, ``Condition``, ``Sequence`` FROM ``{0}``" -f $name) @('action','condition','sequence'))
            }
        }
        $forbiddenProperty = $inspection.properties | Where-Object {
            $_.property -match '(?i)(claim|campaign|device.?token|credential|enroll)'
        }
        if ($forbiddenProperty) {
            throw "MSI inspection found a forbidden secret-bearing property name."
        }
        Assert-UninstallFinalizationSequence $inspection
        Assert-RootCleanupComposition $inspection
        Write-Utf8NoBom $OutputPath ($inspection | ConvertTo-Json -Depth 8)
    }
    finally {
        if ($database) {
            [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($database)
        }
        if ($installer) {
            [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($installer)
        }
    }
}

function Assert-RootCleanupComposition {
    param([Parameter(Mandatory)]$Inspection)
    foreach ($name in @('EndpointAgent','EndpointAgentUpdater')) {
        $service = @($Inspection.services | Where-Object name -eq $name)
        if ($service.Count -ne 1 -or [int]$service[0].start_type -ne 4) { throw 'Canonical update service is not initially quarantined.' }
    }
    foreach ($sequence in $Inspection.all_sequences.Values) {
        if (@($sequence | Where-Object action -eq 'Wix4RemoveFoldersEx_X64').Count) { throw 'Uncontrolled Util cleanup scheduler linked.' }
    }
    $actions = @($Inspection.custom_actions | Where-Object action -eq 'ScheduleEndpointRootCleanup')
    if ($actions.Count -ne 1 -or [int]$actions[0].type -ne 65 -or $actions[0].source -cne 'Wix4UtilCA_X64' -or $actions[0].target -cne 'WixRemoveFoldersEx') { throw 'Unexpected cleanup implementation.' }
    $scheduled = @($Inspection.execute_sequence | Where-Object action -eq 'ScheduleEndpointRootCleanup')
    if ($scheduled.Count -ne 1 -or $scheduled[0].condition -cne 'NOT ENDPOINT_UNINSTALL_FINALIZE') { throw 'Unconditional cleanup scheduler.' }
    $rows = @($Inspection.cleanup_rows)
    if ($rows.Count -ne 1 -or $rows[0].id -cne 'RemoveEndpointAgentBinaries' -or $rows[0].component -cne 'cmpInstallRootCleanup' -or $rows[0].property -cne 'ENDPOINT_AGENT_REMEMBERED_INSTALLROOT' -or [int]$rows[0].mode -ne 2 -or $rows[0].condition -cne 'REMOVE~="ALL" AND NOT UPGRADINGPRODUCTCODE') { throw 'Unexpected cleanup row.' }
    $columns = @($Inspection.cleanup_columns | Sort-Object { [int]$_.number })
    $expectedNames = @('RemoveFolderEx','Component_','Property','InstallMode','Condition')
    $expectedTypes = @(11592,3400,3400,1282,7424)
    if ($columns.Count -ne 5) { throw 'Unexpected cleanup schema.' }
    for ($index=0; $index -lt 5; $index++) {
        if ([int]$columns[$index].number -ne $index+1 -or $columns[$index].name -cne $expectedNames[$index] -or [int]$columns[$index].type -ne $expectedTypes[$index]) { throw 'Unexpected cleanup column.' }
    }
    $validation = @{
        RemoveFolderEx='N|||||Identifier'; Component_='N|||Component|1|Identifier';
        Property='N|||||Identifier'; InstallMode='N|1|3|||'; Condition='Y|||||Condition'
    }
    if (@($Inspection.cleanup_validation).Count -ne 5) { throw 'Unexpected cleanup validation schema.' }
    foreach ($row in $Inspection.cleanup_validation) {
        $value = [string]::Join('|', @($row.nullable,$row.minimum,$row.maximum,$row.key_table,$row.key_column,$row.category))
        if (-not $validation.ContainsKey([string]$row.column) -or $value -cne $validation[[string]$row.column]) { throw 'Unexpected cleanup validation column.' }
    }
    $version = @($Inspection.properties | Where-Object property -eq 'ProductVersion')[0].value
    $upgrades = @($Inspection.upgrades)
    if ($upgrades.Count -ne 2) { throw 'Unexpected upgrade topology.' }
    foreach ($row in $upgrades) {
        if ($row.language -cne '1033' -or $row.remove -cne '') { throw 'Changed upgrade semantics.' }
        if ($row.property -ceq 'WIX_UPGRADE_DETECTED') {
            if ($row.minimum -cne '' -or $row.maximum -cne $version -or [int]$row.attributes -ne 1) { throw 'Changed upgrade bounds.' }
        } elseif ($row.property -ceq 'WIX_DOWNGRADE_DETECTED') {
            if ($row.minimum -cne $version -or $row.maximum -cne '' -or [int]$row.attributes -ne 2) { throw 'Changed downgrade bounds.' }
        } else { throw 'Unexpected upgrade property.' }
    }
}

$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
Assert-CleanSourceTree -RepositoryRoot $repositoryRoot
$checkedOutSourceRevision = Get-SourceRevision -RepositoryRoot $repositoryRoot
$packagingRoot = [IO.Path]::GetFullPath($PSScriptRoot)
$buildRoot = [IO.Path]::GetFullPath((Join-Path $packagingRoot "build\$Configuration-$Platform"))
$allowedBuildParent = [IO.Path]::GetFullPath((Join-Path $packagingRoot 'build'))
if (-not $buildRoot.StartsWith($allowedBuildParent + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing to use a build directory outside packaging/windows/build."
}
$defaultWixBuildRoot = Join-Path ([IO.Path]::GetPathRoot($repositoryRoot)) "endpoint-platform-wix-build\$Configuration-$Platform"
$wixBuildRoot = Assert-SafeWixBuildRoot -Path $(if ($WixBuildRoot) { $WixBuildRoot } else { $defaultWixBuildRoot }) -RepositoryRoot $repositoryRoot

$python = (Get-Command python -ErrorAction Stop).Source
$baselineInitialRuntimeManifest = Join-Path $packagingRoot 'initial-runtime.json'
if (-not $InitialRuntimeManifest) {
    $InitialRuntimeManifest = $baselineInitialRuntimeManifest
}
$initialRuntimeManifestPath = [IO.Path]::GetFullPath($InitialRuntimeManifest)
$manifestPreview = Get-Content -LiteralPath $initialRuntimeManifestPath -Raw | ConvertFrom-Json
$initialRuntimeSourceRevision = $checkedOutSourceRevision
if ([int]$manifestPreview.schema_version -ge 5) {
    if (
        [string]::IsNullOrWhiteSpace($InitialRuntimeStageRoot) -or
        [string]::IsNullOrWhiteSpace($InitialRuntimeStageEvidence)
    ) {
        throw "Initial runtime stage evidence is required for a schema-v5 manifest."
    }
}
$sourceDateEpoch = [string]$manifestPreview.toolchain.source_date_epoch
if ($sourceDateEpoch -notmatch '^[1-9][0-9]*$') {
    throw "Initial runtime manifest has an invalid SOURCE_DATE_EPOCH."
}
$env:SOURCE_DATE_EPOCH = $sourceDateEpoch
if ([int]$manifestPreview.schema_version -ge 3 -and [string]$manifestPreview.toolchain.python_hash_seed -ne '0') {
    throw "Initial runtime manifest must pin python_hash_seed to 0."
}
$env:PYTHONHASHSEED = "0"
$validationArguments = @(
    (Join-Path $packagingRoot 'initial_runtime_contract.py'),
    '--repository-root', $repositoryRoot,
    '--manifest', $initialRuntimeManifestPath,
    '--baseline', $baselineInitialRuntimeManifest
)
if ([int]$manifestPreview.schema_version -ge 5) {
    $validationArguments += @(
        '--stage-root', $InitialRuntimeStageRoot,
        '--stage-evidence', $InitialRuntimeStageEvidence
    )
}
if ($ApproveInitialRuntimeTransition) {
    $validationArguments += '--approve-version'
}
if ($ApproveInitialRuntimeSourceChange) {
    $validationArguments += '--approve-source'
}
$identityJson = & $python @validationArguments
if ($LASTEXITCODE -ne 0) {
    throw "Initial runtime manifest validation failed."
}
$initialRuntimeIdentity = $identityJson | ConvertFrom-Json
$InitialRuntimeVersion = [string]$initialRuntimeIdentity.version
$InitialRuntimeComponentGuid = [string]$initialRuntimeIdentity.component_guid
$BaselineInitialRuntimeVersion = [string]$initialRuntimeIdentity.baseline_version
$InitialRuntimeTransitionApproved = if ([bool]$initialRuntimeIdentity.transition_approved) { '1' } else { '0' }
if ([int]$manifestPreview.schema_version -ge 5) {
    $initialRuntimeSourceRevision = [string]$initialRuntimeIdentity.source_revision
    if ($initialRuntimeSourceRevision -notmatch '^[0-9a-f]{40}$') {
        throw "Initial runtime manifest validation did not return a staged source revision."
    }
    & git -C $repositoryRoot merge-base --is-ancestor $initialRuntimeSourceRevision $checkedOutSourceRevision
    if ($LASTEXITCODE -ne 0) {
        throw "Initial runtime stage source revision is not an ancestor of the clean build source."
    }
}
if (-not $Version) {
    $Version = Get-AgentVersion (Join-Path $repositoryRoot 'pc_agent\version.py')
}
Assert-SemVerTriplet $Version 'Package version'
Assert-SemVerTriplet $InitialRuntimeVersion 'Initial runtime version'

if ((Test-Path -LiteralPath $buildRoot) -and -not $ReusePythonBuild) {
    Remove-Item -LiteralPath $buildRoot -Recurse -Force
}
if ((Test-Path -LiteralPath $wixBuildRoot) -and -not $ReusePythonBuild) {
    Remove-Item -LiteralPath $wixBuildRoot -Recurse -Force
}
$pyinstallerRoot = Join-Path $buildRoot 'pyinstaller'
$distRoot = Join-Path $pyinstallerRoot 'dist'
$workRoot = Join-Path $pyinstallerRoot 'work'
$stagingRoot = Join-Path $wixBuildRoot 'staging'
$programFilesStage = Join-Path $stagingRoot 'ProgramFiles'
$runtimeStage = Join-Path $programFilesStage "versions\$InitialRuntimeVersion"
$outputRoot = Join-Path $wixBuildRoot 'output'
$releaseRoot = Join-Path $wixBuildRoot 'releases'
if ($ReusePythonBuild) {
    foreach ($generatedPath in @($stagingRoot, $outputRoot, (Join-Path $wixBuildRoot 'PayloadComponents.generated.wxs'))) {
        if (Test-Path -LiteralPath $generatedPath) {
            Remove-Item -LiteralPath $generatedPath -Recurse -Force
        }
    }
}
New-Item -ItemType Directory -Path $runtimeStage, $outputRoot, $releaseRoot -Force | Out-Null

$coreSpec = Join-Path $repositoryRoot 'pc_agent\pyinstaller_endpoint_core_windows.spec'
$launcherSpec = Join-Path $repositoryRoot 'pc_agent\pyinstaller_launcher_win.spec'
$serviceHostSpec = Join-Path $repositoryRoot 'pc_agent\pyinstaller_windows_service_launcher.spec'
$updaterSpec = Join-Path $repositoryRoot 'pc_agent\pyinstaller_windows_updater.spec'
$provisionerSpec = Join-Path $repositoryRoot 'pc_agent\pyinstaller_windows_provision.spec'
$traySpec = Join-Path $repositoryRoot 'pc_agent\pyinstaller_windows_tray.spec'
$userSensorSpec = Join-Path $repositoryRoot 'pc_agent\pyinstaller_windows_user_sensor.spec'
$browserBridgeSpec = Join-Path $repositoryRoot 'pc_agent\pyinstaller_windows_browser_bridge.spec'
$browserPolicySpec = Join-Path $repositoryRoot 'pc_agent\pyinstaller_windows_browser_policy_service.spec'
$commonPyInstaller = @('--noconfirm', '--clean', '--distpath', $distRoot, '--workpath', $workRoot)
if (-not $ReusePythonBuild) {
    Invoke-Checked $python (@('-m', 'PyInstaller') + $commonPyInstaller + @($coreSpec)) $repositoryRoot
    Invoke-Checked $python (@('-m', 'PyInstaller') + $commonPyInstaller + @($launcherSpec)) $repositoryRoot
    Invoke-Checked $python (@('-m', 'PyInstaller') + $commonPyInstaller + @($serviceHostSpec)) $repositoryRoot
    Invoke-Checked $python (@('-m', 'PyInstaller') + $commonPyInstaller + @($updaterSpec)) $repositoryRoot
    Invoke-Checked $python (@('-m', 'PyInstaller') + $commonPyInstaller + @($provisionerSpec)) $repositoryRoot
    Invoke-Checked $python (@('-m', 'PyInstaller') + $commonPyInstaller + @($traySpec)) $repositoryRoot
    Invoke-Checked $python (@('-m', 'PyInstaller') + $commonPyInstaller + @($userSensorSpec)) $repositoryRoot
    Invoke-Checked $python (@('-m', 'PyInstaller') + $commonPyInstaller + @($browserBridgeSpec)) $repositoryRoot
    Invoke-Checked $python (@('-m', 'PyInstaller') + $commonPyInstaller + @($browserPolicySpec)) $repositoryRoot
}

$builtCore = Join-Path $distRoot 'endpoint_agent_core'
$builtCoreExe = Join-Path $builtCore 'endpoint_agent_core.exe'
$builtLauncher = Join-Path $distRoot 'launcher.exe'
$builtServiceHost = Join-Path $distRoot 'endpoint-agent-service.exe'
$builtUpdater = Join-Path $distRoot 'endpoint-agent-updater.exe'
$builtProvisioner = Join-Path $distRoot 'endpoint-agent-provision.exe'
$builtTray = Join-Path $distRoot 'EndpointAgentTray.exe'
$builtUserSensor = Join-Path $distRoot 'EndpointUserSensor.exe'
$builtBrowserBridge = Join-Path $distRoot 'EndpointBrowserBridge.exe'
$builtBrowserPolicy = Join-Path $distRoot 'EndpointBrowserPolicy.exe'
if (-not (Test-Path -LiteralPath $builtCoreExe -PathType Leaf)) {
    throw "Headless core build missing $builtCoreExe"
}
if (-not (Test-Path -LiteralPath $builtLauncher -PathType Leaf)) {
    throw "Launcher build missing $builtLauncher"
}
if (-not (Test-Path -LiteralPath $builtServiceHost -PathType Leaf)) {
    throw "Service host build missing $builtServiceHost"
}
if (-not (Test-Path -LiteralPath $builtUpdater -PathType Leaf)) {
    throw "Offline updater build missing $builtUpdater"
}
Invoke-Checked $python @('-m', 'tools.canary.offline_updater_contract', $builtUpdater, '--output', (Join-Path $outputRoot 'offline-updater-inspection.json')) $repositoryRoot
Invoke-Checked $builtUpdater @('--verify-offline') $repositoryRoot
if (-not (Test-Path -LiteralPath $builtProvisioner -PathType Leaf)) {
    throw "Provisioning helper build missing $builtProvisioner"
}
if (-not (Test-Path -LiteralPath $builtTray -PathType Leaf)) {
    throw "Tray companion build missing $builtTray"
}
if (-not (Test-Path -LiteralPath $builtUserSensor -PathType Leaf)) {
    throw "User Sensor build missing $builtUserSensor"
}
if (-not (Test-Path -LiteralPath $builtBrowserBridge -PathType Leaf)) {
    throw "Browser Bridge build missing $builtBrowserBridge"
}
if (-not (Test-Path -LiteralPath $builtBrowserPolicy -PathType Leaf)) {
    throw "Browser Policy service build missing $builtBrowserPolicy"
}
$runtimePayload = $builtCore
if ([int]$manifestPreview.schema_version -ge 5) {
    $runtimePayload = [IO.Path]::GetFullPath($InitialRuntimeStageRoot)
}
$runtimePayloadExe = Join-Path $runtimePayload 'endpoint_agent_core.exe'
if (-not (Test-Path -LiteralPath $runtimePayloadExe -PathType Leaf)) {
    throw "Initial runtime payload missing $runtimePayloadExe"
}
$artifactValidationJson = & $python @($validationArguments + @('--artifact-root', $runtimePayload))
if ($LASTEXITCODE -ne 0) {
    throw "Initial runtime artifact validation failed."
}
$artifactValidationIdentity = $artifactValidationJson | ConvertFrom-Json
if ([string]$artifactValidationIdentity.version -ne $InitialRuntimeVersion) {
    throw "Initial runtime artifact validation returned an unexpected runtime identity."
}
Get-ChildItem -LiteralPath $runtimePayload | ForEach-Object {
    Copy-Item -LiteralPath $_.FullName -Destination $runtimeStage -Recurse -Force
}
Move-Item -LiteralPath (Join-Path $runtimeStage 'endpoint_agent_core.exe') -Destination (Join-Path $runtimeStage 'pc_agent.exe')
Invoke-Checked $python @(
    (Join-Path $packagingRoot 'initial_runtime_contract.py'),
    '--write-installed-manifest', $runtimeStage,
    '--version', $InitialRuntimeVersion,
    '--source-revision', $initialRuntimeSourceRevision
) $repositoryRoot
$runtimeInventoryPath = Join-Path $outputRoot 'initial-runtime-inventory.json'
$contractBytes = [IO.File]::ReadAllBytes((Join-Path $runtimeStage 'endpoint-runtime-contract.json'))
Write-Utf8NoBom (Join-Path $runtimeStage '.endpoint-msi-runtime.json') (@{
    component_guid = $InitialRuntimeComponentGuid
    schema_version = 1
    version = $InitialRuntimeVersion
} | ConvertTo-Json -Compress)
Copy-Item -LiteralPath $builtLauncher -Destination (Join-Path $programFilesStage 'launcher.exe')
Copy-Item -LiteralPath $builtServiceHost -Destination (Join-Path $programFilesStage 'endpoint-agent-service.exe')
Copy-Item -LiteralPath $builtUpdater -Destination (Join-Path $programFilesStage 'endpoint-agent-updater.exe')
Copy-Item -LiteralPath $builtProvisioner -Destination (Join-Path $programFilesStage 'endpoint-agent-provision.exe')
Copy-Item -LiteralPath $builtTray -Destination (Join-Path $programFilesStage 'EndpointAgentTray.exe')
Copy-Item -LiteralPath $builtUserSensor -Destination (Join-Path $programFilesStage 'EndpointUserSensor.exe')
Copy-Item -LiteralPath $builtBrowserBridge -Destination (Join-Path $programFilesStage 'EndpointBrowserBridge.exe')
Copy-Item -LiteralPath $builtBrowserPolicy -Destination (Join-Path $programFilesStage 'EndpointBrowserPolicy.exe')
$foundationBindings = [ordered]@{
    'launcher.exe'=@('filLauncher','cmpLauncher')
    'endpoint-agent-service.exe'=@('filServiceHost','cmpServiceEntrypoints')
    'endpoint-agent-updater.exe'=@('filOfflineUpdater','cmpOfflineUpdater')
    'endpoint-agent-provision.exe'=@('filProvisioner','cmpProvisioner')
    'EndpointAgentTray.exe'=@('filEndpointAgentTray','cmpTrayCompanion')
    'EndpointUserSensor.exe'=@('filEndpointUserSensor','cmpUserSensor')
    'EndpointBrowserBridge.exe'=@('filEndpointBrowserBridge','cmpBrowserBridge')
    'EndpointBrowserPolicy.exe'=@('filEndpointBrowserPolicy','cmpBrowserPolicyService')
}
$foundationInventory = foreach ($name in $foundationBindings.Keys) {
    $path = Join-Path $programFilesStage $name
    @{path=$name;file=$foundationBindings[$name][0];component=$foundationBindings[$name][1];
      size=(Get-Item -LiteralPath $path).Length;sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()}
}
Write-Utf8NoBom $runtimeInventoryPath (@{
    schema_version = 1
    manifest = (Get-Content -LiteralPath (Join-Path $runtimeStage 'endpoint-update-manifest.json') -Raw | ConvertFrom-Json)
    contract_bytes = ([BitConverter]::ToString($contractBytes)).Replace('-', '').ToLowerInvariant()
    foundation_files = @($foundationInventory)
} | ConvertTo-Json -Depth 8 -Compress)
Copy-Item -LiteralPath (Join-Path $packagingRoot 'assets\ru.sosnadmin.endpoint.browser.json') -Destination (Join-Path $programFilesStage 'ru.sosnadmin.endpoint.browser.json')
New-Item -ItemType Directory -Path (Join-Path $programFilesStage 'config'), (Join-Path $programFilesStage 'docs') -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $packagingRoot 'assets\agent-config.yaml') -Destination (Join-Path $programFilesStage 'config\agent-config.yaml')
Copy-Item -LiteralPath (Join-Path $packagingRoot 'README.md') -Destination (Join-Path $programFilesStage 'docs\README.md')
Write-Utf8NoBom (Join-Path $programFilesStage 'current.json') (@{
    schema_version = 1
    source_revision = $initialRuntimeSourceRevision
    version = $InitialRuntimeVersion
} | ConvertTo-Json -Compress)

$generatedWix = Join-Path $wixBuildRoot 'PayloadComponents.generated.wxs'
$generatedItems = Write-GeneratedPayloadWix $runtimeStage $generatedWix
$allFiles = Get-ChildItem -LiteralPath $stagingRoot -Recurse -File | Sort-Object FullName
$fileManifest = foreach ($item in $allFiles) {
    [ordered]@{
        path = (Get-RelativePath $stagingRoot $item.FullName).Replace('\', '/')
        sha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        size = $item.Length
    }
}
$componentManifest = @(
    'cmpLauncher', 'cmpCurrentSelector', 'cmpInitialRuntimeAnchor', 'cmpConfigTemplate', 'cmpPublicReadme',
    'cmpProgramDataRoot', 'cmpInstallRootCleanup', 'cmpInitialRuntimeTransitionState',
    'cmpServiceEntrypoints', 'cmpOfflineUpdater', 'cmpBrowserPolicyService', 'cmpProvisioner',
    'cmpTrayCompanion', 'cmpUserSensor', 'cmpBrowserBridge'
) + @($generatedItems | ForEach-Object {
    Get-StableId -Prefix 'cmpPayload' -Value (Get-RelativePath $runtimeStage $_.FullName)
})
$binding = [ordered]@{
    schema_version = 1
    package = [ordered]@{
        architecture = 'x64'
        scope = 'perMachine'
        upgrade_code = 'D4F3045C-51CF-49D9-AF9C-3AEBF206ED1F'
        version = $Version
        initial_runtime_version = $InitialRuntimeVersion
        initial_runtime_component_guid = $InitialRuntimeComponentGuid
        initial_runtime_manifest_sha256 = (Get-FileHash -LiteralPath $initialRuntimeManifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
        initial_runtime_artifact = $manifestPreview.artifact
        initial_runtime_toolchain = $manifestPreview.toolchain
        initial_runtime_transition_approved = [bool]$ApproveInitialRuntimeTransition
        initial_runtime_source_change_approved = [bool]$ApproveInitialRuntimeSourceChange
    }
    files = @($fileManifest)
    components = @($componentManifest | Sort-Object)
    services = @(
        [ordered]@{ name = 'EndpointAgent'; account = 'NT AUTHORITY\LocalService'; start = 'disabled'; owner_final_start = 'auto'; recovery = 'restart'; binary = 'ProgramFiles/endpoint-agent-service.exe'; arguments = '--agent-service'; selector = 'ProgramFiles/current.json' },
        [ordered]@{ name = 'EndpointAgentUpdater'; account = 'LocalSystem'; start = 'disabled'; owner_final_start = 'demand'; recovery = 'restart'; binary = 'ProgramFiles/endpoint-agent-updater.exe'; arguments = '--updater-service' },
        [ordered]@{ name = 'EndpointBrowserPolicy'; account = 'LocalSystem'; start = 'auto'; recovery = 'restart'; binary = 'ProgramFiles/EndpointBrowserPolicy.exe' }
    )
    state = [ordered]@{
        program_data_permanent = $true
        current_selector_never_overwrite = $true
        program_files_ordinary_user_writable = $false
        embedded_private_material = $false
    }
}
$bindingPath = Join-Path $outputRoot 'binding-manifest.json'
Write-Utf8NoBom $bindingPath ($binding | ConvertTo-Json -Depth 8)

Write-Host "Prepared binding manifest: $bindingPath"
if ($PrepareOnly) {
    Write-Host "PrepareOnly requested; MSI binding skipped."
    exit 0
}

$wixCommand = Get-Command wix -ErrorAction SilentlyContinue
if (-not $wixCommand) {
    throw "WiX Toolset 4 command 'wix' is unavailable. Install a .NET SDK and the WiX 4 global/local tool, then rerun this command."
}
$wixSources = @(
    (Join-Path $packagingRoot 'wix\Package.wxs'),
    (Join-Path $packagingRoot 'wix\Directories.wxs'),
    (Join-Path $packagingRoot 'wix\Components.wxs'),
    (Join-Path $packagingRoot 'wix\Services.wxs'),
    (Join-Path $packagingRoot 'wix\Upgrade.wxs'),
    $generatedWix
)
$msiPath = Join-Path $outputRoot "EndpointAgent-$Version-x64.msi"
$wixArguments = @(
    "build", "-arch", "x64", "-ext", "WixToolset.Util.wixext",
    "-d", "StagingDir=$stagingRoot", "-d", "InitialRuntimeVersion=$InitialRuntimeVersion",
    "-d", "InitialRuntimeComponentGuid=$InitialRuntimeComponentGuid",
    "-d", "InitialRuntimeTransitionApproved=$InitialRuntimeTransitionApproved",
    "-d", "BaselineInitialRuntimeVersion=$BaselineInitialRuntimeVersion",
    "-d", "SourceRevision=$initialRuntimeSourceRevision",
    "-d", "InitialRuntimeInventoryPath=$runtimeInventoryPath",
    "-d", "PackageVersion=$Version", '-out', $msiPath
) + $wixSources
Invoke-Checked $wixCommand.Source $wixArguments $repositoryRoot
$inspectionPath = Join-Path $outputRoot 'msi-inspection.json'
Export-MsiInspection $msiPath $inspectionPath
$inspection = Get-Content -LiteralPath $inspectionPath -Raw | ConvertFrom-Json
$productCodes = @(
    $inspection.properties |
        Where-Object { $_.property -eq 'ProductCode' } |
        ForEach-Object { [string]$_.value }
)
if ($productCodes.Count -ne 1 -or $productCodes[0] -notmatch '^\{[0-9A-F-]{36}\}$') {
    throw "MSI inspection did not yield one canonical ProductCode."
}
$packageSha256 = (Get-FileHash -LiteralPath $msiPath -Algorithm SHA256).Hash.ToLowerInvariant()
Copy-Item -LiteralPath $msiPath -Destination (Join-Path $releaseRoot (Split-Path -Leaf $msiPath)) -Force
$releaseManifestPath = Join-Path $releaseRoot "EndpointAgent-$Version-x64.release.json"
Write-Utf8NoBom $releaseManifestPath (@{
    initial_runtime_tree_sha256 = [string]$manifestPreview.artifact.tree_sha256
    package_sha256 = $packageSha256
    product_code = $productCodes[0]
    schema_version = 'endpoint_windows_release_v1'
    source_revision = $initialRuntimeSourceRevision
    version = $Version
} | ConvertTo-Json -Compress)
Write-Host "MSI: $msiPath"
