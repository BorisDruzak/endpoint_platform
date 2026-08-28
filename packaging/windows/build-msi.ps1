[CmdletBinding()]
param(
    [ValidateSet("Release", "Debug")]
    [string]$Configuration = "Release",
    [ValidateSet("x64")]
    [string]$Platform = "x64",
    [string]$Version,
    [string]$InitialRuntimeManifest,
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
    [void]$builder.AppendLine('    <ComponentGroup Id="EndpointAgentGeneratedPayload">')
    $items = Get-ChildItem -LiteralPath $RuntimeRoot -Recurse -File |
        Where-Object { $_.FullName -ne (Join-Path $RuntimeRoot 'pc_agent.exe') } |
        Sort-Object FullName
    foreach ($item in $items) {
        $relative = Get-RelativePath $RuntimeRoot $item.FullName
        $componentId = Get-StableId -Prefix 'cmpPayload' -Value $relative
        $fileId = Get-StableId -Prefix 'filPayload' -Value $relative
        $subdirectory = [IO.Path]::GetDirectoryName($relative)
        $subdirectoryAttribute = if ($subdirectory) {
            ' Subdirectory="' + (Escape-Xml $subdirectory) + '"'
        } else {
            ''
        }
        [void]$builder.AppendLine(
            "      <Component Id=`"$componentId`" Directory=`"INITIALRUNTIMEDIR`"$subdirectoryAttribute Guid=`"*`" Bitness=`"always64`">"
        )
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
    }
    return $rows
}

function Export-MsiInspection {
    param([Parameter(Mandatory)][string]$MsiPath, [Parameter(Mandatory)][string]$OutputPath)
    $installer = New-Object -ComObject WindowsInstaller.Installer
    $database = $installer.OpenDatabase($MsiPath, 0)
    $inspection = [ordered]@{
        files = Read-MsiTable $database 'SELECT `File`, `Component_`, `FileName`, `FileSize` FROM `File`' @('file', 'component', 'name', 'size')
        components = Read-MsiTable $database 'SELECT `Component`, `ComponentId`, `Directory_`, `Attributes`, `KeyPath` FROM `Component`' @('component', 'guid', 'directory', 'attributes', 'key_path')
        services = Read-MsiTable $database 'SELECT `ServiceInstall`, `Name`, `DisplayName`, `ServiceType`, `StartType`, `ErrorControl`, `LoadOrderGroup`, `Dependencies`, `StartName`, `Password`, `Arguments`, `Component_` FROM `ServiceInstall`' @('id', 'name', 'display_name', 'service_type', 'start_type', 'error_control', 'load_order_group', 'dependencies', 'account', 'password', 'arguments', 'component')
        properties = Read-MsiTable $database 'SELECT `Property`, `Value` FROM `Property`' @('property', 'value')
    }
    $forbiddenProperty = $inspection.properties | Where-Object {
        $_.property -match '(?i)(claim|campaign|device.?token|credential|enroll)'
    }
    if ($forbiddenProperty) {
        throw "MSI inspection found a forbidden secret-bearing property name."
    }
    Write-Utf8NoBom $OutputPath ($inspection | ConvertTo-Json -Depth 8)
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
$initialRuntimeSourceRevision = [string]$manifestPreview.source_revision
if ($initialRuntimeSourceRevision -notmatch '^[0-9a-f]{40}$') {
    throw "Initial runtime manifest has an invalid source revision."
}
& git -C $repositoryRoot merge-base --is-ancestor $initialRuntimeSourceRevision $checkedOutSourceRevision
if ($LASTEXITCODE -ne 0) {
    throw "Initial runtime source revision is not an ancestor of the clean build source."
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
    '--baseline', $baselineInitialRuntimeManifest,
    '--source-revision', $initialRuntimeSourceRevision
)
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
if ([string]$initialRuntimeIdentity.source_revision -ne $initialRuntimeSourceRevision) {
    throw "Initial runtime manifest validation returned an unexpected source revision."
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
$provisionerSpec = Join-Path $repositoryRoot 'pc_agent\pyinstaller_windows_provision.spec'
$commonPyInstaller = @('--noconfirm', '--clean', '--distpath', $distRoot, '--workpath', $workRoot)
if (-not $ReusePythonBuild) {
    Invoke-Checked $python (@('-m', 'PyInstaller') + $commonPyInstaller + @($coreSpec)) $repositoryRoot
    Invoke-Checked $python (@('-m', 'PyInstaller') + $commonPyInstaller + @($launcherSpec)) $repositoryRoot
    Invoke-Checked $python (@('-m', 'PyInstaller') + $commonPyInstaller + @($serviceHostSpec)) $repositoryRoot
    Invoke-Checked $python (@('-m', 'PyInstaller') + $commonPyInstaller + @($provisionerSpec)) $repositoryRoot
}

$builtCore = Join-Path $distRoot 'endpoint_agent_core'
$builtCoreExe = Join-Path $builtCore 'endpoint_agent_core.exe'
$builtLauncher = Join-Path $distRoot 'launcher.exe'
$builtServiceHost = Join-Path $distRoot 'endpoint-agent-service.exe'
$builtProvisioner = Join-Path $distRoot 'endpoint-agent-provision.exe'
if (-not (Test-Path -LiteralPath $builtCoreExe -PathType Leaf)) {
    throw "Headless core build missing $builtCoreExe"
}
if (-not (Test-Path -LiteralPath $builtLauncher -PathType Leaf)) {
    throw "Launcher build missing $builtLauncher"
}
if (-not (Test-Path -LiteralPath $builtServiceHost -PathType Leaf)) {
    throw "Service host build missing $builtServiceHost"
}
if (-not (Test-Path -LiteralPath $builtProvisioner -PathType Leaf)) {
    throw "Provisioning helper build missing $builtProvisioner"
}
Get-ChildItem -LiteralPath $builtCore | ForEach-Object {
    Copy-Item -LiteralPath $_.FullName -Destination $runtimeStage -Recurse -Force
}
Move-Item -LiteralPath (Join-Path $runtimeStage 'endpoint_agent_core.exe') -Destination (Join-Path $runtimeStage 'pc_agent.exe')
$artifactValidationJson = & $python @($validationArguments + @('--artifact-root', $runtimeStage))
if ($LASTEXITCODE -ne 0) {
    throw "Staged initial runtime artifact validation failed."
}
$artifactValidationIdentity = $artifactValidationJson | ConvertFrom-Json
if ([string]$artifactValidationIdentity.version -ne $InitialRuntimeVersion) {
    throw "Staged artifact validation returned an unexpected runtime identity."
}
Write-Utf8NoBom (Join-Path $runtimeStage '.endpoint-msi-runtime.json') (@{
    component_guid = $InitialRuntimeComponentGuid
    schema_version = 1
    version = $InitialRuntimeVersion
} | ConvertTo-Json -Compress)
Copy-Item -LiteralPath $builtLauncher -Destination (Join-Path $programFilesStage 'launcher.exe')
Copy-Item -LiteralPath $builtServiceHost -Destination (Join-Path $programFilesStage 'endpoint-agent-service.exe')
Copy-Item -LiteralPath $builtProvisioner -Destination (Join-Path $programFilesStage 'endpoint-agent-provision.exe')
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
    'cmpServiceEntrypoints', 'cmpProvisioner'
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
        [ordered]@{ name = 'EndpointAgent'; account = 'NT AUTHORITY\LocalService'; start = 'auto'; recovery = 'restart'; binary = 'ProgramFiles/endpoint-agent-service.exe'; arguments = '--agent-service'; selector = 'ProgramFiles/current.json' },
        [ordered]@{ name = 'EndpointAgentUpdater'; account = 'LocalSystem'; start = 'demand'; recovery = 'restart'; binary = 'ProgramFiles/endpoint-agent-service.exe'; arguments = '--updater-service' }
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
