[CmdletBinding()]
param(
    [ValidateSet("Release", "Debug")]
    [string]$Configuration = "Release",
    [ValidateSet("x64")]
    [string]$Platform = "x64",
    [string]$Version,
    [string]$InitialRuntimeVersion,
    [switch]$ApproveInitialRuntimeTransition,
    [switch]$ReusePythonBuild,
    [switch]$PrepareOnly
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
    $view.Execute()
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
        $view.Close()
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
$packagingRoot = [IO.Path]::GetFullPath($PSScriptRoot)
$buildRoot = [IO.Path]::GetFullPath((Join-Path $packagingRoot "build\$Configuration-$Platform"))
$allowedBuildParent = [IO.Path]::GetFullPath((Join-Path $packagingRoot 'build'))
if (-not $buildRoot.StartsWith($allowedBuildParent + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing to use a build directory outside packaging/windows/build."
}

$baselineInitialRuntime = [IO.File]::ReadAllText(
    (Join-Path $packagingRoot 'initial-runtime.version')
).Trim()
if (-not $InitialRuntimeVersion) {
    $InitialRuntimeVersion = $baselineInitialRuntime
}
if (-not $Version) {
    $Version = Get-AgentVersion (Join-Path $repositoryRoot 'pc_agent\version.py')
}
Assert-SemVerTriplet $Version 'Package version'
Assert-SemVerTriplet $InitialRuntimeVersion 'Initial runtime version'
if ($InitialRuntimeVersion -ne $baselineInitialRuntime -and -not $ApproveInitialRuntimeTransition) {
    throw "An initial runtime transition requires -ApproveInitialRuntimeTransition and review of selector compatibility."
}

if ((Test-Path -LiteralPath $buildRoot) -and -not $ReusePythonBuild) {
    Remove-Item -LiteralPath $buildRoot -Recurse -Force
}
$pyinstallerRoot = Join-Path $buildRoot 'pyinstaller'
$distRoot = Join-Path $pyinstallerRoot 'dist'
$workRoot = Join-Path $pyinstallerRoot 'work'
$stagingRoot = Join-Path $buildRoot 'staging'
$programFilesStage = Join-Path $stagingRoot 'ProgramFiles'
$runtimeStage = Join-Path $programFilesStage "versions\$InitialRuntimeVersion"
$outputRoot = Join-Path $buildRoot 'output'
if ($ReusePythonBuild) {
    foreach ($generatedPath in @($stagingRoot, $outputRoot, (Join-Path $buildRoot 'PayloadComponents.generated.wxs'))) {
        if (Test-Path -LiteralPath $generatedPath) {
            Remove-Item -LiteralPath $generatedPath -Recurse -Force
        }
    }
}
New-Item -ItemType Directory -Path $runtimeStage, $outputRoot -Force | Out-Null

$python = (Get-Command python -ErrorAction Stop).Source
$coreSpec = Join-Path $repositoryRoot 'pc_agent\pyinstaller_endpoint_core_windows.spec'
$launcherSpec = Join-Path $repositoryRoot 'pc_agent\pyinstaller_launcher_win.spec'
$commonPyInstaller = @('--noconfirm', '--clean', '--distpath', $distRoot, '--workpath', $workRoot)
if (-not $ReusePythonBuild) {
    Invoke-Checked $python (@('-m', 'PyInstaller') + $commonPyInstaller + @($coreSpec)) $repositoryRoot
    Invoke-Checked $python (@('-m', 'PyInstaller') + $commonPyInstaller + @($launcherSpec)) $repositoryRoot
}

$builtCore = Join-Path $distRoot 'endpoint_agent_core'
$builtCoreExe = Join-Path $builtCore 'endpoint_agent_core.exe'
$builtLauncher = Join-Path $distRoot 'launcher.exe'
if (-not (Test-Path -LiteralPath $builtCoreExe -PathType Leaf)) {
    throw "Headless core build missing $builtCoreExe"
}
if (-not (Test-Path -LiteralPath $builtLauncher -PathType Leaf)) {
    throw "Launcher build missing $builtLauncher"
}
Get-ChildItem -LiteralPath $builtCore | ForEach-Object {
    Copy-Item -LiteralPath $_.FullName -Destination $runtimeStage -Recurse -Force
}
Move-Item -LiteralPath (Join-Path $runtimeStage 'endpoint_agent_core.exe') -Destination (Join-Path $runtimeStage 'pc_agent.exe')
Copy-Item -LiteralPath $builtLauncher -Destination (Join-Path $programFilesStage 'launcher.exe')
New-Item -ItemType Directory -Path (Join-Path $programFilesStage 'config'), (Join-Path $programFilesStage 'docs') -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $packagingRoot 'assets\agent-config.yaml') -Destination (Join-Path $programFilesStage 'config\agent-config.yaml')
Copy-Item -LiteralPath (Join-Path $packagingRoot 'README.md') -Destination (Join-Path $programFilesStage 'docs\README.md')
Write-Utf8NoBom (Join-Path $programFilesStage 'current.json') (@{ version = $InitialRuntimeVersion } | ConvertTo-Json -Compress)

$generatedWix = Join-Path $buildRoot 'PayloadComponents.generated.wxs'
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
    'cmpLauncher', 'cmpCurrentSelector', 'cmpConfigTemplate', 'cmpPublicReadme',
    'cmpProgramDataRoot', 'cmpInstallRootCleanup', 'cmpServiceEntrypoints'
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
        initial_runtime_transition_approved = [bool]$ApproveInitialRuntimeTransition
    }
    files = @($fileManifest)
    components = @($componentManifest | Sort-Object)
    services = @(
        [ordered]@{ name = 'EndpointAgent'; account = 'NT AUTHORITY\LocalService'; start = 'auto'; recovery = 'restart' },
        [ordered]@{ name = 'EndpointAgentUpdater'; account = 'LocalSystem'; start = 'demand'; recovery = 'restart' }
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
    "-dStagingDir=$stagingRoot", "-dInitialRuntimeVersion=$InitialRuntimeVersion",
    "-dPackageVersion=$Version", '-out', $msiPath
) + $wixSources
Invoke-Checked $wixCommand.Source $wixArguments $repositoryRoot
Export-MsiInspection $msiPath (Join-Path $outputRoot 'msi-inspection.json')
Write-Host "MSI: $msiPath"
