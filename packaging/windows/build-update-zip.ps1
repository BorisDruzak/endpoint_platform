[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$RuntimeRoot,
    [Parameter(Mandatory)][string]$Version,
    [Parameter(Mandatory)][string]$SourceRevision,
    [Parameter(Mandatory)][string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-SafeRuntimeTree {
    param([Parameter(Mandatory)][string]$Root)
    $full = [IO.Path]::GetFullPath($Root)
    if (-not (Test-Path -LiteralPath $full -PathType Container)) {
        throw "Runtime root is not a directory: $full"
    }
    $rootItem = Get-Item -LiteralPath $full -Force
    if ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw "Runtime root must not be a reparse point: $full"
    }
    $files = @(Get-ChildItem -LiteralPath $full -Recurse -File -Force | Sort-Object FullName)
    if ($files.Count -eq 0) { throw 'Runtime root has no files.' }
    foreach ($file in $files) {
        if ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "Runtime payload contains a reparse point: $($file.FullName)"
        }
    }
    if (-not (Test-Path -LiteralPath (Join-Path $full 'pc_agent.exe') -PathType Leaf)) {
        throw 'Runtime payload has no pc_agent.exe.'
    }
    return @{ root = $full; files = $files }
}

if ($Version -notmatch '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$') {
    throw "Invalid release version: $Version"
}
if ($SourceRevision -notmatch '^[0-9a-f]{40}$') {
    throw 'SourceRevision must be a lowercase 40-character Git revision.'
}

$tree = Assert-SafeRuntimeTree -Root $RuntimeRoot
$runtimeVersion = & (Join-Path $tree.root 'pc_agent.exe') --print-version
if ($LASTEXITCODE -ne 0 -or ([string]$runtimeVersion).Trim() -ne $Version) {
    throw 'Runtime pc_agent.exe version does not match Version.'
}
$destination = [IO.Path]::GetFullPath($OutputPath)
if ([IO.Path]::GetExtension($destination) -ne '.zip') { throw 'OutputPath must end in .zip.' }
if (Test-Path -LiteralPath $destination) { throw "Refusing to overwrite existing archive: $destination" }
$destinationParent = Split-Path -Parent $destination
New-Item -ItemType Directory -Path $destinationParent -Force | Out-Null

$stage = Join-Path $destinationParent ('.endpoint-update-' + [guid]::NewGuid().ToString('N'))
$temporaryZip = Join-Path $destinationParent ('.endpoint-update-' + [guid]::NewGuid().ToString('N') + '.zip')
try {
    New-Item -ItemType Directory -Path $stage | Out-Null
    $entries = @()
    foreach ($file in $tree.files) {
        $relative = $file.FullName.Substring($tree.root.Length).TrimStart('\', '/') -replace '\\', '/'
        $target = Join-Path $stage ($relative -replace '/', [IO.Path]::DirectorySeparatorChar)
        New-Item -ItemType Directory -Path (Split-Path -Parent $target) -Force | Out-Null
        Copy-Item -LiteralPath $file.FullName -Destination $target -Force
        $entries += [ordered]@{
            path = $relative
            sha256 = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant()
            size = (Get-Item -LiteralPath $target).Length
        }
    }
    $manifest = [ordered]@{
        files = @($entries | Sort-Object path)
        schema_version = 1
        source_revision = $SourceRevision
        version = $Version
    }
    [IO.File]::WriteAllText(
        (Join-Path $stage 'endpoint-update-manifest.json'),
        ($manifest | ConvertTo-Json -Depth 5 -Compress),
        [Text.UTF8Encoding]::new($false)
    )
    Compress-Archive -LiteralPath (Get-ChildItem -LiteralPath $stage -Force | ForEach-Object FullName) -DestinationPath $temporaryZip -CompressionLevel Optimal
    Move-Item -LiteralPath $temporaryZip -Destination $destination
}
finally {
    Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $temporaryZip -Force -ErrorAction SilentlyContinue
}

Write-Output $destination
