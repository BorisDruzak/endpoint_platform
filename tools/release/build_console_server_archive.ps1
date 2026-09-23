param(
    [Parameter(Mandatory = $true)]
    [string] $OutputPath
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location -LiteralPath $repositoryRoot

if ((git status --porcelain) -ne $null) {
    throw 'Release archive requires a clean committed working tree.'
}

$releaseCommit = (git rev-parse --short=12 HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $releaseCommit -notmatch '^[0-9a-f]{12}$') {
    throw 'Cannot resolve the release commit.'
}

Push-Location -LiteralPath (Join-Path $repositoryRoot 'webapp')
try {
    npm ci
    if ($LASTEXITCODE -ne 0) { throw 'npm ci failed.' }
    npm run build
    if ($LASTEXITCODE -ne 0) { throw 'Console build failed.' }
}
finally {
    Pop-Location
}

$tempRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd('\')
$stage = Join-Path $tempRoot ('endpoint-console-release-' + [guid]::NewGuid().ToString('N'))
$stageResolved = [System.IO.Path]::GetFullPath($stage)
if (-not $stageResolved.StartsWith($tempRoot + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'Release staging path escaped the system temporary directory.'
}

New-Item -ItemType Directory -Path $stageResolved | Out-Null
try {
    $releaseDirectory = Join-Path $stageResolved "endpoint-platform-$releaseCommit"
    New-Item -ItemType Directory -Path $releaseDirectory | Out-Null
    $sourceTar = Join-Path $stageResolved 'source.tar'
    git archive --format=tar --output="$sourceTar" HEAD endpoint_server endpoint_contracts alembic.ini requirements-server.txt tools/__init__.py tools/register_windows_setup_release.py
    if ($LASTEXITCODE -ne 0) { throw 'git archive failed.' }
    tar -xf $sourceTar -C $releaseDirectory
    if ($LASTEXITCODE -ne 0) { throw 'Source archive extraction failed.' }

    $bundleTarget = Join-Path $releaseDirectory 'webapp\dist'
    New-Item -ItemType Directory -Path $bundleTarget -Force | Out-Null
    Copy-Item -Path (Join-Path $repositoryRoot 'webapp\dist\*') -Destination $bundleTarget -Recurse
    if (-not (Test-Path -LiteralPath (Join-Path $bundleTarget 'index.html'))) {
        throw 'Console index is absent from release stage.'
    }

    $archive = [System.IO.Path]::GetFullPath($OutputPath)
    tar -czf $archive -C $stageResolved "endpoint-platform-$releaseCommit"
    if ($LASTEXITCODE -ne 0) { throw 'Final release archive failed.' }
    Write-Output $archive
}
finally {
    if (Test-Path -LiteralPath $stageResolved) {
        Remove-Item -LiteralPath $stageResolved -Recurse -Force
    }
}
