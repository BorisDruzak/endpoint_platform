[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('\A[A-Za-z0-9][A-Za-z0-9_.-]*\z')][string]$RepositoryHost,
    [Parameter(Mandatory)][ValidatePattern('\A/[A-Za-z0-9_./-]+\z')][string]$DistributionRoot,
    [Parameter(Mandatory)][string]$OutputDirectory,
    [Parameter(Mandatory)][string]$Keyring,
    [Parameter(Mandatory)][string]$PublisherHome,
    [Parameter(Mandatory)][string]$GitBin,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9A-F]{40}\z')][string]$NoblePublisher,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9A-F]{40}\z')][string]$BookwormPublisher,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9A-F]{40}\z')][string]$SigningFingerprint
)

$ErrorActionPreference = 'Stop'
$sshOptions = @('-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10')
$keyringPath = (Resolve-Path -LiteralPath $Keyring).Path
$outputRoot = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDirectory)
$channels = @(
    @{ Name = 'noble'; Repository = 'ubuntu'; Publisher = $NoblePublisher }
    @{ Name = 'bookworm'; Repository = 'debian'; Publisher = $BookwormPublisher }
)

function Invoke-RepositoryCommand([string]$Command) {
    $result = & ssh @sshOptions $RepositoryHost $Command
    if ($LASTEXITCODE -ne 0) { throw "Repository SSH command failed with exit code $LASTEXITCODE" }
    return $result
}

function Copy-RepositoryFiles([string[]]$Paths, [string]$Destination) {
    & scp -q @sshOptions -- @Paths $Destination
    if ($LASTEXITCODE -ne 0) { throw "Publisher SCP transfer failed with exit code $LASTEXITCODE" }
}

$remote = Invoke-RepositoryCommand 'mktemp -d /dev/shm/endpoint-apt-external.XXXXXXXX'
if ($remote -cnotmatch '\A/dev/shm/endpoint-apt-external\.[A-Za-z0-9]{8}\z') {
    throw 'Repository host returned an invalid workspace'
}

try {
    Copy-RepositoryFiles @(
        (Join-Path $PSScriptRoot 'build_ubuntu_apt_repository.py')
        (Join-Path $PSScriptRoot 'prepare_external_apt_renewal.py')
    ) "${RepositoryHost}:${remote}/"
    Copy-RepositoryFiles @($keyringPath) "${RepositoryHost}:${remote}/publishers.gpg"
    Invoke-RepositoryCommand "mkdir '$remote/noble' '$remote/bookworm'"

    foreach ($channel in $channels) {
        $suite = $channel.Name
        $root = "$DistributionRoot/$($channel.Repository)"
        $work = "$remote/$suite"
        $program = "python3 -B '$remote/prepare_external_apt_renewal.py'"
        $commonArgs = "'$root' '$work' '$remote/publishers.gpg' '$suite' '$($channel.Publisher)'"
        $draft = Invoke-RepositoryCommand "$program draft $commonArgs" | ConvertFrom-Json
        if ($draft.source_sha256 -cnotmatch '\A[0-9a-f]{64}\z') { throw 'Invalid source hash' }
        if (!$draft.draft_sha256) {
            Write-Output "$suite verified, renewal not due, source $($draft.source_sha256)"
            continue
        }
        if ($draft.draft_sha256 -cnotmatch '\A[0-9a-f]{64}\z') { throw 'Invalid draft hash' }

        $parent = Join-Path $outputRoot "$suite/$($draft.source_sha256)/$SigningFingerprint"
        $null = New-Item -ItemType Directory -Path $parent -Force
        $existing = Get-ChildItem -LiteralPath $parent -Directory |
            Where-Object Name -CMatch '\A[0-9]{8}T[0-9]{6}Z\z' |
            Sort-Object Name -Descending | Select-Object -First 1
        $reused = $false
        if ($existing) {
            $receipt = Get-Content -LiteralPath (Join-Path $existing.FullName 'verified.json') -Raw | ConvertFrom-Json
            if ([datetimeoffset]$receipt.valid_until -gt [DateTimeOffset]::UtcNow) {
                $names = @('Release', 'InRelease', 'request.json')
                $paths = @($names | ForEach-Object { Join-Path $existing.FullName $_ })
                Copy-RepositoryFiles $paths "${RepositoryHost}:${work}/"
                $verified = Invoke-RepositoryCommand "$program verify $commonArgs --successor '$SigningFingerprint'" | ConvertFrom-Json
                if ($verified.candidate_sha256 -cne $receipt.candidate_sha256 -or $verified.source_sha256 -cne $draft.source_sha256) {
                    throw 'Reverified candidate differs from its receipt'
                }
                Write-Output "$suite verified existing candidate $($existing.FullName)"
                $reused = $true
            }
        }
        if ($reused) { continue }

        $stage = Join-Path $parent ('.prepare-' + [guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path $stage
        try {
            Copy-RepositoryFiles @("${RepositoryHost}:${work}/Release", "${RepositoryHost}:${work}/request.json") "$stage/"
            $release = Join-Path $stage 'Release'
            $signed = Join-Path $stage 'InRelease'
            if ((Get-FileHash -LiteralPath $release).Hash.ToLowerInvariant() -cne $draft.draft_sha256) {
                throw 'Downloaded Release differs from the verified draft'
            }
            & (Join-Path $PSScriptRoot 'sign_endpoint_apt_release.ps1') -Release $release -InRelease $signed `
                -PublisherHome $PublisherHome -Fingerprint $SigningFingerprint -GitBin $GitBin
            Copy-RepositoryFiles @($signed) "${RepositoryHost}:${work}/InRelease"
            $verified = Invoke-RepositoryCommand "$program verify $commonArgs --successor '$SigningFingerprint'" | ConvertFrom-Json
            if ((Get-FileHash -LiteralPath $signed).Hash.ToLowerInvariant() -cne $verified.candidate_sha256 -or
                $verified.source_sha256 -cne $draft.source_sha256) {
                throw 'Verified signature or source differs from the local candidate'
            }
            $verified | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $stage 'verified.json') -Encoding utf8
            $validUntil = [datetimeoffset]$verified.valid_until
            $destination = Join-Path $parent $validUntil.UtcDateTime.ToString('yyyyMMddTHHmmssZ')
            [IO.Directory]::Move($stage, $destination)
            Write-Output "$suite prepared candidate $destination"
        }
        finally {
            if (Test-Path -LiteralPath $stage) {
                foreach ($name in @('Release', 'InRelease', 'request.json', 'verified.json')) {
                    $path = Join-Path $stage $name
                    if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path }
                }
                Remove-Item -LiteralPath $stage
            }
        }
    }
}
finally {
    Invoke-RepositoryCommand "test -O '$remote' && rm -rf -- '$remote' && test ! -e '$remote'"
}
