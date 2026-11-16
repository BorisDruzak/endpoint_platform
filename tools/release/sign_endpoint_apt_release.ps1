[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Release,
    [Parameter(Mandatory)][string]$InRelease,
    [Parameter(Mandatory)][string]$PublisherHome,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9A-Fa-f]{40}\z')][string]$Fingerprint,
    [Parameter(Mandatory)][string]$GitBin
)

$ErrorActionPreference = 'Stop'
$gpg = Join-Path $GitBin 'gpg.exe'
$cygpath = Join-Path $GitBin 'cygpath.exe'
$homePath = (Resolve-Path -LiteralPath $PublisherHome).Path
$homePosix = & $cygpath -u $homePath
if ($LASTEXITCODE -ne 0 -or !$homePosix) {
    throw 'Unable to resolve the Git for Windows GnuPG home'
}

$target = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($InRelease)
if (Test-Path -LiteralPath $target) {
    throw 'InRelease already exists'
}
$source = [IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $Release).Path)
if ($source.Length -lt 2 -or $source.Length -gt 1MB -or $source[-1] -ne 10 -or $source -contains 13) {
    throw 'Release must have LF line endings and a terminating LF'
}

$scratch = Join-Path ([IO.Path]::GetDirectoryName($target)) ('.apt-sign-' + [guid]::NewGuid().ToString('N'))
$scratchRelease = Join-Path $scratch 'Release'
$scratchSignature = Join-Path $scratch 'InRelease'
$null = New-Item -ItemType Directory -Path $scratch
try {
    # Git for Windows adds a separator LF that Linux gpgv includes in the cleartext.
    $stream = [IO.File]::Open($scratchRelease, 'CreateNew', 'Write', 'None')
    try { $stream.Write($source, 0, $source.Length - 1) }
    finally { $stream.Dispose() }

    $passphrase = [Security.Cryptography.ProtectedData]::Unprotect(
        [IO.File]::ReadAllBytes((Join-Path $homePath 'passphrase.dpapi')),
        $null, [Security.Cryptography.DataProtectionScope]::CurrentUser
    )
    try {
        if (!$passphrase.Length -or $passphrase -contains 0 -or $passphrase -contains 10 -or $passphrase -contains 13) {
            throw 'The publisher passphrase must be a single nonempty line'
        }
        $launch = [Diagnostics.ProcessStartInfo]::new($gpg)
        $launch.UseShellExecute = $false
        $launch.RedirectStandardInput = $true
        $launch.StandardInputEncoding = [Text.UTF8Encoding]::new($false)
        foreach ($argument in @(
            '--homedir', $homePosix, '--batch', '--pinentry-mode', 'loopback', '--passphrase-fd', '0',
            '--local-user', $Fingerprint, '--digest-algo', 'SHA256', '--output', $scratchSignature,
            '--clearsign', $scratchRelease
        )) {
            $null = $launch.ArgumentList.Add($argument)
        }
        $process = [Diagnostics.Process]::Start($launch)
        try {
            $inputStream = $process.StandardInput.BaseStream
            $inputStream.Write($passphrase, 0, $passphrase.Length)
            # Preserve the Windows CRLF input used to create the protected signing key.
            $inputStream.WriteByte(13)
            $inputStream.WriteByte(10)
            $inputStream.Flush()
            $process.StandardInput.Close()
            if (!$process.WaitForExit(60 * 1000)) {
                $process.Kill()
                $process.WaitForExit()
                throw 'GnuPG timed out'
            }
            if ($process.ExitCode -ne 0) {
                throw "GnuPG signing failed with exit code $($process.ExitCode)"
            }
        }
        finally { $process.Dispose() }
    }
    finally { [Array]::Clear($passphrase, 0, $passphrase.Length) }

    [IO.File]::Move($scratchSignature, $target)
}
finally {
    foreach ($file in @($scratchRelease, $scratchSignature)) {
        if (Test-Path -LiteralPath $file) { Remove-Item -LiteralPath $file }
    }
    Remove-Item -LiteralPath $scratch
}
