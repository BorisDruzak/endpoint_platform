<#
Connect using the UUID, assigned loopback port and public host key copied from
one authenticated Endpoint device card. This script does not enable policy.
-InspectOnly validates/builds the command without writing pins or connecting.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][guid]$DeviceId,
    [Parameter(Mandatory=$true)][ValidateRange(32000,41999)][int]$RemotePort,
    [Parameter(Mandatory=$true)]
    [ValidatePattern('^(?=.{1,64}$)(?:[A-Za-z0-9][A-Za-z0-9_\-]{0,14}\\)?[A-Za-z0-9][A-Za-z0-9_.\-]{0,63}$')]
    [string]$WindowsAdminUsername,
    [Parameter(Mandatory=$true)][ValidatePattern('^ssh-ed25519 [A-Za-z0-9+/]{68}$')][string]$HostPublicKey,
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$')][string]$GatewayAlias='endpoint-platform-server',
    [string]$OperatorKeyPath=(Join-Path $env:USERPROFILE '.ssh\id_ed25519'),
    [string]$KnownHostsDirectory=(Join-Path $env:USERPROFILE '.ssh'),
    [string]$RemoteCommand='powershell.exe -NoLogo -NoProfile',
    [switch]$InspectOnly
)
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
if($DeviceId -eq [guid]::Empty){throw 'Device UUID must not be empty'}
if($HostPublicKey -cnotmatch '^ssh-ed25519 [A-Za-z0-9+/]{68}$'){throw 'Invalid exact device host key'}
$blob=[Convert]::FromBase64String($HostPublicKey.Substring(12))
$header=[byte[]](0,0,0,11,115,115,104,45,101,100,50,53,53,49,57,0,0,0,32)
if($blob.Length -ne 51){throw 'Invalid Ed25519 host key'}
for($i=0;$i -lt $header.Length;$i++){if($blob[$i] -ne $header[$i]){throw 'Invalid Ed25519 host key'}}
if([Convert]::ToBase64String($blob) -cne $HostPublicKey.Substring(12)){throw 'Noncanonical device host key'}
$uuid=$DeviceId.ToString()
$alias='endpoint-device-'+$uuid
$directory=[IO.Path]::GetFullPath($KnownHostsDirectory)
$pin=Join-Path $directory ($alias+'.known_hosts')
$line=$alias+' '+$HostPublicKey
foreach($path in @($directory,$pin)){
    if(Test-Path -LiteralPath $path){
        if(((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Reparse pin path is not supported'}
    }
}
if(Test-Path -LiteralPath $pin){
    if([IO.File]::ReadAllText($pin).Trim() -cne $line){throw 'Device host key changed; verify authorized recovery before replacing its pin'}
}
$ssh=Join-Path ([Environment]::GetFolderPath('System')) 'OpenSSH\ssh.exe'
if(!(Test-Path -LiteralPath $ssh -PathType Leaf)){throw 'Windows OpenSSH client is unavailable'}
$proxy='"'+$ssh+'" -o BatchMode=yes -o StrictHostKeyChecking=yes -o ForwardAgent=no -o PermitLocalCommand=no -W %h:%p '+$GatewayAlias
$pinOption='UserKnownHostsFile="'+$pin.Replace('\','/')+'"'
$sshArgs=@('-F','NUL','-o','BatchMode=yes','-o','IdentitiesOnly=yes',
    '-o','StrictHostKeyChecking=yes','-o','GlobalKnownHostsFile=NUL',
    '-o',$pinOption,'-o',('HostKeyAlias='+$alias),'-o',('ProxyCommand='+$proxy),
    '-o','ForwardAgent=no','-o','PermitLocalCommand=no','-o','ClearAllForwardings=yes',
    '-o','ServerAliveInterval=15','-o','ServerAliveCountMax=2','-o','ConnectTimeout=10',
    '-i',[IO.Path]::GetFullPath($OperatorKeyPath),'-p',[string]$RemotePort,
    '-l',$WindowsAdminUsername.ToLowerInvariant(),'127.0.0.1',$RemoteCommand)
if($InspectOnly){
    [ordered]@{device_id=$uuid;windows_admin_username=$WindowsAdminUsername.ToLowerInvariant();
        executable=$ssh;arguments=$sshArgs;known_hosts_path=$pin;host_pin_line=$line}|ConvertTo-Json -Depth 4
    return
}
if(!(Test-Path -LiteralPath $OperatorKeyPath -PathType Leaf)){throw 'Approved operator private key is unavailable'}
if(!(Test-Path -LiteralPath $directory)){New-Item -ItemType Directory -Path $directory -ErrorAction Stop|Out-Null}
if(!(Test-Path -LiteralPath $pin)){
    # Never overwrite a concurrent or changed pin. Public key only, no credentials.
    $stream=[IO.File]::Open($pin,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
    try{$bytes=[Text.Encoding]::ASCII.GetBytes($line+"`n");$stream.Write($bytes,0,$bytes.Length);$stream.Flush()}finally{$stream.Dispose()}
}
& $ssh @sshArgs
if($LASTEXITCODE -ne 0){throw ('Reserve SSH failed with exit code '+$LASTEXITCODE)}
