param([Guid]$RunId,[string]$PlanSha256,[string]$ExpectedBaselineSha256,[Guid]$ExpectedVmUuid,[Guid]$ExpectedDeviceId,[string]$ExpectedMac,[string]$ExpectedIp)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$install='C:\Program Files\Endpoint Platform\Agent';$data='C:\ProgramData\Endpoint Platform\Agent'
$recovery='C:\Endpoint81RecoveryTask13-'+$RunId.ToString('N')
$vm=(Get-CimInstance Win32_ComputerSystemProduct -OperationTimeoutSec 5).UUID
if(([Guid]$vm) -ne $ExpectedVmUuid){throw 'wrong guest VM identity'}
$net=@(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -OperationTimeoutSec 5|Where-Object {$_.MACAddress -eq $ExpectedMac -and $_.IPAddress -contains $ExpectedIp})
if($net.Count -ne 1){throw 'wrong guest network identity'}
$identity=Get-Content -LiteralPath (Join-Path $data 'enrollment-identity.json') -Raw|ConvertFrom-Json
if(([Guid]$identity.device_id) -ne $ExpectedDeviceId){throw 'wrong guest device identity'}
foreach($path in @($install,$data,$recovery,(Join-Path $recovery 'baseline.json'))){
 $item=Get-Item -LiteralPath $path
 while($null -ne $item){if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'preflight reparse'};$item=$item.Parent}
}
$service=Get-CimInstance Win32_Service -Filter "Name='EndpointAgent'" -OperationTimeoutSec 5
$selector=Get-Content -LiteralPath (Join-Path $install 'current.json') -Raw|ConvertFrom-Json
$owners=@();foreach($leaf in @('pending_update.json','startup-attempt.json','terminal-outcome.json')){
 if(Test-Path -LiteralPath (Join-Path $data ('updates\'+$leaf))){$owners+=$leaf}
}
if(Test-Path -LiteralPath 'C:\Program Files\Endpoint Platform\installer-state\transaction.json'){$owners+='transaction.json'}
$msi=@(Get-CimInstance Win32_Process -Filter "Name='msiexec.exe'" -OperationTimeoutSec 5|Select-Object ProcessId,CreationDate)
$inProgress=Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\InProgress'
$baseline=(Get-FileHash -LiteralPath (Join-Path $recovery 'baseline.json') -Algorithm SHA256).Hash.ToLowerInvariant()
if($baseline -cne $ExpectedBaselineSha256){throw 'baseline changed'}
[ordered]@{status='QUIESCENT_NATIVE81_OBSERVED';run_id=$RunId.ToString();plan_sha256=$PlanSha256;utc=[DateTime]::UtcNow.ToString('o');
 vm_uuid=([Guid]$vm).ToString();device_id=$identity.device_id;network_matches=$net.Count;
 service_state=$service.State;current=('versions/'+$selector.version);update_owners=@($owners);msi_in_progress=[bool]$inProgress;
 msiexec=@($msi);baseline_sha256=$baseline;marker_absent=(-not(Test-Path -LiteralPath (Join-Path $recovery 'after-snapshot-marker.txt')))}|ConvertTo-Json -Depth 6 -Compress
