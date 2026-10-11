param([Guid]$RunId,[Guid]$ExpectedVmUuid,[string]$RegistrySha256,[uint32[]]$Ids)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$OutputEncoding=[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$timer=[Diagnostics.Stopwatch]::StartNew()
function Bound {if($timer.ElapsedMilliseconds -ge 25000){throw 'identity observation bound'}}
if($RunId -eq [Guid]::Empty -or $ExpectedVmUuid -eq [Guid]::Empty -or $RegistrySha256 -cnotmatch '^[0-9a-f]{64}$' -or $Ids.Count -lt 1 -or $Ids.Count -gt 16 -or @($Ids|Select-Object -Unique).Count -ne $Ids.Count){throw 'fixed identity request'}
if([Guid](Get-CimInstance Win32_ComputerSystemProduct -Property UUID -OperationTimeoutSec 3).UUID -ne $ExpectedVmUuid){throw 'identity guest binding'}
Add-Type -TypeDefinition @'
using System;using System.Text;using System.Runtime.InteropServices;
public static class Task13IdentityNative {
 [DllImport("kernel32.dll",SetLastError=true)] public static extern IntPtr OpenProcess(uint access,bool inherit,uint pid);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool CloseHandle(IntPtr handle);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern uint GetProcessId(IntPtr handle);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool GetProcessTimes(IntPtr handle,out long birth,out long exit,out long kernel,out long user);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] public static extern bool QueryFullProcessImageName(IntPtr handle,uint flags,StringBuilder image,ref uint size);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool GetProcessHandleCount(IntPtr handle,out uint count);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool ProcessIdToSessionId(uint pid,out uint session);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern uint WaitForSingleObject(IntPtr handle,uint milliseconds);
}
'@
$sha=[Security.Cryptography.SHA256]::Create()
function HashText([string]$value){return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($value)))).Replace('-','').ToLowerInvariant()}
function ProcessRow([uint32]$target){
 Bound
 return @(Get-CimInstance Win32_Process -Filter "ProcessId=$target" -Property ProcessId,ParentProcessId,CreationDate,ExecutablePath,Name,SessionId -OperationTimeoutSec 3)
}
function Sample([uint32]$target,[ref]$held){
 Bound;$held.Value=[Task13IdentityNative]::OpenProcess(0x101000,$false,$target)
 $errorCode=[Runtime.InteropServices.Marshal]::GetLastWin32Error()
 $sample=[ordered]@{status='UNKNOWN';pid=$target;birth_filetime=$null;image=$null;image_sha256=$null;parent_pid=$null;session_id=$null;handle_count=$null;wait_result=$null;native_error=$errorCode;cim_count=$null;cim_birth_filetime=$null;cim_image_equal=$null;cim_session_equal=$null}
 if($held.Value -eq [IntPtr]::Zero){
  if($errorCode -ne 87){return $sample}
  $cim=@(ProcessRow $target);$sample.cim_count=$cim.Count
  if($cim.Count -eq 0){$sample.status='ABSENT'}
  return $sample
 }
 $sample.native_error=0
 [long]$birth=0;[long]$exit=0;[long]$kernel=0;[long]$user=0
 if(-not [Task13IdentityNative]::GetProcessTimes($held.Value,[ref]$birth,[ref]$exit,[ref]$kernel,[ref]$user)){throw 'native creation unavailable'}
 if([Task13IdentityNative]::GetProcessId($held.Value) -ne $target){throw 'native PID changed'}
 $image=[Text.StringBuilder]::new(32768);[uint32]$size=32768
 if(-not [Task13IdentityNative]::QueryFullProcessImageName($held.Value,0,$image,[ref]$size)){throw 'native image unavailable'}
 [uint32]$count=0;[uint32]$session=0
 if(-not [Task13IdentityNative]::GetProcessHandleCount($held.Value,[ref]$count)){throw 'native handle count unavailable'}
 if(-not [Task13IdentityNative]::ProcessIdToSessionId($target,[ref]$session)){throw 'native session unavailable'}
 $sample.birth_filetime=$birth;$sample.image=$image.ToString();$sample.image_sha256=HashText $sample.image
 $sample.handle_count=$count;$sample.session_id=$session
 $cim=@(ProcessRow $target);$sample.cim_count=$cim.Count
 if($cim.Count -eq 1){
  $x=$cim[0];$sample.parent_pid=[uint32]$x.ParentProcessId
  $sample.cim_birth_filetime=$x.CreationDate.ToUniversalTime().ToFileTimeUtc()
  $sample.cim_image_equal=($sample.image -ieq $x.ExecutablePath)
  $sample.cim_session_equal=($session -eq $x.SessionId)
 }
 Bound;$sample.wait_result=[Task13IdentityNative]::WaitForSingleObject($held.Value,0)
 $sample.status='PRESENT'
 return $sample
}
$rows=@();$parents=@()
try{
 foreach($target in $Ids){
  $firstHandle=[IntPtr]::Zero;$secondHandle=[IntPtr]::Zero
  $row=[ordered]@{pid=$target;first=$null;second=$null;retained_first_not_exited=$null;error_type=$null}
  try{
   $row.first=Sample $target ([ref]$firstHandle)
   $row.second=Sample $target ([ref]$secondHandle)
   if($firstHandle -ne [IntPtr]::Zero){$row.retained_first_not_exited=([Task13IdentityNative]::WaitForSingleObject($firstHandle,0) -eq 258)}
  }catch{$row.error_type=$_.Exception.GetType().Name}
  finally{
   if($firstHandle -ne [IntPtr]::Zero){[void][Task13IdentityNative]::CloseHandle($firstHandle)}
   if($secondHandle -ne [IntPtr]::Zero){[void][Task13IdentityNative]::CloseHandle($secondHandle)}
  }
  $rows+=$row
 }
 foreach($parentId in @($rows|Where-Object {$null -ne $_.first -and $null -ne $_.first.parent_pid}|ForEach-Object {$_.first.parent_pid}|Select-Object -Unique)){
  $entry=[ordered]@{pid=$parentId;status='UNKNOWN';image=$null;birth_filetime=$null;session_id=$null;error_type=$null}
  try{Bound;$parent=@(ProcessRow $parentId);if($parent.Count -eq 0){$entry.status='ABSENT'}elseif($parent.Count -eq 1){$entry.image=$parent[0].ExecutablePath;$entry.birth_filetime=$parent[0].CreationDate.ToUniversalTime().ToFileTimeUtc();$entry.session_id=$parent[0].SessionId;$entry.status='CIM_METADATA'}}catch{$entry.error_type=$_.Exception.GetType().Name}
  $parents+=$entry
 }
 $value=[ordered]@{schema='task13_native_process_identity_v1';status='READ_ONLY_PROCESS_IDENTITY_OBSERVATION';run_id=$RunId.ToString();vm_uuid=$ExpectedVmUuid.ToString();registry_sha256=$RegistrySha256;utc=[DateTime]::UtcNow.ToString('o');rows=$rows;parent_observations=$parents}
 $json=$value|ConvertTo-Json -Compress -Depth 8
 if([Text.Encoding]::UTF8.GetByteCount($json) -gt 49152){throw 'identity output bound'}
 [Console]::Out.WriteLine($json);[Console]::Out.Flush()
}finally{$sha.Dispose()}
