param([Guid]$RunId,[Guid]$ExpectedVmUuid,[string]$RegistrySha256,[uint32[]]$Ids)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$OutputEncoding=[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$timer=[Diagnostics.Stopwatch]::StartNew()
$script:Stage='START';$script:NativeError=$null;$script:Partial=$null;$diagnostics=@()
function Stage([string]$name){$script:Stage=$name;$script:NativeError=$null}
function ErrorDetails($record){
 $chain=@();$exception=$record.Exception
 for($depth=0;$null -ne $exception -and $depth -lt 4;$depth++){
  $native=$null;if($null -ne $exception.PSObject.Properties['NativeErrorCode']){$native=$exception.NativeErrorCode}
  $chain+=@{type=$exception.GetType().FullName;hresult=$exception.HResult;native_error_code=$native}
  $exception=$exception.InnerException
 }
 $fixed=@('identity observation bound','native creation unavailable','native PID changed','native image unavailable','native handle count unavailable','native session unavailable')
 $message=$record.Exception.Message;$messageId=$null;if($fixed -ccontains $message){$messageId=$message}
 $fqid=$record.FullyQualifiedErrorId;$fqidSafe=$null
 if($fixed -ccontains $fqid -or $fqid -cmatch '^[A-Za-z0-9_.]+(,[A-Za-z0-9_.]+)*$'){$fqidSafe=$fqid}
 return @{error_record_type=$record.GetType().FullName;fully_qualified_error_id=$fqidSafe;fully_qualified_error_id_sha256=(HashText $fqid);message_id=$messageId;category=$record.CategoryInfo.Category.ToString();reason=$record.CategoryInfo.Reason;line=$record.InvocationInfo.ScriptLineNumber;exceptions=$chain}
}

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
 Stage 'Get-CimInstance.Win32_Process';Bound
 return @(Get-CimInstance Win32_Process -Filter "ProcessId=$target" -Property ProcessId,ParentProcessId,CreationDate,ExecutablePath,Name,SessionId -OperationTimeoutSec 3)
}
function Sample([uint32]$target,[ref]$held){
 Stage 'OpenProcess';Bound;$held.Value=[Task13IdentityNative]::OpenProcess(0x101000,$false,$target)
 $errorCode=[Runtime.InteropServices.Marshal]::GetLastWin32Error()
 $script:NativeError=$errorCode
 $sample=[ordered]@{status='UNKNOWN';pid=$target;birth_filetime=$null;image=$null;image_sha256=$null;parent_pid=$null;session_id=$null;handle_count=$null;wait_result=$null;native_error=$errorCode;cim_count=$null;cim_birth_filetime=$null;cim_image_equal=$null;cim_session_equal=$null}
 $script:Partial=$sample
 if($held.Value -eq [IntPtr]::Zero){
  if($errorCode -ne 87){return $sample}
  $cim=@(ProcessRow $target);$sample.cim_count=$cim.Count
  if($cim.Count -eq 0){$sample.status='ABSENT'}
  return $sample
 }
 $sample.native_error=0
 [long]$birth=0;[long]$exit=0;[long]$kernel=0;[long]$user=0
 Stage 'GetProcessTimes'
 if(-not [Task13IdentityNative]::GetProcessTimes($held.Value,[ref]$birth,[ref]$exit,[ref]$kernel,[ref]$user)){$script:NativeError=[Runtime.InteropServices.Marshal]::GetLastWin32Error();throw 'native creation unavailable'}
 $script:Partial.birth_filetime=$birth
 Stage 'GetProcessId'
 $actualId=[Task13IdentityNative]::GetProcessId($held.Value);$script:NativeError=[Runtime.InteropServices.Marshal]::GetLastWin32Error()
 if($actualId -ne $target){throw 'native PID changed'}
 $image=[Text.StringBuilder]::new(32768);[uint32]$size=32768
 Stage 'QueryFullProcessImageName'
 if(-not [Task13IdentityNative]::QueryFullProcessImageName($held.Value,0,$image,[ref]$size)){$script:NativeError=[Runtime.InteropServices.Marshal]::GetLastWin32Error();throw 'native image unavailable'}
 [uint32]$count=0;[uint32]$session=0
 Stage 'GetProcessHandleCount'
 if(-not [Task13IdentityNative]::GetProcessHandleCount($held.Value,[ref]$count)){$script:NativeError=[Runtime.InteropServices.Marshal]::GetLastWin32Error();throw 'native handle count unavailable'}
 Stage 'ProcessIdToSessionId'
 if(-not [Task13IdentityNative]::ProcessIdToSessionId($target,[ref]$session)){$script:NativeError=[Runtime.InteropServices.Marshal]::GetLastWin32Error();throw 'native session unavailable'}
 $sample.birth_filetime=$birth;$sample.image=$image.ToString();$sample.image_sha256=HashText $sample.image
 $sample.handle_count=$count;$sample.session_id=$session
 $cim=@(ProcessRow $target);$sample.cim_count=$cim.Count
 if($cim.Count -eq 1){
  $x=$cim[0];$sample.parent_pid=[uint32]$x.ParentProcessId
  Stage 'CIM.CreationDate.ToFileTimeUtc'
  $sample.cim_birth_filetime=$x.CreationDate.ToUniversalTime().ToFileTimeUtc()
  $sample.cim_image_equal=($sample.image -ieq $x.ExecutablePath)
  $sample.cim_session_equal=($session -eq $x.SessionId)
 }
 Stage 'WaitForSingleObject';Bound;$sample.wait_result=[Task13IdentityNative]::WaitForSingleObject($held.Value,0)
 $sample.status='PRESENT'
 return $sample
}
$rows=@();$parents=@()
try{
 foreach($target in $Ids){
  $script:Stage='FIRST';$script:NativeError=$null;$script:Partial=$null;$failed=$null;$which='first'
  $firstHandle=[IntPtr]::Zero;$secondHandle=[IntPtr]::Zero
  $row=[ordered]@{pid=$target;first=$null;second=$null;retained_first_not_exited=$null;error_type=$null}
  try{
   $row.first=Sample $target ([ref]$firstHandle)
   $which='second';$script:Partial=$null
   $row.second=Sample $target ([ref]$secondHandle)
   if($firstHandle -ne [IntPtr]::Zero){$row.retained_first_not_exited=([Task13IdentityNative]::WaitForSingleObject($firstHandle,0) -eq 258)}
  }catch{
   $row.error_type=$_.Exception.GetType().Name
   $failureStage=$script:Stage;$nativeError=$script:NativeError;$details=ErrorDetails $_
   $firstWait=$null;$secondWait=$null
   if($firstHandle -ne [IntPtr]::Zero){$firstWait=[Task13IdentityNative]::WaitForSingleObject($firstHandle,0)}
   if($secondHandle -ne [IntPtr]::Zero){$secondWait=[Task13IdentityNative]::WaitForSingleObject($secondHandle,0)}
   $failed=@{sample=$which;stage=$failureStage;native_error=$nativeError;elapsed_ms=$timer.ElapsedMilliseconds;partial=$script:Partial;first_wait=$firstWait;second_wait=$secondWait;error_record=$details}
  }
  finally{
   if($firstHandle -ne [IntPtr]::Zero){[void][Task13IdentityNative]::CloseHandle($firstHandle)}
   if($secondHandle -ne [IntPtr]::Zero){[void][Task13IdentityNative]::CloseHandle($secondHandle)}
  }
  $rows+=$row;$diagnostics+=@{pid=$target;failure=$failed;elapsed_ms=$timer.ElapsedMilliseconds}
 }
 foreach($parentId in @($rows|Where-Object {$null -ne $_.first -and $null -ne $_.first.parent_pid}|ForEach-Object {$_.first.parent_pid}|Select-Object -Unique)){
  $entry=[ordered]@{pid=$parentId;status='UNKNOWN';image=$null;birth_filetime=$null;session_id=$null;error_type=$null}
  try{Bound;$parent=@(ProcessRow $parentId);if($parent.Count -eq 0){$entry.status='ABSENT'}elseif($parent.Count -eq 1){$entry.image=$parent[0].ExecutablePath;$entry.birth_filetime=$parent[0].CreationDate.ToUniversalTime().ToFileTimeUtc();$entry.session_id=$parent[0].SessionId;$entry.status='CIM_METADATA'}}catch{$entry.error_type=$_.Exception.GetType().Name}
  $parents+=$entry
 }
 $value=[ordered]@{schema='task13_native_process_identity_v1';status='READ_ONLY_PROCESS_IDENTITY_OBSERVATION';run_id=$RunId.ToString();vm_uuid=$ExpectedVmUuid.ToString();registry_sha256=$RegistrySha256;utc=[DateTime]::UtcNow.ToString('o');rows=$rows;parent_observations=$parents}
 $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
 $context=@{pid=$PID;user_sid=$identity.User.Value;authentication_type=$identity.AuthenticationType;impersonation_level=$identity.ImpersonationLevel.ToString();is_admin=([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);ps_version=$PSVersionTable.PSVersion.ToString();clr_version=$PSVersionTable.CLRVersion.ToString();is_64bit=[Environment]::Is64BitProcess;requested_process_access=0x101000;privileges=@(& "$env:WINDIR\System32\whoami.exe" /priv /fo csv /nh)}
 $value.schema='task13_native_process_identity_v2';$value.diagnostics=$diagnostics;$value.caller_context=$context
 $json=$value|ConvertTo-Json -Compress -Depth 12
 if([Text.Encoding]::UTF8.GetByteCount($json) -gt 49152){throw 'identity output bound'}
 [Console]::Out.WriteLine($json);[Console]::Out.Flush()
}finally{$sha.Dispose()}
