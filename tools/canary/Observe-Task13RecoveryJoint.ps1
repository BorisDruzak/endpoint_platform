param([string]$CurrentSourceBase64,[string]$CurrentSourceSha256,[string]$IdentitySourceBase64,[string]$IdentitySourceSha256,
      [string]$IdentityParametersBase64,[string]$IdentityParametersSha256)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$task13JointUtf8=[Text.UTF8Encoding]::new($false,$true)
function JointHash([byte[]]$bytes){$hash=[Security.Cryptography.SHA256]::Create();try{([BitConverter]::ToString($hash.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()}finally{$hash.Dispose()}}
$task13CurrentBytes=[Convert]::FromBase64String($CurrentSourceBase64)
$task13IdentityBytes=[Convert]::FromBase64String($IdentitySourceBase64)
$task13ParameterBytes=[Convert]::FromBase64String($IdentityParametersBase64)
if((JointHash $task13CurrentBytes) -cne $CurrentSourceSha256 -or (JointHash $task13IdentityBytes) -cne $IdentitySourceSha256 -or (JointHash $task13ParameterBytes) -cne $IdentityParametersSha256){throw 'joint source binding'}
$task13IdentityParameters=$task13JointUtf8.GetString($task13ParameterBytes)|ConvertFrom-Json
if(((@($task13IdentityParameters.PSObject.Properties.Name)|Sort-Object)-join '|') -cne 'ExpectedVmUuid|Ids|RegistrySha256|RunId'){throw 'joint parameter names'}
Add-Type -TypeDefinition @'
using System;using System.Text;using System.IO;using System.Globalization;using System.Management.Automation.Host;using System.Runtime.InteropServices;
public sealed class Task13JointHost : PSHost {
 readonly Guid id=Guid.NewGuid();readonly CultureInfo culture=System.Threading.Thread.CurrentThread.CurrentCulture;
 readonly CultureInfo uiCulture=System.Threading.Thread.CurrentThread.CurrentUICulture;
 public bool ExitRequested;public int? ExitCode;public int ExitCount;
 public override Guid InstanceId {get{return id;}}public override string Name {get{return "Task13RecoveryJointV2";}}
 public override Version Version {get{return new Version(1,0);}}public override PSHostUserInterface UI {get{return null;}}
 public override CultureInfo CurrentCulture {get{return culture;}}public override CultureInfo CurrentUICulture {get{return uiCulture;}}
 public override void SetShouldExit(int code){ExitRequested=true;ExitCode=code;ExitCount++;}
 public override void EnterNestedPrompt(){throw new NotSupportedException();}public override void ExitNestedPrompt(){throw new NotSupportedException();}
 public override void NotifyBeginApplication(){}public override void NotifyEndApplication(){}
}
public sealed class Task13JointWriter : TextWriter {
 readonly StringBuilder text=new StringBuilder();public override Encoding Encoding {get{return new UTF8Encoding(false,true);}}
 public override void Write(char value){if(text.Length>=65536)throw new InvalidOperationException("joint capture bound");text.Append(value);}
 public override void Write(string value){if(value==null)return;if(text.Length+value.Length>65536)throw new InvalidOperationException("joint capture bound");text.Append(value);}
 public override string ToString(){return text.ToString();}
}
public static class Task13JointNative {
 [DllImport("kernel32.dll",SetLastError=true)]public static extern IntPtr OpenProcess(uint access,bool inherit,uint pid);
 [DllImport("kernel32.dll",SetLastError=true)]public static extern bool GetProcessTimes(IntPtr h,out long birth,out long exit,out long kernel,out long user);
 [DllImport("kernel32.dll",SetLastError=true)]public static extern uint GetProcessId(IntPtr h);
 [DllImport("kernel32.dll",SetLastError=true)]public static extern uint WaitForSingleObject(IntPtr h,uint millis);
 [DllImport("kernel32.dll",SetLastError=true)]public static extern bool CloseHandle(IntPtr h);
}
'@
function JointCapture([string]$source,[string]$sourceSha,[hashtable]$parameters){
 $hostCapture=[Task13JointHost]::new();$runspace=$null;$pipeline=$null
 $stdout=[Task13JointWriter]::new();$stderr=[Task13JointWriter]::new()
 $originalOut=[Console]::Out;$originalError=[Console]::Error
 $result=$null;$failure=$null
 try{
  $runspace=[Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace($hostCapture)
  $runspace.ThreadOptions=[Management.Automation.Runspaces.PSThreadOptions]::UseCurrentThread
  $runspace.Open();$pipeline=[PowerShell]::Create();$pipeline.Runspace=$runspace
  [void]$pipeline.AddScript($source)
  foreach($key in $parameters.Keys){[void]$pipeline.AddParameter($key,$parameters[$key])}
  [Console]::SetOut($stdout);[Console]::SetError($stderr)
  try{$result=@($pipeline.Invoke())}catch{$failure=$_.Exception.GetType().FullName;$result=@()}
  $outputs=@();foreach($item in $result){
   if($item -isnot [string]){throw 'joint output type'}
   $bytes=$task13JointUtf8.GetBytes([string]$item);if($bytes.Length -gt 65536 -or $outputs.Count -ge 1){throw 'joint pipeline output bound'}
   $outputs+=([Convert]::ToBase64String($bytes))
  }
  $outBytes=$task13JointUtf8.GetBytes($stdout.ToString());$errBytes=$task13JointUtf8.GetBytes($stderr.ToString())
  if($outBytes.Length -gt 65536 -or $errBytes.Length -gt 65536){throw 'joint console output bound'}
  $counts=@{};foreach($stream in @('Error','Warning','Verbose','Debug','Information','Progress')){$counts[$stream.ToLowerInvariant()]=$pipeline.Streams.$stream.Count}
  return [ordered]@{source_sha256=$sourceSha;pipeline_state=$pipeline.InvocationStateInfo.State.ToString();had_errors=[bool]$pipeline.HadErrors;
   exception_type=$failure;exit_requested=[bool]$hostCapture.ExitRequested;exit_code=$hostCapture.ExitCode;exit_count=$hostCapture.ExitCount;
   console_stdout_b64=[Convert]::ToBase64String($outBytes);console_stderr_b64=[Convert]::ToBase64String($errBytes);
   pipeline_stdout_b64=@($outputs);stream_counts=$counts}
 }finally{
  [Console]::SetOut($originalOut);[Console]::SetError($originalError)
  if($null -ne $pipeline){$pipeline.Dispose()}
  if($null -ne $runspace){$runspace.Close();$runspace.Dispose()}
  $stdout.Dispose();$stderr.Dispose()
 }
}
$task13Observer=[Task13JointNative]::OpenProcess(0x101000,$false,[uint32]$PID)
if($task13Observer -eq [IntPtr]::Zero){throw 'joint observer handle unavailable'}
try{
 [long]$task13Birth=0;[long]$task13Exit=0;[long]$task13Kernel=0;[long]$task13User=0
 if(-not [Task13JointNative]::GetProcessTimes($task13Observer,[ref]$task13Birth,[ref]$task13Exit,[ref]$task13Kernel,[ref]$task13User) -or [Task13JointNative]::GetProcessId($task13Observer) -ne $PID){throw 'joint observer initial identity'}
 $task13Current=JointCapture $task13JointUtf8.GetString($task13CurrentBytes) $CurrentSourceSha256 @{}
 $task13Parameters=@{};foreach($property in $task13IdentityParameters.PSObject.Properties){$task13Parameters[$property.Name]=$property.Value}
 $task13Identity=JointCapture $task13JointUtf8.GetString($task13IdentityBytes) $IdentitySourceSha256 $task13Parameters
 [long]$task13AfterBirth=0
 if(-not [Task13JointNative]::GetProcessTimes($task13Observer,[ref]$task13AfterBirth,[ref]$task13Exit,[ref]$task13Kernel,[ref]$task13User)){throw 'joint observer final identity'}
 $task13Alive=([Task13JointNative]::WaitForSingleObject($task13Observer,0) -eq 258)
 [ordered]@{schema='task13_joint_current_identity_capture_v2';status='JOINT_READONLY_CAPTURED';
  observer=@{pid=$PID;birth_filetime=$task13Birth;after_birth_filetime=$task13AfterBirth;retained_not_exited=$task13Alive};
  current=$task13Current;process_identity=$task13Identity}|ConvertTo-Json -Depth 10 -Compress
}finally{[void][Task13JointNative]::CloseHandle($task13Observer)}
