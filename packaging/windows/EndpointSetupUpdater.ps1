[CmdletBinding()]
param([Parameter(Mandatory)][ValidateSet('Install','Run')][string]$Mode)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$script:ClientVersion='1.0.5'
$script:Publisher='4D4C23389F5FF77BC4EB32044761019EAE8FB776'
$script:Origin='https://endpoint.sosnadmin.local'
$script:ProgramFiles=[Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
$script:ProgramData=[Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
$script:AgentRoot=Join-Path $script:ProgramFiles 'Endpoint Platform\Agent'
$script:AgentData=Join-Path $script:ProgramData 'Endpoint Platform\Agent'
$script:InstallerState=Join-Path $script:ProgramFiles 'Endpoint Platform\installer-state'
$script:ClientRoot=Join-Path $script:ProgramFiles 'EndpointPlatformSetupUpdater'
$script:StateRoot=Join-Path $script:ProgramData 'EndpointPlatformSetupUpdates'
$script:TaskName='EndpointSetupUpdater'

function Assert-System {
 if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne 'S-1-5-18'){throw 'system_required'}
}
function New-ClientMutexSecurity {
 $security=[Security.AccessControl.MutexSecurity]::new();$security.SetAccessRuleProtection($true,$false)
 foreach($sid in @('S-1-5-18','S-1-5-32-544')){
  $security.AddAccessRule([Security.AccessControl.MutexAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','Allow'))
 }
 return $security
}
function Assert-NoReparse([string]$path){
 $full=[IO.Path]::GetFullPath($path);$part=$full
 while($part){if(Test-Path -LiteralPath $part){if((Get-Item -LiteralPath $part -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'unsafe_reparse_path'}};$parent=[IO.Path]::GetDirectoryName($part);if($parent -eq $part){break};$part=$parent}
}
function Assert-AdministrativePath([string]$path){
 Assert-NoReparse $path
 $acl=Get-Acl -LiteralPath $path
 if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -cnotin @('S-1-5-18','S-1-5-32-544')){throw 'unsafe_owner'}
 foreach($ace in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){
  if($ace.AccessControlType -ne 'Allow' -or $ace.IdentityReference.Value -cnotin @('S-1-5-18','S-1-5-32-544')){throw 'unsafe_administrative_acl'}
 }
}
function New-AdministrativeDirectory([string]$path){
 Assert-NoReparse $path
 if(!(Test-Path -LiteralPath $path)){
  $acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetAccessRuleProtection($true,$false)
  foreach($sid in @('S-1-5-18','S-1-5-32-544')){
   $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
  }
  [IO.Directory]::CreateDirectory($path,$acl)|Out-Null
 }
 Assert-AdministrativePath $path
 if(!(Get-Acl -LiteralPath $path).AreAccessRulesProtected){throw 'unprotected_administrative_root'}
}
function Initialize-FileEvidence {
 if('EndpointSetupFileEvidence' -as [type]){return}
 Add-Type -TypeDefinition @"
using System;using System.IO;using System.Runtime.InteropServices;using System.Security.Cryptography;using Microsoft.Win32.SafeHandles;
public static class EndpointSetupFileEvidence {
 [StructLayout(LayoutKind.Sequential)] public struct Info { public uint Attributes;public System.Runtime.InteropServices.ComTypes.FILETIME Creation,Access,Write;public uint Volume,SizeHigh,SizeLow,Links,IndexHigh,IndexLow; }
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern SafeFileHandle CreateFile(string p,uint access,uint share,IntPtr security,uint creation,uint flags,IntPtr template);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandle(SafeFileHandle file,out Info info);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool GetKernelObjectSecurity(SafeFileHandle handle,uint requested,byte[] descriptor,uint length,out uint needed);
 public static string Read(string path){
  if(!path.StartsWith(@"\\?\"))path=@"\\?\"+path;
  using(var file=CreateFile(path,0x80000000,7,IntPtr.Zero,3,0x00200000,IntPtr.Zero)){
   Info before,after;if(file.IsInvalid||!GetFileInformationByHandle(file,out before))throw new IOException("private_open_failed");
   if((before.Attributes&0x410)!=0||before.Links!=1||before.SizeHigh!=0||before.SizeLow>65536)throw new IOException("private_file_unsafe");
   uint required;GetKernelObjectSecurity(file,7,null,0,out required);if(required<20||required>65536)throw new IOException("private_security_unavailable");
   byte[] sd=new byte[required];if(!GetKernelObjectSecurity(file,7,sd,required,out required))throw new IOException("private_security_unavailable");
   using(var stream=new FileStream(file,FileAccess.Read))using(var hash=SHA256.Create()){
    string digest=BitConverter.ToString(hash.ComputeHash(stream)).Replace("-","").ToLowerInvariant();
    if(!GetFileInformationByHandle(file,out after)||before.Volume!=after.Volume||before.IndexLow!=after.IndexLow||before.IndexHigh!=after.IndexHigh||before.Links!=after.Links||before.Attributes!=after.Attributes||before.SizeLow!=after.SizeLow||before.Write.dwLowDateTime!=after.Write.dwLowDateTime||before.Write.dwHighDateTime!=after.Write.dwHighDateTime)throw new IOException("private_file_changed");
    return before.Volume.ToString("X8")+":"+before.IndexHigh.ToString("X8")+before.IndexLow.ToString("X8")+"|"+before.SizeLow.ToString()+"|"+digest+"|"+Convert.ToBase64String(sd);
   }
  }
 }
}
"@
}
function Initialize-SessionIdentity {
 if('EndpointSetupSessionIdentity' -as [type]){return}
 Add-Type -TypeDefinition @"
using System;using System.IO;using System.Runtime.InteropServices;using System.Security.Principal;
public static class EndpointSetupSessionIdentity {
 [StructLayout(LayoutKind.Sequential)] struct Session { public int Id;public IntPtr Station;public int State; }
 [DllImport("wtsapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool WTSQuerySessionInformation(IntPtr server,int session,int kind,out IntPtr buffer,out int bytes);
 [DllImport("wtsapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool WTSEnumerateSessions(IntPtr server,int reserved,int version,out IntPtr buffer,out int count);
 [DllImport("wtsapi32.dll")] static extern void WTSFreeMemory(IntPtr value);
 public static string RequireQuery(bool success,string value){if(!success)throw new IOException("session_identity_lookup_failed");return value;}
 static bool Exists(int id){IntPtr p;int count;if(!WTSEnumerateSessions(IntPtr.Zero,0,1,out p,out count))throw new IOException("session_enumeration_failed");try{int size=Marshal.SizeOf(typeof(Session));for(int i=0;i<count;i++){var item=(Session)Marshal.PtrToStructure(IntPtr.Add(p,i*size),typeof(Session));if(item.Id==id)return true;}return false;}finally{WTSFreeMemory(p);}}
 public static int[] Sessions(){IntPtr p;int count;if(!WTSEnumerateSessions(IntPtr.Zero,0,1,out p,out count))throw new IOException("session_enumeration_failed");try{if(count<0||count>1024)throw new IOException("session_enumeration_invalid");var ids=new System.Collections.Generic.List<int>();int size=Marshal.SizeOf(typeof(Session));for(int i=0;i<count;i++){var item=(Session)Marshal.PtrToStructure(IntPtr.Add(p,i*size),typeof(Session));if(item.Id>0)ids.Add(item.Id);}return ids.ToArray();}finally{WTSFreeMemory(p);}}
 static string Text(int session,int kind){IntPtr p;int bytes;bool ok=WTSQuerySessionInformation(IntPtr.Zero,session,kind,out p,out bytes);if(!ok)return RequireQuery(false,null);try{return RequireQuery(true,bytes<2?String.Empty:Marshal.PtrToStringUni(p));}finally{WTSFreeMemory(p);}}
 public static string Sid(int session){if(!Exists(session))return null;string user=Text(session,5),domain=Text(session,7);if(String.IsNullOrEmpty(user))return null;return ((SecurityIdentifier)new NTAccount(domain,user).Translate(typeof(SecurityIdentifier))).Value;}
}
"@
}
function Assert-PrivateLeaf([string]$path){
 Assert-NoReparse $path
 $a=Get-Acl -LiteralPath $path
 if($a.GetOwner([Security.Principal.SecurityIdentifier]).Value -cnotin @('S-1-5-18','S-1-5-32-544')){throw 'private_owner_unsafe'}
 $agent='S-1-5-80-1102781572-1373263041-1070489469-7526906-1468061691';$updater='S-1-5-80-327494974-20047353-929432329-1920152597-707704661'
 $name=[IO.Path]::GetFileName($path);$readonly=$name -cin @('device-credential','endpoint-ca.crt')
 $originProtected=($name -ceq 'endpoint-origin' -and $a.AreAccessRulesProtected -and !@($a.Access|Where-Object IsInherited).Count)
 $expected=@{'S-1-5-18'=0x1f01ff;'S-1-5-32-544'=0x1f01ff};$expected[$agent]=$(if($readonly -or $originProtected){0x120089}else{0x13019f});$expected[$updater]=$(if($readonly -or $originProtected){0x120116}else{0x13019f})
 $seen=@{};foreach($ace in $a.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){
  $sid=$ace.IdentityReference.Value;$rights=[int]$ace.FileSystemRights
  if($seen.ContainsKey($sid) -or !$expected.ContainsKey($sid) -or $ace.AccessControlType -ne 'Allow' -or ($rights -ne $expected[$sid] -and !(!$readonly -and !$originProtected -and $sid -ceq $updater -and $rights -eq 0x130116))){throw 'private_acl_unsafe'}
  $seen[$sid]=$true
 }
 if($seen.Count -ne 4){throw 'private_acl_unsafe'}
 if($readonly -and (!$a.AreAccessRulesProtected -or @($a.Access|Where-Object IsInherited).Count)){throw 'private_readonly_acl_unsafe'}
}
function Get-PrivateSnapshot {
 Initialize-FileEvidence
 $rows=[ordered]@{}
 foreach($name in @('device-credential','enrollment-identity.json','endpoint-origin','endpoint-ca.crt')){
  $path=Join-Path $script:AgentData $name
  if($name -ceq 'endpoint-origin' -and !(Test-Path -LiteralPath $path)){$rows[$name]=$null;continue}
  Assert-PrivateLeaf $path;$rows[$name]=[EndpointSetupFileEvidence]::Read($path)
 }
 return $rows
}
function Compare-PrivateSnapshot($before,$after){
 return [ordered]@{credential=($before.'device-credential' -ceq $after.'device-credential');identity=($before.'enrollment-identity.json' -ceq $after.'enrollment-identity.json');origin=($before.'endpoint-origin' -ceq $after.'endpoint-origin');ca=($before.'endpoint-ca.crt' -ceq $after.'endpoint-ca.crt')}
}
function Read-BoundedJson([string]$path,[int]$maximum=262144){
 Assert-NoReparse $path
 if(!(Test-Path -LiteralPath $path)){return $null}
 if((Get-Item -LiteralPath $path).Length -gt $maximum){throw 'local_json_too_large'}
 return Get-Content -Raw -LiteralPath $path|ConvertFrom-Json
}
function Write-PrivateJson([string]$path,$value){
 Assert-NoReparse $path;Assert-AdministrativePath ([IO.Path]::GetDirectoryName($path))
 $temporary=$path+'.'+[guid]::NewGuid().ToString('N')+'.tmp';$bytes=[Text.Encoding]::UTF8.GetBytes(($value|ConvertTo-Json -Depth 24))
 $f=[IO.File]::Open($temporary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
 try{$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()}
 if(Test-Path -LiteralPath $path){Assert-AdministrativePath $path;[IO.File]::Replace($temporary,$path,[NullString]::Value)}else{[IO.File]::Move($temporary,$path)}
}
function Assert-SignedFile([string]$path,[string]$sha){
 Assert-NoReparse $path
 if($sha -and (Get-FileHash -LiteralPath $path).Hash -ine $sha){throw 'artifact_hash_mismatch'}
 $signature=Get-AuthenticodeSignature -LiteralPath $path
 if($signature.Status -ne 'Valid' -or !$signature.TimeStamperCertificate -or $signature.SignerCertificate.Thumbprint -cne $script:Publisher){throw 'artifact_signature_invalid'}
}
function Install-SetupClient {
 Assert-System;Assert-SignedFile $PSCommandPath $null
 $null=New-ClientMutexSecurity
 $pending=Read-BoundedJson (Join-Path $script:AgentData 'updates\pending_update.json') 16384
 if(!$pending -or $pending.version -cnotmatch '^3\.2\.[0-9]+$' -or [version]$pending.version -lt [version]'3.2.159' -or $pending.archive_type -cne 'zip'){throw 'bootstrap_assignment_required'}
 New-AdministrativeDirectory $script:ClientRoot;New-AdministrativeDirectory $script:StateRoot
 $versionRoot=Join-Path $script:ClientRoot $script:ClientVersion;New-AdministrativeDirectory $versionRoot
 $target=Join-Path $versionRoot 'EndpointSetupUpdater.ps1'
 $pin=[IO.File]::Open($PSCommandPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
 try{
  $sha=(Get-FileHash -LiteralPath $PSCommandPath).Hash;Assert-SignedFile $PSCommandPath $sha
  if(Test-Path -LiteralPath $target){Assert-AdministrativePath $target;Assert-SignedFile $target $sha}else{
   $output=[IO.File]::Open($target,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
   try{$pin.CopyTo($output);$output.Flush($true)}finally{$output.Dispose()}
   Assert-SignedFile $target $sha
  }
 }finally{$pin.Dispose()}
 $powershell=Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::System)) 'WindowsPowerShell\v1.0\powershell.exe'
 $action=New-ScheduledTaskAction -Execute $powershell -Argument ('-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy AllSigned -File "'+$target+'" -Mode Run')
 $trigger=New-ScheduledTaskTrigger -Once -At ([DateTime]::Now.AddSeconds(15)) -RepetitionInterval ([TimeSpan]::FromMinutes(1))
 $logon=New-ScheduledTaskTrigger -AtLogOn
 $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
 $principal=New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest
 Register-ScheduledTask -TaskName $script:TaskName -Action $action -Trigger @($trigger,$logon) -Settings $settings -Principal $principal -Description 'Endpoint Platform authenticated full Setup updates and user-session continuity' -Force|Out-Null
 $scheduler=New-Object -ComObject Schedule.Service;$scheduler.Connect();$scheduler.GetFolder('\').GetTask($script:TaskName).SetSecurityDescriptor('D:P(A;;FA;;;SY)(A;;FA;;;BA)',0)
 Write-PrivateJson (Join-Path $script:StateRoot 'client.json') @{client_version=$script:ClientVersion;script_sha256=$sha;installed_at=[DateTime]::UtcNow.ToString('o')}
}
function Assert-FullSetupSource($p,$release){
 if($p.schema_version -cne 'endpoint_windows_fleet_preflight_v1' -or $p.target_version -cne $release.version -or $p.eligibility -cnotin @('READY_FOR_SETUP_UPGRADE','ALREADY_CURRENT')){throw 'setup_source_not_supported'}
 foreach($value in @($p.foundation.native_verified,$p.core.verified,$p.provenance.verified,$p.services.EndpointAgent.identity_valid,$p.services.EndpointAgentUpdater.identity_valid)){if($value -isnot [bool] -or !$value){throw 'setup_source_unverified'}}
 foreach($value in @($p.pending.active_or_degraded,$p.provenance.conflict)){if($value -isnot [bool] -or $value){throw 'setup_source_recovery_active'}}
 foreach($part in @($p.foundation,$p.core)){
  if($part.version -cnotmatch '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' -or [version]$part.version -gt [version]$release.version){throw 'setup_source_newer_than_target'}
 }
 if($p.services.EndpointAgent.state -cne 'running'){throw 'setup_agent_not_running'}
 if($p.eligibility -ceq 'READY_FOR_SETUP_UPGRADE' -and ($p.disk.sufficient -isnot [bool] -or !$p.disk.sufficient)){throw 'setup_disk_not_ready'}
 if($p.eligibility -ceq 'ALREADY_CURRENT'){
  foreach($part in @($p.foundation,$p.core)){if($part.version -cne $release.version -or $part.source_revision -cne $release.source_revision -or $part.package_sha256 -cne $release.msi_sha256){throw 'setup_current_binding_differs'}}
  if($p.core.origin -cne 'msi'){throw 'setup_current_binding_differs'}
 }
 return $p.eligibility
}

function Initialize-EndpointClient {
 foreach($name in @('device-credential','enrollment-identity.json','endpoint-ca.crt')){Assert-PrivateLeaf (Join-Path $script:AgentData $name)}
 $identity=Read-BoundedJson (Join-Path $script:AgentData 'enrollment-identity.json') 65536
 $script:DeviceId=[guid]::ParseExact([string]$identity.device_id,'D').ToString()
 if($script:DeviceId -cne [string]$identity.device_id -or $script:DeviceId -ceq [guid]::Empty.ToString()){throw 'device_identity_invalid'}
 $originPath=Join-Path $script:AgentData 'endpoint-origin'
 if(Test-Path -LiteralPath $originPath){Assert-PrivateLeaf $originPath;if([IO.File]::ReadAllText($originPath).Trim() -cne $script:Origin){throw 'endpoint_origin_differs'}}
 if([Net.ServicePointManager]::SecurityProtocol -ne [Net.SecurityProtocolType]::SystemDefault -or $null -ne [Net.ServicePointManager]::ServerCertificateValidationCallback){throw 'default_os_tls_required'}
 $raw=[IO.File]::ReadAllBytes((Join-Path $script:AgentData 'device-credential'))
 try{$script:Credential=[Text.Encoding]::ASCII.GetString($raw).TrimEnd([char[]]"`r`n");if($script:Credential -cnotmatch '^[A-Za-z0-9_-]{43}$'){throw 'device_credential_invalid'}}finally{[Array]::Clear($raw,0,$raw.Length)}
 Add-Type -AssemblyName System.Net.Http
 $handler=[Net.Http.HttpClientHandler]::new();$handler.AllowAutoRedirect=$false;$handler.UseProxy=$false;$handler.UseCookies=$false;$handler.UseDefaultCredentials=$false
 $script:Http=[Net.Http.HttpClient]::new($handler);$script:Http.Timeout=[TimeSpan]::FromSeconds(30);$script:Http.MaxResponseContentBufferSize=65536
}
function New-EndpointRequest([string]$method,[string]$path,$body){
 if($path -cnotmatch '^/agent/v1/setup-updates/(hello|recommendation|assignments/[0-9a-f-]{36}/(artifact|progress|status))$'){throw 'api_path_invalid'}
 $request=[Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::new($method),[uri]($script:Origin+$path))
 $request.Headers.Authorization=[Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer',$script:Credential)
 if($null -ne $body){$request.Content=[Net.Http.StringContent]::new(($body|ConvertTo-Json -Depth 18 -Compress),[Text.Encoding]::UTF8,'application/json')}
 return $request
}
function Read-BoundedResponse($response,[int]$maximum=65536){
 if($response.Content.Headers.ContentLength -gt $maximum){throw 'api_response_too_large'}
 $stream=$response.Content.ReadAsStreamAsync().GetAwaiter().GetResult();$buffer=New-Object byte[] 4096;$output=[IO.MemoryStream]::new()
 try{
  while($true){$read=$stream.ReadAsync($buffer,0,$buffer.Length);if(!$read.Wait(15000)){throw 'api_read_timeout'};$count=$read.Result;if(!$count){break};if($output.Length+$count -gt $maximum){throw 'api_response_too_large'};$output.Write($buffer,0,$count)}
  if(!$output.Length){return $null};return [Text.Encoding]::UTF8.GetString($output.ToArray())|ConvertFrom-Json
 }finally{$output.Dispose();$stream.Dispose()}
}
function Invoke-EndpointJson([string]$method,[string]$path,$body=$null){
 $request=New-EndpointRequest $method $path $body;$response=$null
 try{
  $response=$script:Http.SendAsync($request,[Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
  if([int]$response.StatusCode -eq 204){return $null}
  if(!$response.IsSuccessStatusCode){throw ('api_status_'+[int]$response.StatusCode)}
  return Read-BoundedResponse $response
 }finally{if($response){$response.Dispose()};$request.Headers.Authorization=$null;$request.Dispose()}
}
function Assert-SetupRecommendation($value){
 if($value.schema_version -cne 'windows_setup_recommendation_v1' -or $value.device_id -cne $script:DeviceId){throw 'assignment_identity_invalid'}
 $id=[guid]::ParseExact([string]$value.assignment_id,'D').ToString();if($id -cne $value.assignment_id -or $id -ceq [guid]::Empty.ToString()){throw 'assignment_identity_invalid'}
 $r=$value.release
 if($r.schema_version -cne 'windows_setup_release_v1' -or $r.version -cnotmatch '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' -or $r.artifact_name -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,251}\.exe$' -or $r.size -is [bool] -or $r.size -le 0 -or $r.size -gt 536870912){throw 'setup_release_invalid'}
 foreach($key in @('sha256','msi_sha256','tray_sha256','sensor_sha256')){if($r.$key -cnotmatch '^[0-9a-f]{64}$'){throw 'setup_release_invalid'}}
 if($r.source_revision -cnotmatch '^[0-9a-f]{40}$'){throw 'setup_release_invalid'}
 return $id
}
function Get-JobRoot([string]$assignment){
 if($assignment -cnotmatch '^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$'){throw 'job_identity_invalid'}
 return Join-Path (Join-Path $script:StateRoot 'jobs') $assignment
}
function Save-Job($job){Write-PrivateJson (Join-Path (Get-JobRoot $job.assignment_id) 'job.json') $job}
function Send-Progress($job,[string]$phase,$proof=$null,[string]$safeCode=$null){
 $payload=[ordered]@{attempt_id=$job.attempt_id;phase=$phase;safe_code=$safeCode;proof=$proof}
 $job.report=$payload;Save-Job $job
 $response=Invoke-EndpointJson 'POST' ('/agent/v1/setup-updates/assignments/'+$job.assignment_id+'/progress') $payload
 if($response.assignment_id -cne $job.assignment_id -or $response.attempt_id -cne $job.attempt_id -or $response.phase -cne $phase){throw 'progress_ack_differs'}
 $job.phase=$phase;$job.report=$null;Save-Job $job
}
function Get-SetupArtifact($job,[string]$destination){
 if(Test-Path -LiteralPath $destination){Assert-AdministrativePath $destination;if((Get-Item -LiteralPath $destination).Length -eq $job.release.size -and (Get-FileHash -LiteralPath $destination).Hash -ieq $job.release.sha256){return};throw 'cached_artifact_differs'}
 $partial=$destination+'.partial';Assert-NoReparse $partial
 if(Test-Path -LiteralPath $partial){Assert-AdministrativePath $partial;Remove-Item -LiteralPath $partial}
 $request=New-EndpointRequest 'GET' ('/agent/v1/setup-updates/assignments/'+$job.assignment_id+'/artifact') $null;$response=$null;$stream=$null;$output=$null
 try{
  $response=$script:Http.SendAsync($request,[Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
  if(!$response.IsSuccessStatusCode){throw ('api_status_'+[int]$response.StatusCode)}
  if($response.Content.Headers.ContentLength -ne $job.release.size){throw 'artifact_size_differs'}
  $stream=$response.Content.ReadAsStreamAsync().GetAwaiter().GetResult();$output=[IO.File]::Open($partial,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
  $buffer=New-Object byte[] 65536;$received=[long]0
  while($true){$read=$stream.ReadAsync($buffer,0,$buffer.Length);if(!$read.Wait(30000)){throw 'artifact_read_timeout'};$count=$read.Result;if(!$count){break};$received+=$count;if($received -gt $job.release.size){throw 'artifact_size_differs'};$output.Write($buffer,0,$count)}
  $output.Flush($true);$output.Dispose();$output=$null
  if($received -ne $job.release.size -or (Get-FileHash -LiteralPath $partial).Hash -ine $job.release.sha256){throw 'artifact_integrity_failed'}
  [IO.File]::Move($partial,$destination)
 }finally{if($output){$output.Dispose()};if($stream){$stream.Dispose()};if($response){$response.Dispose()};$request.Headers.Authorization=$null;$request.Dispose()}
}
function Read-SetupPreflight([string]$setup){
 $info=[Diagnostics.ProcessStartInfo]::new();$info.FileName=$setup;$info.Arguments='--preflight --quiet';$info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
 $process=[Diagnostics.Process]::Start($info);$handle=$process.Handle;$stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
 if(!$process.WaitForExit(180000)){throw 'preflight_observation_expired'}
 $exit=$process.ExitCode;$out=$stdout.Result;$err=$stderr.Result;$process.Dispose()
 if($exit -ne 0 -or $out.Length -gt 32768 -or $err.Length){throw 'preflight_unavailable'}
 return $out|ConvertFrom-Json
}
function Get-LoggedOnUserSessions {
 Initialize-SessionIdentity
 $rows=@()
 foreach($id in [EndpointSetupSessionIdentity]::Sessions()){
  $sid=Get-LiveSessionSid ([int]$id)
  if($sid -and $sid -cmatch '^S-1-5-21-[0-9-]+$'){$rows+=@{session=[int]$id;sid=$sid}}
 }
 return $rows
}
function Get-CompanionSessions {
 $rows=@();$seen=@{}
 foreach($process in @(Get-CimInstance Win32_Process -Filter "Name='EndpointAgentTray.exe' OR Name='EndpointUserSensor.exe'")){
  if($process.SessionId -le 0 -or $process.ExecutablePath -ine (Join-Path $script:AgentRoot $process.Name)){continue}
  $owner=Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid
  if($owner.ReturnValue -ne 0 -or $owner.Sid -cnotmatch '^S-1-5-21-[0-9-]+$'){throw 'companion_identity_unavailable'}
  $key=[string]$process.SessionId+'|'+$owner.Sid+'|'+$process.Name
  if(!$seen.ContainsKey($key)){$rows+=@{session=[int]$process.SessionId;sid=$owner.Sid;name=$process.Name;sha256=(Get-FileHash -LiteralPath $process.ExecutablePath).Hash.ToLowerInvariant()};$seen[$key]=$true}
 }
 # A SYSTEM installation has no user token and may leave both companions absent
 # in an existing ordinary session. Plan the installed pair even in that case.
 foreach($session in @(Get-LoggedOnUserSessions)){
  if($session.session -le 0 -or $session.sid -cnotmatch '^S-1-5-21-[0-9-]+$'){continue}
  if((Get-LiveSessionSid ([int]$session.session)) -cne $session.sid){continue}
  foreach($name in @('EndpointAgentTray.exe','EndpointUserSensor.exe')){
   $key=[string]$session.session+'|'+$session.sid+'|'+$name
   if(!$seen.ContainsKey($key)){
    $file=Join-Path $script:AgentRoot $name;Assert-NoReparse $file
    $rows+=@{session=[int]$session.session;sid=$session.sid;name=$name;sha256=(Get-FileHash -LiteralPath $file).Hash.ToLowerInvariant()};$seen[$key]=$true
   }
  }
 }
 return $rows
}
function Get-LiveSessionSid([int]$session){Initialize-SessionIdentity;return [EndpointSetupSessionIdentity]::Sid($session)}
function Get-CompanionExpectedHash($job,$session){
 if($session.name -cnotin @('EndpointAgentTray.exe','EndpointUserSensor.exe')){throw 'companion_record_invalid'}
 $hash=if($null -ne $job.native_exit -and $job.native_exit -ne 0){$session.sha256}elseif($session.name -ceq 'EndpointAgentTray.exe'){$job.release.tray_sha256}else{$job.release.sensor_sha256}
 if($hash -cnotmatch '^[0-9a-f]{64}$'){throw 'companion_binding_unavailable'}
 return $hash
}
function Get-CompanionEvidence($job){
 $evidence=@()
 foreach($session in @($job.companions)){
  if((Get-LiveSessionSid ([int]$session.session)) -cne $session.sid){continue}
  $file=Join-Path $script:AgentRoot $session.name
  $processes=@(Get-CimInstance Win32_Process -Filter ("Name='"+$session.name+"'")|Where-Object {$_.SessionId -eq $session.session -and $_.ExecutablePath -ieq $file})
  if($processes.Count -lt 1 -or $processes.Count -gt 2 -or ($session.name -ceq 'EndpointUserSensor.exe' -and $processes.Count -ne 1)){throw 'companion_liveness_failed'}
  if($processes.Count -eq 2 -and @($processes|Where-Object {$processes.ProcessId -contains $_.ParentProcessId}).Count -ne 1){throw 'companion_process_tree_invalid'}
  foreach($process in $processes){
   $owner=Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid
   if($owner.ReturnValue -ne 0 -or $owner.Sid -cne $session.sid -or $process.ExecutablePath -ine $file){throw 'companion_user_differs'}
   $evidence+=@{name=$session.name;session=[int]$session.session;sid=$session.sid;pid=$process.ProcessId;created=$process.CreationDate.ToUniversalTime().ToString('o')}
  }
 }
 return @($evidence|Sort-Object session,name,pid)
}
function Restore-Companions($job,[int]$BudgetSeconds=0){
 Initialize-SessionIdentity
 $clock=[Diagnostics.Stopwatch]::StartNew()
 $scheduler=$null;$owned=@()
 try{
  foreach($session in @($job.companions)){
   if($BudgetSeconds -gt 0 -and $clock.Elapsed.TotalSeconds -ge $BudgetSeconds){return $false}
   if($session.name -cnotin @('EndpointAgentTray.exe','EndpointUserSensor.exe') -or $session.session -le 0 -or $session.sid -cnotmatch '^S-1-5-21-[0-9-]+$'){throw 'companion_record_invalid'}
   $liveSid=Get-LiveSessionSid ([int]$session.session)
   if(!$liveSid -or $liveSid -cne $session.sid){continue}
   $file=Join-Path $script:AgentRoot $session.name;Assert-NoReparse $file
   $expected=Get-CompanionExpectedHash $job $session
   if((Get-FileHash -LiteralPath $file).Hash -ine $expected){throw 'companion_payload_differs'}
   $processes=@(Get-CimInstance Win32_Process -Filter ("Name='"+$session.name+"'")|Where-Object {$_.SessionId -eq $session.session -and $_.ExecutablePath -ieq $file})
   if(!$processes.Count){
    $name='EndpointSetupCompanion-'+$job.assignment_id.Replace('-','')+'-'+$session.session+'-'+$session.name.Replace('.exe','')
    $existing=Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
    if($existing){throw 'companion_prior_launch_unsettled'}
    $action=New-ScheduledTaskAction -Execute $file -WorkingDirectory $script:AgentRoot
    $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    $principal=New-ScheduledTaskPrincipal -UserId $session.sid -LogonType Interactive -RunLevel Limited
    Register-ScheduledTask -TaskName $name -Action $action -Settings $settings -Principal $principal -Description 'Endpoint full Setup user-session continuation'|Out-Null;$owned+=$name
    if(!$scheduler){$scheduler=New-Object -ComObject Schedule.Service;$scheduler.Connect()}
    $task=$scheduler.GetFolder('\').GetTask($name);$task.SetSecurityDescriptor('D:P(A;;FA;;;SY)(A;;FA;;;BA)',0)
    $null=$task.RunEx($null,12,[int]$session.session,[string]$session.sid)
    Start-Sleep -Seconds 8
    $processes=@(Get-CimInstance Win32_Process -Filter ("Name='"+$session.name+"'")|Where-Object {$_.SessionId -eq $session.session -and $_.ExecutablePath -ieq $file})
   }
   if($processes.Count -lt 1 -or $processes.Count -gt 2 -or ($session.name -ceq 'EndpointUserSensor.exe' -and $processes.Count -ne 1)){throw 'companion_launch_not_verified'}
   if($processes.Count -eq 2 -and @($processes|Where-Object {$processes.ProcessId -contains $_.ParentProcessId}).Count -ne 1){throw 'companion_process_tree_invalid'}
   foreach($process in $processes){
    $owner=Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid
    if($process.ExecutablePath -ine $file -or $owner.ReturnValue -ne 0 -or $owner.Sid -cne $session.sid){throw 'companion_user_differs'}
   }
  }
  return $true
 }finally{
  foreach($name in $owned){Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue}
 }
}
function Enter-CompanionExclusion {
 # Same kernel object, protected ACL and service rights as update_transaction.py.
 # This maintenance path never starts MSI and never clears an abandoned fence.
 $expected=@{'S-1-5-18'=0x1f0001;'S-1-5-32-544'=0x1f0001;'S-1-5-80-1102781572-1373263041-1070489469-7526906-1468061691'=0x120001;'S-1-5-80-327494974-20047353-929432329-1920152597-707704661'=0x120001;'S-1-3-4'=0x20000}
 $security=[Security.AccessControl.MutexSecurity]::new();$security.SetAccessRuleProtection($true,$false)
 foreach($sid in $expected.Keys){$security.AddAccessRule([Security.AccessControl.MutexAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),[Security.AccessControl.MutexRights]$expected[$sid],'Allow'))}
 [bool]$created=$false;$mutex=[Threading.Mutex]::new($false,'Global\EndpointPlatform.Agent.UpdateTransaction',[ref]$created,$security)
 try{
  $acl=$mutex.GetAccessControl()
  if(!$acl.AreAccessRulesProtected -or $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -cnotin @('S-1-5-18','S-1-5-32-544','S-1-5-19','S-1-5-80-1102781572-1373263041-1070489469-7526906-1468061691','S-1-5-80-327494974-20047353-929432329-1920152597-707704661')){throw 'companion_exclusion_unsafe'}
  $seen=@{};foreach($ace in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){
   $sid=$ace.IdentityReference.Value
   if($seen.ContainsKey($sid) -or !$expected.ContainsKey($sid) -or $ace.AccessControlType -ne 'Allow' -or [int]$ace.MutexRights -ne $expected[$sid]){throw 'companion_exclusion_unsafe'};$seen[$sid]=$true
  }
  if($seen.Count -ne $expected.Count){throw 'companion_exclusion_unsafe'}
  $held=$false;try{$held=$mutex.WaitOne(0)}catch [Threading.AbandonedMutexException]{$held=$true}
  if(!$held){$mutex.Dispose();return $null}
  return $mutex
 }catch{$mutex.Dispose();throw}
}
function Exit-CompanionExclusion($lease){if($lease){try{$lease.ReleaseMutex()}finally{$lease.Dispose()}}}
function Invoke-CompanionMaintenance($job){
 try{Maintain-UserCompanions $job;return $true}catch{
  # User-session maintenance must not starve authenticated hello/assignments.
  try{Save-ClientStatus 'user_companion_unavailable' $job}catch{}
  return $false
 }
}
function Maintain-UserCompanions($job){
 if(!$job -or $job.phase -cne 'applied' -or $job.native_exit -ne 0 -or !$job.soak -or
  $job.soak.duration_seconds -lt 180 -or $job.soak.samples -lt 6 -or
  !$job.soak.services_stable -or !$job.soak.companions_stable -or !$job.soak.connected){return}
 if(Test-CoreOrNativeBusy){return}
 $lease=Enter-CompanionExclusion
 if(!$lease){return}
 try{
 if(Test-CoreOrNativeBusy){return}
 $service=Get-Service -Name EndpointAgent -ErrorAction SilentlyContinue
 if(!$service -or $service.Status -ne 'Running'){return}
 $selector=Read-BoundedJson (Join-Path $script:AgentRoot 'current.json') 4096
 $native=Read-BoundedJson (Join-Path $script:InstallerState 'foundation.json') 16384
 if(!$selector -or !$native -or $native.schema_version -ne 1){return}
 foreach($part in @($selector,$native.release)){
  if($part.version -cne $job.release.version -or $part.source_revision -cne $job.release.source_revision){return}
 }
 if($native.release.package_sha256 -cne $job.release.msi_sha256){return}
 # Persist/revalidate logged-on identities before launching, including a new
 # logon after native acceptance. Do not reopen or replay the native operation.
 $job.companions=@(Get-CompanionSessions);Save-Job $job
 if(Test-CoreOrNativeBusy){return}
 $restored=Restore-Companions $job -BudgetSeconds 10
 if(!$restored){throw 'user_companion_waiting'}
 }finally{Exit-CompanionExclusion $lease}
}
function Test-CoreOrNativeBusy {
 if(Test-Path -LiteralPath (Join-Path $script:AgentData 'updates\pending_update.json')){return $true}
 if(Test-Path -LiteralPath (Join-Path $script:InstallerState 'transaction.json')){return $true}
 $journal=Read-BoundedJson (Join-Path $script:InstallerState 'staged-update.json')
 if($journal -and $journal.phase -cnotin @('accepted','rolled-back')){return $true}
 return $false
}
function Get-ClientHello {
 $service=Get-Service -Name EndpointAgent -ErrorAction SilentlyContinue
 $selector=Read-BoundedJson (Join-Path $script:AgentRoot 'current.json') 4096
 $core=$null;if($selector.version -cmatch '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'){$core=[string]$selector.version}
 $native=Read-BoundedJson (Join-Path $script:InstallerState 'foundation.json') 16384
 $foundation=$null;if($native.schema_version -eq 1 -and $native.release.version -cmatch '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'){$foundation=[string]$native.release.version}
 $ready=($null -ne $service -and $service.Status -eq 'Running' -and $null -ne $core -and !(Test-CoreOrNativeBusy))
 return [ordered]@{client_version=$script:ClientVersion;core_version=$core;foundation_version=$foundation;ready=$ready;safe_code=$(if($ready){$null}else{'client_waiting_for_agent'})}
}
function New-NativeProof($job,$preflight,[string]$outcome,$exitCode,[bool]$companions){
 $private=Compare-PrivateSnapshot $job.private_before (Get-PrivateSnapshot)
 $services=$true
 foreach($v in @($preflight.services.EndpointAgent.identity_valid,$preflight.services.EndpointAgentUpdater.identity_valid)){if($v -isnot [bool] -or !$v){$services=$false}}
 if($preflight.services.EndpointAgent.state -cne 'running' -or $preflight.services.EndpointAgent.start_mode -cne 'automatic' -or $preflight.services.EndpointAgentUpdater.start_mode -cne 'manual'){$services=$false}
 $browser=Get-CimInstance Win32_Service -Filter "Name='EndpointBrowserPolicy'"
 if(!$browser -or $browser.State -cne 'Running' -or $browser.StartName -cne 'LocalSystem'){$services=$false}
 return [ordered]@{foundation_version=$preflight.foundation.version;core_version=$preflight.core.version;source_revision=$preflight.foundation.source_revision;msi_sha256=$preflight.foundation.package_sha256;native_phase=$outcome;exit_code=$exitCode;native_verified=[bool]$preflight.foundation.native_verified;core_verified=[bool]$preflight.core.verified;provenance_verified=([bool]$preflight.provenance.verified -and !$preflight.provenance.conflict);pending=[bool]$preflight.pending.active_or_degraded;services_verified=$services;companions_restored=$companions;private=$private}
}
function Test-NativeProofHealthy($proof){
 foreach($value in @($proof.native_verified,$proof.core_verified,$proof.provenance_verified,$proof.services_verified,$proof.companions_restored,$proof.private.credential,$proof.private.identity,$proof.private.origin,$proof.private.ca)){
  if($value -isnot [bool] -or !$value){return $false}
 }
 return ($proof.pending -is [bool] -and !$proof.pending)
}
function Invoke-NativeSetup($job,[string]$setup){
 $marker=Join-Path (Get-JobRoot $job.assignment_id) 'native-started.json'
 $bytes=[Text.Encoding]::UTF8.GetBytes((@{assignment_id=$job.assignment_id;attempt_id=$job.attempt_id;sha256=$job.release.sha256;utc=[DateTime]::UtcNow.ToString('o')}|ConvertTo-Json -Compress))
 $f=[IO.File]::Open($marker,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);try{$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()}
 $job.native_started=$true;$job.started_at=[DateTime]::UtcNow.ToString('o');Save-Job $job
 $info=[Diagnostics.ProcessStartInfo]::new();$info.FileName=$setup;$info.Arguments='--quiet';$info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
 $process=[Diagnostics.Process]::Start($info);$handle=$process.Handle;$stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
 $job.native_pid=$process.Id;$job.native_created=$process.StartTime.ToUniversalTime().ToString('o');Save-Job $job
 $clock=[Diagnostics.Stopwatch]::StartNew()
 while(!$process.WaitForExit(1000)){
  if($clock.Elapsed.TotalMinutes -gt 40 -and !$job.observation_expired){
   $job.observation_expired=$true;Save-Job $job
   try{Send-Progress $job 'recovery_required' $null 'native_still_running_after_observation_bound'}catch{}
  }
  $journal=Read-BoundedJson (Join-Path $script:InstallerState 'staged-update.json')
  if($journal -and $journal.binding.operation_id -cne $job.previous_native_id -and $journal.binding.new_release.package_sha256 -ceq $job.release.msi_sha256 -and $journal.phase -cne $job.native_stage){
   $job.native_stage=$journal.phase;Save-Job $job
   $phase=if($job.observation_expired -or $job.phase -ceq 'recovery_required'){'recovery_required'}else{'installing'}
   try{Send-Progress $job $phase $null ('native_'+$journal.phase.Replace('-','_'))}catch{}
  }
 }
 $job.native_exit=[int]$process.ExitCode;$job.native_ended=[DateTime]::UtcNow.ToString('o');$process.Dispose();Save-Job $job
}
function Complete-NativeJob($job,[string]$setup){
 if($job.native_exit -ne 0 -and $job.native_exit -ne 67){
  # Only a known provenance rejection can be settled by proving that its exact
  # source survived. Unknown exits and interrupted native journals stay held.
  if($job.native_exit -ne 21 -or (Test-CoreOrNativeBusy)){Send-Progress $job 'recovery_required' $null 'native_exit_requires_recovery';return}
  if($job.phase -cne 'recovery_required'){Send-Progress $job 'recovery_required' $null 'native_exit_requires_recovery'}
  $after=Read-SetupPreflight $setup
  foreach($part in @('foundation','core')){
   foreach($field in @('version','source_revision')){
    if(!$job.before.$part.$field -or $after.$part.$field -cne $job.before.$part.$field){Send-Progress $job 'recovery_required' $null 'native_exit_requires_recovery';return}
   }
  }
  if($job.before.core.package_sha256 -cnotmatch '^[0-9a-f]{64}$' -or $after.core.package_sha256 -cne $job.before.core.package_sha256 -or $after.foundation.package_sha256 -cne $job.before.foundation.package_sha256 -or $after.core.origin -cne $job.before.core.origin -or $after.pending.active_or_degraded){Send-Progress $job 'recovery_required' $null 'native_exit_requires_recovery';return}
  $journal=Read-BoundedJson (Join-Path $script:InstallerState 'staged-update.json')
  $observed=$(if($journal){$journal.binding.operation_id}else{$null})
  if($observed -cne $job.previous_native_id){Send-Progress $job 'recovery_required' $null 'native_exit_requires_recovery';return}
  $restored=Restore-Companions $job
  $proof=New-NativeProof $job $after 'unchanged' 21 $restored
  $proof.soak=Observe-InstalledRuntime $job $job.before.core.version
  if(!(Test-NativeProofHealthy $proof) -or !$proof.soak.services_stable -or !$proof.soak.connected -or !$proof.soak.companions_stable){Send-Progress $job 'recovery_required' $proof 'native_exit_requires_recovery';return}
  Send-Progress $job 'failed' $proof 'native_failed_source_verified';return
 }
 if($job.native_exit -eq 0 -and $job.phase -cin @('installing','recovery_required')){Send-Progress $job 'verifying'}
 $script:Stage='native_verification'
 $after=Read-SetupPreflight $setup
 for($n=0;$after.pending.active_or_degraded -and $n -lt 12;$n++){Start-Sleep -Seconds 5;$after=Read-SetupPreflight $setup}
 if($job.native_exit -eq 67){
  if($after.foundation.version -cne $job.before.foundation.version -or $after.core.version -cne $job.before.core.version -or $after.foundation.package_sha256 -cne $job.before.foundation.package_sha256){throw 'rollback_source_differs'}
  $script:Stage='user_session_restore';$restored=Restore-Companions $job
  $proof=New-NativeProof $job $after 'rolled-back' 67 $restored
  if(!(Test-NativeProofHealthy $proof)){Send-Progress $job 'recovery_required' $proof 'rollback_verification_failed';return}
  Send-Progress $job 'rolled_back' $proof 'setup_automatically_rolled_back'
 }else{
  foreach($part in @($after.foundation,$after.core)){if($part.version -cne $job.release.version -or $part.source_revision -cne $job.release.source_revision -or $part.package_sha256 -cne $job.release.msi_sha256){throw 'target_native_binding_differs'}}
  if($after.core.origin -cne 'msi' -or $after.eligibility -cne 'ALREADY_CURRENT'){throw 'target_native_not_current'}
  $null=Assert-FullSetupSource $after $job.release
  $job.companions=@(Get-CompanionSessions);Save-Job $job
  $script:Stage='user_session_restore';$restored=Restore-Companions $job
  $proof=New-NativeProof $job $after 'accepted' 0 $restored
  $proof.soak=Observe-InstalledRuntime $job
  if(!(Test-NativeProofHealthy $proof) -or !$proof.soak.services_stable -or !$proof.soak.connected -or !$proof.soak.companions_stable){Send-Progress $job 'recovery_required' $proof 'post_install_verification_failed';return}
  $script:Stage='server_acceptance';Send-Progress $job 'applied' $proof 'setup_post_restart_confirmed'
 }
}
function Observe-InstalledRuntime($job,[string]$expectedVersion){
 # Source recovery always starts a new observation epoch. A target-version
 # cache from a previous observation cannot stand in for the surviving source.
 if(!$expectedVersion -and $job.soak -and $job.soak.duration_seconds -ge 180 -and $job.soak.samples -ge 6 -and $job.soak.services_stable -and $job.soak.companions_stable -and $job.soak.connected){return $job.soak}
 if(!$expectedVersion){$expectedVersion=$job.release.version}
 $script:Stage='post_install_observation'
 $processors=[Math]::Max(1,[int](Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors)
 $services=@(Get-CimInstance Win32_Service -Filter "Name='EndpointAgent' OR Name='EndpointBrowserPolicy'"|Sort-Object Name|Select-Object Name,ProcessId)
 $baseline=$services|ConvertTo-Json -Compress;$stable=$true;$connected=$true;$companionsStable=$true;$maximum=0.0;$count=0;$previous=@{}
 $companionBaseline=@(Get-CompanionEvidence $job)
 foreach($process in @(Get-Process -Name EndpointUserSensor -ErrorAction SilentlyContinue)){$previous[[string]$process.Id]=@{cpu=$process.CPU;created=$process.StartTime.ToUniversalTime().ToString('o')}}
 $clock=[Diagnostics.Stopwatch]::StartNew();$last=0.0;$samples=@()
 for($index=0;$index -lt 6;$index++){
  Start-Sleep -Seconds 30;$elapsed=$clock.Elapsed.TotalSeconds;$delta=0.0;$next=@{}
  $sensors=@(Get-Process -Name EndpointUserSensor -ErrorAction SilentlyContinue);$count=$sensors.Count
  foreach($process in $sensors){$id=[string]$process.Id;$created=$process.StartTime.ToUniversalTime().ToString('o');if($previous.ContainsKey($id) -and $previous[$id].created -ceq $created){$delta+=[Math]::Max(0.0,$process.CPU-$previous[$id].cpu)};$next[$id]=@{cpu=$process.CPU;created=$created}}
  $percent=[Math]::Min(100.0,[Math]::Max(0.0,$delta/($elapsed-$last)/$processors*100.0));$maximum=[Math]::Max($maximum,$percent)
  $current=@(Get-CimInstance Win32_Service -Filter "Name='EndpointAgent' OR Name='EndpointBrowserPolicy'"|Sort-Object Name|Select-Object Name,ProcessId)
  if(($current|ConvertTo-Json -Compress) -cne $baseline -or @($current|Where-Object ProcessId -eq 0).Count){$stable=$false}
  try{
   $surviving=@($companionBaseline|Where-Object {(Get-LiveSessionSid ([int]$_.session)) -ceq $_.sid})
   $companionNow=@(Get-CompanionEvidence $job)
   if(($surviving|ConvertTo-Json -Depth 5 -Compress) -cne ($companionNow|ConvertTo-Json -Depth 5 -Compress)){$companionsStable=$false}
   $companionBaseline=$surviving
  }catch{$companionsStable=$false}
  $status=Read-BoundedJson (Join-Path $script:ProgramData 'Endpoint Platform\Tray\agent-status.json') 65536
  if(!$status -or $status.version -cne $expectedVersion -or $status.agent_state -cne 'running' -or $status.endpoint_state -cne 'connected' -or ([DateTimeOffset]::UtcNow-[DateTimeOffset]::Parse($status.observed_at)).TotalSeconds -gt 90){$connected=$false}
  $samples+=@{elapsed_seconds=[Math]::Round($elapsed,3);sensor_count=$count;sensor_cpu_percent=[Math]::Round($percent,4);utc=[DateTime]::UtcNow.ToString('o')}
  Write-PrivateJson (Join-Path (Get-JobRoot $job.assignment_id) 'observation.json') $samples
  $previous=$next;$last=$elapsed
 }
 $job.soak=[ordered]@{duration_seconds=[Math]::Round($clock.Elapsed.TotalSeconds,3);samples=6;sensor_count=$count;sensor_cpu_percent_max=[Math]::Round($maximum,4);services_stable=$stable;companions_stable=$companionsStable;connected=$connected};Save-Job $job
 return $job.soak
}
function Save-ClientStatus([string]$code,$job=$null,[int]$line=0){
 if(!(Test-Path -LiteralPath $script:StateRoot)){return}
 Write-PrivateJson (Join-Path $script:StateRoot 'status.json') @{client_version=$script:ClientVersion;utc=[DateTime]::UtcNow.ToString('o');safe_code=$code;stage=$script:Stage;line=$line;assignment_id=$(if($job){$job.assignment_id}else{$null})}
}
function Get-ActiveJob {
 $active=Read-BoundedJson (Join-Path $script:StateRoot 'active.json') 4096
 if(!$active -or !$active.assignment_id){return $null}
 $root=Get-JobRoot $active.assignment_id;Assert-AdministrativePath $root
 $job=Read-BoundedJson (Join-Path $root 'job.json')
 if(!$job -or $job.assignment_id -cne $active.assignment_id -or $job.device_id -cne $script:DeviceId){throw 'client_journal_invalid'}
 return $job
}
function Test-TerminalPhase([string]$phase){return $phase -cin @('applied','already_current','failed','rolled_back','blocked','cancelled')}
function Sync-ServerJob($job){
 $status=Invoke-EndpointJson 'GET' ('/agent/v1/setup-updates/assignments/'+$job.assignment_id+'/status')
 if($status.phase -ceq 'cancelled' -and !$job.native_started){$job.phase='cancelled';$job.report=$null;Save-Job $job}
}
function Get-PermanentFailureCode([string]$message){
 if($message -cin @('setup_source_not_supported','setup_source_unverified','setup_source_recovery_active','setup_source_newer_than_target','setup_agent_not_running','setup_disk_not_ready','setup_current_binding_differs','cached_artifact_differs','artifact_size_differs','artifact_hash_differs','artifact_hash_mismatch','artifact_signature_invalid','target_native_binding_differs','target_native_not_current','rollback_source_differs','private_material_changed','native_observation_expired')){return $message}
 return $null
}
function Invoke-SetupClient {
 Assert-System;Assert-AdministrativePath $PSCommandPath;Assert-SignedFile $PSCommandPath $null
 Assert-AdministrativePath $script:ClientRoot;Assert-AdministrativePath $script:StateRoot
 $script:Stage='authentication';Initialize-EndpointClient
 $job=Get-ActiveJob;$script:CurrentJob=$job
 $maintenanceReady=Invoke-CompanionMaintenance $job
 $hello=Get-ClientHello
 if(!$maintenanceReady){$hello.safe_code='user_companion_unavailable'}
 $accepted=Invoke-EndpointJson 'POST' '/agent/v1/setup-updates/hello' $hello
 if($accepted.device_id -cne $script:DeviceId){throw 'authenticated_device_differs'}
 if($job -and !(Test-TerminalPhase $job.phase)){Sync-ServerJob $job}
 if($job -and $job.report){
  $pending=$job.report;Send-Progress $job $pending.phase $pending.proof $pending.safe_code
 }
 if($job -and $job.native_started -and !(Test-TerminalPhase $job.phase)){
  if($null -eq $job.native_exit){
   $process=Get-CimInstance Win32_Process -Filter ('ProcessId='+[int]$job.native_pid) -ErrorAction SilentlyContinue
   if($process -and $process.CreationDate.ToUniversalTime().ToString('o') -ceq $job.native_created){Save-ClientStatus 'native_still_running' $job;return}
   Send-Progress $job 'recovery_required' $null 'setup_outcome_unknown';return
  }
  $setup=Join-Path (Get-JobRoot $job.assignment_id) 'Setup.exe';Assert-AdministrativePath $setup
  $pin=[IO.File]::Open($setup,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
  try{Assert-SignedFile $setup $job.release.sha256;Complete-NativeJob $job $setup}finally{$pin.Dispose()}
  return
 }
 if(!$hello.ready){Save-ClientStatus 'waiting_for_agent' $job;return}
 $recommendation=Invoke-EndpointJson 'GET' '/agent/v1/setup-updates/recommendation'
 if(!$recommendation){Save-ClientStatus $(if($maintenanceReady){'idle'}else{'user_companion_unavailable'}) $job;return}
 $assignment=Assert-SetupRecommendation $recommendation
 if(!$job -or $job.assignment_id -cne $assignment){
  if($job -and !(Test-TerminalPhase $job.phase)){throw 'active_assignment_differs'}
  $jobs=Join-Path $script:StateRoot 'jobs';New-AdministrativeDirectory $jobs;$root=Get-JobRoot $assignment;New-AdministrativeDirectory $root
  if(Test-Path -LiteralPath (Join-Path $root 'job.json')){throw 'prior_assignment_must_not_reinstall'}
  $job=[pscustomobject][ordered]@{assignment_id=$assignment;device_id=$script:DeviceId;attempt_id=[guid]::NewGuid().ToString();release=$recommendation.release;phase='assigned';report=$null;native_started=$false;observation_expired=$false;native_pid=0;native_created=$null;native_exit=$null;native_ended=$null;started_at=$null;native_stage=$null;previous_native_id=$null;before=$null;private_before=$null;companions=@();soak=$null}
  Save-Job $job;Write-PrivateJson (Join-Path $script:StateRoot 'active.json') @{assignment_id=$assignment}
  $script:CurrentJob=$job
 }
 $root=Get-JobRoot $assignment;$setup=Join-Path $root 'Setup.exe';$pin=$null
 try{
  if($job.phase -ceq 'assigned'){Send-Progress $job 'downloading'}
  $script:Stage='download'
  $free=[IO.DriveInfo]::new([IO.Path]::GetPathRoot($root)).AvailableFreeSpace
  if($free -lt ([long]$job.release.size*3+536870912)){throw 'client_disk_insufficient'}
  Get-SetupArtifact $job $setup;Assert-AdministrativePath $setup
  $pin=[IO.File]::Open($setup,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);Assert-SignedFile $setup $job.release.sha256
  $script:Stage='preflight';$before=Read-SetupPreflight $setup;$decision=Assert-FullSetupSource $before $job.release
  $job.before=$before;$job.private_before=Get-PrivateSnapshot;$job.companions=@(Get-CompanionSessions)
  $native=Read-BoundedJson (Join-Path $script:InstallerState 'staged-update.json');$job.previous_native_id=$(if($native){$native.binding.operation_id}else{$null});Save-Job $job
  if($job.phase -ceq 'downloading'){Send-Progress $job 'verified'}
  if($decision -ceq 'ALREADY_CURRENT'){
   $proof=New-NativeProof $job $before 'unchanged' $null $true
   if(!(Test-NativeProofHealthy $proof)){Send-Progress $job 'blocked' $proof 'current_state_verification_failed';return}
   Send-Progress $job 'already_current' $proof 'native_already_current';return
  }
  if(Test-CoreOrNativeBusy){Save-ClientStatus 'waiting_for_transaction' $job;return}
  if(Test-Path -LiteralPath (Join-Path $root 'native-started.json')){Send-Progress $job 'recovery_required' $null 'setup_outcome_unknown';return}
  Send-Progress $job 'installing'
  $script:Stage='native_setup';Invoke-NativeSetup $job $setup
  Complete-NativeJob $job $setup
 }finally{if($pin){$pin.Dispose()}}
 Save-ClientStatus 'operation_reported' $job
}

$script:Stage='entry';$script:Http=$null;$script:Credential=$null;$mutex=$null;$held=$false
try{
 Assert-System
 if($Mode -ceq 'Install'){Install-SetupClient;exit 0}
 $security=New-ClientMutexSecurity
 [bool]$created=$false;$mutex=[Threading.Mutex]::new($false,'Global\EndpointSetupUpdater-v1',[ref]$created,$security)
 $acl=$mutex.GetAccessControl()
 if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -cnotin @('S-1-5-18','S-1-5-32-544')){throw 'client_mutex_unsafe'}
 foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){if($rule.IdentityReference.Value -cnotin @('S-1-5-18','S-1-5-32-544') -or $rule.AccessControlType -ne 'Allow'){throw 'client_mutex_unsafe'}}
 try{$held=$mutex.WaitOne(0)}catch [Threading.AbandonedMutexException]{$held=$true}
 if(!$held){exit 0}
 Invoke-SetupClient
}catch{
 # Only a fixed code and line number leave the exception boundary. Neither
 # response bodies nor credentials, paths or arbitrary exception text are logged.
 $failure=Get-PermanentFailureCode $_.Exception.Message
 try{
  if($script:CurrentJob -and !$script:CurrentJob.report -and !(Test-TerminalPhase $script:CurrentJob.phase)){
   if($script:CurrentJob.native_started){Send-Progress $script:CurrentJob 'recovery_required' $null $(if($failure){$failure}else{'native_observation_unavailable'})}
   elseif($failure){Send-Progress $script:CurrentJob 'blocked' $null $failure}
  }
 }catch{}
 try{Save-ClientStatus 'client_run_failed' $script:CurrentJob $_.InvocationInfo.ScriptLineNumber}catch{}
 exit 20
}finally{
 if($script:Http){$script:Http.Dispose()};$script:Credential=$null
 if($held -and $mutex){$mutex.ReleaseMutex()};if($mutex){$mutex.Dispose()}
}
