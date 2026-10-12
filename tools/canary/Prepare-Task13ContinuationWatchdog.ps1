param([Guid]$Run,[string]$Root,[string]$WatchdogBase64,[string]$ExpectedSha256)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
if($Root -cne ('C:\Task13Continuation-'+$Run.ToString('N')) -or (Test-Path -LiteralPath $Root)){throw 'fresh continuation root required'}
$parent=Get-Item -LiteralPath 'C:\';if($parent.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'root reparse'}
Add-Type -TypeDefinition @'
using System;using System.IO;using System.Runtime.InteropServices;using Microsoft.Win32.SafeHandles;
public static class Task13ExclusiveRoot {
 [StructLayout(LayoutKind.Sequential)]struct SA {public uint length;public IntPtr descriptor;public int inherit;}
 [StructLayout(LayoutKind.Sequential,Pack=4)]struct Info {public uint attrs;public long creation,access,write;public uint volume,high,low,links,indexHigh,indexLow;}
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string s,uint r,out IntPtr p,IntPtr size);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern bool CreateDirectory(string p,ref SA a);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern SafeFileHandle CreateFile(string p,uint a,uint share,IntPtr sa,uint d,uint flags,IntPtr t);
 [DllImport("kernel32.dll",SetLastError=true)]static extern bool GetFileInformationByHandle(SafeFileHandle h,out Info i);
 [DllImport("kernel32.dll")]static extern IntPtr LocalFree(IntPtr p);
 static SafeFileHandle parent,root;
 public static void Create(string path){
  parent=CreateFile(Path.GetPathRoot(path),0x80000000,3,IntPtr.Zero,3,0x02200000,IntPtr.Zero);
  Info pi;if(parent.IsInvalid||!GetFileInformationByHandle(parent,out pi)||(pi.attrs&0x400)!=0)throw new IOException("parent identity");
  IntPtr descriptor;if(!ConvertStringSecurityDescriptorToSecurityDescriptor("O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",1,out descriptor,IntPtr.Zero))throw new IOException("root security");
  try{var sa=new SA{length=(uint)Marshal.SizeOf(typeof(SA)),descriptor=descriptor,inherit=0};if(!CreateDirectory(path,ref sa))throw new IOException("exclusive root exists or creation refused");}finally{LocalFree(descriptor);}
  root=CreateFile(path,0x80000000,3,IntPtr.Zero,3,0x02200000,IntPtr.Zero);
  Info ri;if(root.IsInvalid||!GetFileInformationByHandle(root,out ri)||(ri.attrs&0x400)!=0)throw new IOException("root identity");
 }
}
'@
[Task13ExclusiveRoot]::Create($Root)
$bytes=[Convert]::FromBase64String($WatchdogBase64);$sha=[Security.Cryptography.SHA256]::Create()
try{$actual=([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
if($actual -cne $ExpectedSha256){throw 'watchdog exact source'}
$path=Join-Path $Root 'watchdog.ps1'
$stream=[IO.FileStream]::new($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read,4096,[IO.FileOptions]::WriteThrough)
try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
$name='Task13ContinuationWatchdog-'+$Run.ToString('N')
$exe=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$action=New-ScheduledTaskAction -Execute $exe -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$path+'" -Root "'+$Root+'" -Run '+$Run.ToString()+' -Limit 120')
$settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::FromMinutes(4)) -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName $name -Action $action -Settings $settings -User 'SYSTEM' -RunLevel Highest -ErrorAction Stop|Out-Null
Start-ScheduledTask -TaskName $name
$wait=[Diagnostics.Stopwatch]::StartNew()
while(-not(Test-Path -LiteralPath (Join-Path $Root 'watchdog-ready.json'))){if($wait.Elapsed.TotalSeconds -ge 15){throw 'watchdog readiness UNKNOWN'};Start-Sleep -Milliseconds 50}
$ready=Get-Content -LiteralPath (Join-Path $Root 'watchdog-ready.json') -Raw|ConvertFrom-Json
if($ready.run -cne $Run.ToString() -or $ready.limit -ne 120 -or $ready.pid -le 0){throw 'watchdog readiness binding'}
[ordered]@{status='INDEPENDENT_WATCHDOG_READY';run=$Run.ToString();root=$Root;watchdog_sha256=$actual;ready=$ready}|ConvertTo-Json -Compress
