param([Guid]$Run,[string]$Root)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
if($Root -cne ('C:\Task13Continuation-'+$Run.ToString('N'))){throw 'evidence root binding'}
$acl=[IO.Directory]::GetAccessControl($Root)
if(-not $acl.AreAccessRulesProtected -or $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18','S-1-5-32-544')){throw 'evidence root protection'}
foreach($ace in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){if($ace.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544')){throw 'evidence principal'}}
Add-Type -TypeDefinition @'
using System;using System.IO;using System.Runtime.InteropServices;using Microsoft.Win32.SafeHandles;
public static class Task13RetainedEvidence {
 [StructLayout(LayoutKind.Sequential,Pack=4)]struct Info {public uint attrs;public long creation,access,write;public uint volume,high,low,links,indexHigh,indexLow;}
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern SafeFileHandle CreateFile(string p,uint a,uint share,IntPtr sa,uint disposition,uint flags,IntPtr t);
 [DllImport("kernel32.dll",SetLastError=true)]static extern bool GetFileInformationByHandle(SafeFileHandle h,out Info info);
 static System.Collections.Generic.List<SafeFileHandle> ancestry=new System.Collections.Generic.List<SafeFileHandle>();
 public static void Hold(string root){for(var d=new DirectoryInfo(root);d!=null;d=d.Parent){var h=CreateFile(d.FullName,0x80000000,3,IntPtr.Zero,3,0x02200000,IntPtr.Zero);Info i;if(h.IsInvalid||!GetFileInformationByHandle(h,out i)||(i.attrs&0x400)!=0)throw new IOException("evidence ancestry");ancestry.Add(h);}}
 public static byte[] Read(string path){using(var h=CreateFile(path,0x80000000,1,IntPtr.Zero,3,0x00200000,IntPtr.Zero)){Info i;if(h.IsInvalid||!GetFileInformationByHandle(h,out i)||(i.attrs&0x410)!=0||i.links!=1||i.high!=0||i.low>33554432)throw new IOException("evidence retained identity");using(var f=new FileStream(h,FileAccess.Read)){byte[] b=new byte[i.low];int p=0;while(p<b.Length){int n=f.Read(b,p,b.Length-p);if(n<=0)throw new IOException("evidence truncated");p+=n;}if(f.ReadByte()!=-1)throw new IOException("evidence changed");return b;}}}
}
'@
[Task13RetainedEvidence]::Hold($Root)
$wait=[Diagnostics.Stopwatch]::StartNew()
while(-not(Test-Path -LiteralPath (Join-Path $Root 'exit-confirmed.json'))){if($wait.Elapsed.TotalSeconds -ge 10){throw 'exit settlement UNKNOWN'};Start-Sleep -Milliseconds 50}
foreach($bad in @('watchdog-error.json','failsafe-exit-confirmed.json')){if(Test-Path -LiteralPath (Join-Path $Root $bad)){throw 'watchdog failed'}}
$files=[ordered]@{}
foreach($name in @('identity.json','watchdog-ready.json','watchdog-armed.json','exit-confirmed.json','stages.jsonl')){
 $bytes=[Task13RetainedEvidence]::Read((Join-Path $Root $name));$files[$name]=[Convert]::ToBase64String($bytes)
}
[ordered]@{status='RETAINED_CONTINUATION_EVIDENCE';run=$Run.ToString();root=$Root;files=$files}|ConvertTo-Json -Depth 5 -Compress
