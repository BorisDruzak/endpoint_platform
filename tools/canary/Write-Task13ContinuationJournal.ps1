# Dot-source once in the workload. Hold journal and directory handles until exit.
Add-Type -TypeDefinition @'
using System;using System.IO;using System.Runtime.InteropServices;
public static class Task13ContinuationJournal {
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern IntPtr CreateFile(string p,uint a,uint share,IntPtr sa,uint disposition,uint flags,IntPtr t);
 static IntPtr[] directories;
 static FileStream stream;
 public static void Open(string root){
  var acl=Directory.GetAccessControl(root);
  if(!acl.AreAccessRulesProtected || (acl.GetOwner(typeof(System.Security.Principal.SecurityIdentifier)).Value!="S-1-5-18" && acl.GetOwner(typeof(System.Security.Principal.SecurityIdentifier)).Value!="S-1-5-32-544"))throw new IOException("protected journal root required");
  foreach(System.Security.AccessControl.FileSystemAccessRule ace in acl.GetAccessRules(true,true,typeof(System.Security.Principal.SecurityIdentifier))){var sid=ace.IdentityReference.Value;if(sid!="S-1-5-18"&&sid!="S-1-5-32-544")throw new IOException("journal principal");}
  var ancestry=new System.Collections.Generic.List<IntPtr>();
  for(var d=new DirectoryInfo(root);d!=null;d=d.Parent){
   if((d.Attributes&FileAttributes.ReparsePoint)!=0)throw new IOException("journal reparse");
   var h=CreateFile(d.FullName,0x80000000,3,IntPtr.Zero,3,0x02200000,IntPtr.Zero);
   if(h==new IntPtr(-1))throw new IOException("journal ancestry handle");ancestry.Add(h);
  }
  directories=ancestry.ToArray();
  stream=new FileStream(Path.Combine(root,"stages.jsonl"),FileMode.CreateNew,FileAccess.Write,FileShare.Read,4096,FileOptions.WriteThrough);
 }
 public static void Append(byte[] bytes){if(stream==null||stream.Length+bytes.Length>33554432)throw new IOException("journal bound");stream.Write(bytes,0,bytes.Length);stream.Flush(true);}
}
'@
[Task13ContinuationJournal]::Open($global:Task13Root)
function global:Task13Mark([string]$phase,[string]$stage,$counts=$null){
 $row=[ordered]@{utc=[DateTime]::UtcNow.ToString('o');ms=$global:Task13Clock.ElapsedMilliseconds;run=$global:Task13Run;pid=$PID;birth=$global:Task13Birth;phase=$phase;stage=$stage;seq=++$global:Task13Seq;counts=$counts}
 [Task13ContinuationJournal]::Append([Text.UTF8Encoding]::new($false).GetBytes(($row|ConvertTo-Json -Depth 8 -Compress)+"`n"))
}
