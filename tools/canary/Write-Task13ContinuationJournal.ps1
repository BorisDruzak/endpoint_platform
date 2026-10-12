# Dot-source once in the workload. Hold journal and directory handles until exit.
Add-Type -TypeDefinition @'
using System;using System.IO;using System.Runtime.InteropServices;using Microsoft.Win32.SafeHandles;
public static class Task13ContinuationJournal {
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern IntPtr CreateFile(string p,uint a,uint share,IntPtr sa,uint disposition,uint flags,IntPtr t);
 static IntPtr[] directories;
 static FileStream stream;
 [StructLayout(LayoutKind.Sequential)]struct SA {public uint length;public IntPtr descriptor;public int inherit;}
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string s,uint r,out IntPtr p,IntPtr size);
 [DllImport("kernel32.dll")]static extern IntPtr LocalFree(IntPtr p);
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
  IntPtr descriptor;if(!ConvertStringSecurityDescriptorToSecurityDescriptor("O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)",1,out descriptor,IntPtr.Zero))throw new IOException("journal security");
  IntPtr attributes=Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SA)));
  try{Marshal.StructureToPtr(new SA{length=(uint)Marshal.SizeOf(typeof(SA)),descriptor=descriptor,inherit=0},attributes,false);
   var h=CreateFile(Path.Combine(root,"stages.jsonl"),0x40000000,1,attributes,1,0x80200000,IntPtr.Zero);
   if(h==new IntPtr(-1))throw new IOException("exclusive protected journal");
   stream=new FileStream(new SafeFileHandle(h,true),FileAccess.Write,4096,false);
  }finally{Marshal.FreeHGlobal(attributes);LocalFree(descriptor);}
 }
 public static void Append(byte[] bytes){if(stream==null||stream.Length+bytes.Length>33554432)throw new IOException("journal bound");stream.Write(bytes,0,bytes.Length);stream.Flush(true);}
}
'@
[Task13ContinuationJournal]::Open($global:Task13Root)
function global:Task13Mark([string]$phase,[string]$stage,$counts=$null){
 $row=[ordered]@{utc=[DateTime]::UtcNow.ToString('o');ms=$global:Task13Clock.ElapsedMilliseconds;run=$global:Task13Run;pid=$PID;birth=$global:Task13Birth;phase=$phase;stage=$stage;seq=++$global:Task13Seq;counts=$counts}
 [Task13ContinuationJournal]::Append([Text.UTF8Encoding]::new($false).GetBytes(($row|ConvertTo-Json -Depth 8 -Compress)+"`n"))
}
