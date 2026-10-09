# Diagnostic acceptance harness only. Run independently (for example as SYSTEM
# scheduled task) before a single explicitly approved workload; does not launch it.
# Caller must prepare a fresh protected root and atomically publish identity.json.
# SyntheticCaptureStall is only for local failure-path regression tests.
param([Parameter(Mandatory=$true)][string]$Root,[Parameter(Mandatory=$true)][string]$Run,[ValidateRange(2,120)][int]$Limit=120,[switch]$SyntheticCaptureStall)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$Root=[IO.Path]::GetFullPath($Root)
if(([Guid]$Run).ToString() -cne $Run){throw 'canonical run required'}
$item=[IO.DirectoryInfo]::new($Root)
if(-not $item.Exists){throw 'root must be directory'}
while($null -ne $item){if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'root ancestry reparse'};$item=$item.Parent}
$acl=[IO.Directory]::GetAccessControl($Root)
if(-not $acl.AreAccessRulesProtected -or $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18','S-1-5-32-544')){throw 'root protection required'}
foreach($ace in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){if($ace.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544')){throw 'root principal refused'}}
Add-Type -TypeDefinition @'
using System;using System.IO;using System.Text;using System.Threading;using System.Diagnostics;using System.Runtime.InteropServices;
public static class Task13Watch {
 [DllImport("kernel32.dll",SetLastError=true)]static extern IntPtr OpenProcess(uint access,bool inherit,uint id);
 [DllImport("kernel32.dll",SetLastError=true)]static extern bool GetProcessTimes(IntPtr h,out long creation,out long exit,out long kernel,out long user);
 [DllImport("kernel32.dll",SetLastError=true)]static extern uint WaitForSingleObject(IntPtr h,uint ms);
 [DllImport("kernel32.dll",SetLastError=true)]static extern bool TerminateProcess(IntPtr h,uint code);
 [DllImport("kernel32.dll",SetLastError=true)]static extern bool GetExitCodeProcess(IntPtr h,out uint code);
 [DllImport("kernel32.dll",SetLastError=true)]static extern bool CloseHandle(IntPtr h);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern bool QueryFullProcessImageName(IntPtr h,uint flags,StringBuilder image,ref uint size);
 public static void Save(string root,string name,string data){byte[] b=new UTF8Encoding(false).GetBytes(data);using(var f=new FileStream(Path.Combine(root,name),FileMode.CreateNew,FileAccess.Write,FileShare.Read,4096,FileOptions.WriteThrough)){f.Write(b,0,b.Length);f.Flush(true);}}
 static string Q(string s){return "\""+s.Replace("\\","\\\\").Replace("\"","\\\"").Replace("\r","\\r").Replace("\n","\\n")+"\"";}
 public static void Run(string root,uint pid,long expectedBirth,int limit,bool stall){
  IntPtr h=OpenProcess(0x101001,false,pid);bool verified=false;bool ended=false;bool captured=false;bool captureBeforeExit=false;string captureError=null;string killUtc=null;long captureFinishedTicks=0;
  if(h==IntPtr.Zero)throw new Exception("open target");
  try{
   long birth,exit,kernel,user;
   if(!GetProcessTimes(h,out birth,out exit,out kernel,out user)||birth!=expectedBirth)throw new Exception("birth mismatch");
   var image=new StringBuilder(32768);uint size=32768;
   if(!QueryFullProcessImageName(h,0,image,ref size)||!String.Equals(image.ToString(),Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),@"WindowsPowerShell\v1.0\powershell.exe"),StringComparison.OrdinalIgnoreCase))throw new Exception("image mismatch");
   verified=true;
   // Reserve 500ms inside the ceiling for wake-up/scheduling/termination latency.
   // Native kill does not wait for capture, including capture I/O failures.
   double remaining=limit-0.5-(DateTime.UtcNow-DateTime.FromFileTimeUtc(birth)).TotalSeconds;
   if(remaining<=0)throw new Exception("late watchdog");
   Stopwatch clock=Stopwatch.StartNew();
   Save(root,"watchdog-armed.json","{\"pid\":"+pid+",\"birth\":"+birth+",\"remaining_ms\":"+(long)(remaining*1000)+",\"safety_margin_ms\":500,\"retained_handle\":true}");
   while(clock.Elapsed.TotalSeconds<Math.Max(0,remaining-Math.Min(2,remaining/2))){if(WaitForSingleObject(h,20)==0){ended=true;break;}}
   bool terminated=false;
   if(!ended && WaitForSingleObject(h,0)!=0){
    uint before;
    if(!GetProcessTimes(h,out birth,out exit,out kernel,out user)||!GetExitCodeProcess(h,out before))throw new IOException("process state unavailable");
    long capturedBirth=birth,capturedKernel=kernel,capturedUser=user;uint capturedCode=before;
    var capture=new Thread(()=>{try{
     if(stall)Thread.Sleep(30000);
     string journal=Path.Combine(root,"stages.jsonl");string last="";
     if(!File.Exists(journal))throw new IOException("stage journal missing");
     if(File.Exists(journal)){
      string snapshot=Path.Combine(root,"stages-before-termination.jsonl");
      using(var input=new FileStream(journal,FileMode.Open,FileAccess.Read,FileShare.ReadWrite))
      using(var output=new FileStream(snapshot,FileMode.CreateNew,FileAccess.Write,FileShare.Read,4096,FileOptions.WriteThrough)){
       // Freeze a bounded prefix. Concurrent append cannot extend this copy.
       long left=input.Length,expected=left;
       if(left>33554432)throw new IOException("stage journal bound");
       byte[] buffer=new byte[8192];
       while(left>0){int n=input.Read(buffer,0,(int)Math.Min(buffer.Length,left));if(n<=0)throw new EndOfStreamException("journal prefix truncated");output.Write(buffer,0,n);left-=n;}
       if(output.Length!=expected||output.Length>33554432)throw new IOException("snapshot bound");
       output.Flush(true);
      }
      string text=File.ReadAllText(snapshot);int end=text.LastIndexOf('\n');
      if(end<0)throw new IOException("no complete journal frame");
      string complete=text.Substring(0,end).TrimEnd('\r');int previous=complete.LastIndexOf('\n');
      last=complete.Substring(previous+1).TrimEnd('\r');
     }
     if(last.Length==0)throw new IOException("stage journal empty");
     Save(root,"capture-state.json","{\"pid\":"+pid+",\"birth\":"+capturedBirth+",\"exit_code\":"+capturedCode+",\"kernel_ticks\":"+capturedKernel+",\"user_ticks\":"+capturedUser+",\"utc\":"+Q(DateTime.UtcNow.ToString("o"))+",\"last_stage\":"+Q(last)+",\"capture_complete\":true}");
     Interlocked.Exchange(ref captureFinishedTicks,DateTime.UtcNow.Ticks);
     Volatile.Write(ref captured,true);
    }catch(Exception e){captureError=e.GetType().Name;}});capture.IsBackground=true;capture.Start();
    while(clock.Elapsed.TotalSeconds<remaining){if(WaitForSingleObject(h,10)==0){ended=true;break;}}
    captureBeforeExit=Volatile.Read(ref captured);
    if(!ended && WaitForSingleObject(h,0)!=0){killUtc=DateTime.UtcNow.ToString("o");terminated=TerminateProcess(h,124);if(!terminated)throw new Exception("termination refused");}
   }
   uint signal=WaitForSingleObject(h,10000),code;bool query=GetExitCodeProcess(h,out code);bool confirmed=signal==0&&query&&code!=259;
   Save(root,"exit-confirmed.json","{\"pid\":"+pid+",\"birth\":"+birth+",\"terminated\":"+terminated.ToString().ToLowerInvariant()+",\"wait_result\":"+signal+",\"exit_code\":"+code+",\"confirmed\":"+confirmed.ToString().ToLowerInvariant()+",\"capture_complete_before_exit\":"+captureBeforeExit.ToString().ToLowerInvariant()+",\"capture_finished_utc_ticks\":"+Interlocked.Read(ref captureFinishedTicks)+",\"termination_utc\":"+(killUtc==null?"null":Q(killUtc))+",\"capture_error\":"+(captureError==null?"null":Q(captureError))+",\"elapsed_ms\":"+clock.ElapsedMilliseconds+"}");
   if(!confirmed)throw new Exception("exit unconfirmed");
  }finally{
   if(verified&&WaitForSingleObject(h,0)!=0){bool t=TerminateProcess(h,125);uint s=WaitForSingleObject(h,10000),c;bool q=GetExitCodeProcess(h,out c);try{Save(root,"failsafe-exit-confirmed.json","{\"terminated\":"+t.ToString().ToLowerInvariant()+",\"confirmed\":"+(s==0&&q&&c!=259).ToString().ToLowerInvariant()+"}");}catch{}}
   CloseHandle(h);
  }
 }
}
'@
try{
 [Task13Watch]::Save($Root,'watchdog-ready.json',(@{pid=$PID;run=$Run;limit=$Limit;utc=[DateTime]::UtcNow.ToString('o')}|ConvertTo-Json -Compress))
 $wait=[Diagnostics.Stopwatch]::StartNew()
 while(-not(Test-Path -LiteralPath (Join-Path $Root 'identity.json'))){if($wait.Elapsed.TotalSeconds -ge 60){throw 'no target'};Start-Sleep -Milliseconds 50}
 $identity=Get-Content -LiteralPath (Join-Path $Root 'identity.json') -Raw|ConvertFrom-Json
 if($identity.root -cne $Root -or $identity.run -cne $Run -or $identity.pid -le 0 -or $identity.pid -eq $PID){throw 'target binding'}
 [Task13Watch]::Run($Root,[uint32]$identity.pid,[long]$identity.birth,$Limit,$SyntheticCaptureStall.IsPresent)
}catch{try{[Task13Watch]::Save($Root,'watchdog-error.json',(@{type=$_.Exception.GetType().Name;message=$_.Exception.Message}|ConvertTo-Json -Compress))}catch{};exit 2}
