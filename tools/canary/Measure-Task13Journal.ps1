param([Parameter(Mandatory=$true)][string]$Root)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
Add-Type 'public static class BenchNative { [System.Runtime.InteropServices.DllImport("kernel32.dll")] public static extern uint GetCurrentProcessId(); }'
$root=[IO.Path]::GetFullPath($Root)
$item=[IO.DirectoryInfo]::new($root)
while($null -ne $item){
 if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'reparse ancestor'}
 $item=$item.Parent
}
$acl=[IO.Directory]::GetAccessControl($root)
if(-not $acl.AreAccessRulesProtected){throw 'protected root required'}
if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18','S-1-5-32-544')){throw 'unexpected owner'}
foreach($ace in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){
 if($ace.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544')){throw 'unexpected principal'}
}
$ops=2000;$encoding=[Text.UTF8Encoding]::new($false)
$events=@($encoding.GetBytes('{"phase":"ENTER","stage":"SYNTHETIC"}'+"`n"),$encoding.GetBytes('{"phase":"RETURN","stage":"SYNTHETIC"}'+"`n"))
$results=@()
foreach($trial in 1..3){
 $modes=$(if($trial -eq 2){@('aggregate_flush','per_event_flush','profile_counts')}else{@('per_event_flush','aggregate_flush','profile_counts')})
 foreach($mode in $modes){
  $path=Join-Path $root ('benchmark-'+$trial+'-'+$mode+'.jsonl')
  $stream=[IO.FileStream]::new($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read,4096,[IO.FileOptions]::None)
  $clock=[Diagnostics.Stopwatch]::StartNew();$flushes=0;$native=0;$eventsWritten=0
  try{
   foreach($i in 1..$ops){
    if($clock.Elapsed.TotalSeconds -gt 30){throw 'benchmark time bound'}
    [void][BenchNative]::GetCurrentProcessId();$native++
    if($mode -ne 'profile_counts'){
     foreach($bytes in $events){$stream.Write($bytes,0,$bytes.Length);$eventsWritten++;if($mode -eq 'per_event_flush'){$stream.Flush($true);$flushes++}}
     if($mode -eq 'aggregate_flush' -and $i%128 -eq 0){$stream.Flush($true);$flushes++}
    }
   }
   if($mode -eq 'profile_counts'){$bytes=$encoding.GetBytes(('{"native_calls":'+$native+',"logical_events":'+($native*2)+'}')+"`n");$stream.Write($bytes,0,$bytes.Length);$eventsWritten++}
   $stream.Flush($true);$flushes++
  }finally{$stream.Dispose()}
  $clock.Stop()
  $results+=@{mode=$mode;trial=$trial;operations=$native;logical_events=($native*2);written_events=$eventsWritten;flushes=$flushes;bytes=(Get-Item -LiteralPath $path).Length;hash=(Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant();ms=$clock.Elapsed.TotalMilliseconds}
 }
}
@{operations_per_trial=$ops;frequency=[Diagnostics.Stopwatch]::Frequency;results=$results}|ConvertTo-Json -Depth 8 -Compress|Set-Content -LiteralPath (Join-Path $root 'benchmark-results.json') -Encoding UTF8
