# In-memory native timings; flush at durable phase boundaries, not per call.
$global:Task13NativeStats=@{}
$global:Task13NativeActive=$null
function global:Task13AggEnter([string]$name){
 if($null -ne $global:Task13NativeActive){throw 'overlapping native profile'}
 if(-not $global:Task13NativeStats.ContainsKey($name)){
  $global:Task13NativeStats[$name]=@{started=0;returned=0;ticks=0L;max_ticks=0L;frequency=[Diagnostics.Stopwatch]::Frequency}
 }
 $global:Task13NativeStats[$name].started++
 $global:Task13NativeActive=@{name=$name;tick=[Diagnostics.Stopwatch]::GetTimestamp()}
}
function global:Task13AggReturn([string]$name){
 if($null -eq $global:Task13NativeActive -or $global:Task13NativeActive.name -cne $name){throw 'native profile pairing'}
 $elapsed=[Diagnostics.Stopwatch]::GetTimestamp()-$global:Task13NativeActive.tick
 $stats=$global:Task13NativeStats[$name];$stats.returned++;$stats.ticks+=$elapsed
 if($elapsed -gt $stats.max_ticks){$stats.max_ticks=$elapsed}
 $global:Task13NativeActive=$null
}
function global:Task13ProfileFlush {
 foreach($name in @($global:Task13NativeStats.Keys|Sort-Object)){
  Task13Mark 'RETURN' ('PROFILE.'+$name) $global:Task13NativeStats[$name]
 }
 if($null -ne $global:Task13NativeActive){Task13Mark 'UNKNOWN' ('PROFILE.'+$global:Task13NativeActive.name) @{incomplete=$true}}
 $global:Task13NativeStats=@{}
}
