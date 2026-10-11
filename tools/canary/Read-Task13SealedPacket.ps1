# Bindings are prepended by the reviewed packet factory. No script runs before EOF.
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$OutputEncoding=[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$t=[Diagnostics.Stopwatch]::StartNew();$u=[Text.UTF8Encoding]::new($false,$true)
$m=$null;$g=$null;$o=$null;$i=[Console]::OpenStandardInput()
function T13H([byte[]]$b){$h=[Security.Cryptography.SHA256]::Create();try{([BitConverter]::ToString($h.ComputeHash($b))).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()}}
function T13R([byte[]]$b,[int]$p,[int]$n){
 if($t.ElapsedMilliseconds -ge 10000){throw 'input deadline'}
 $a=$i.BeginRead($b,$p,$n,$null,$null)
 if(-not $a.AsyncWaitHandle.WaitOne([Math]::Max(0,10000-[int]$t.ElapsedMilliseconds))){throw 'input deadline'}
 try{$r=$i.EndRead($a);if($t.ElapsedMilliseconds -ge 10000){throw 'input deadline'};$r}finally{$a.AsyncWaitHandle.Dispose()}
}
try{
 [byte[]]$wire=New-Object 'byte[]' $n;$p=0;$calls=0
 while($p -lt $n){
  if($calls -ge $n -or $t.ElapsedMilliseconds -ge 120000){throw 'frame bound'}
  $take=[Math]::Min(4096,$n-$p);$r=T13R $wire $p $take;$calls++
  if($r -le 0 -or $r -gt $take){throw 'frame count'};$p+=$r
 }
 if((T13R (New-Object 'byte[]' 1) 0 1) -ne 0){throw 'frame trailing input'}
 $text=$u.GetString($wire)
 if($t.ElapsedMilliseconds -ge 120000 -or $text.Length -ne $n -or $wire.Length -ne $n -or (T13H $wire) -cne $wh){throw 'wire identity'}
 $m=[IO.MemoryStream]::new([Convert]::FromBase64String($text));$g=[IO.Compression.GzipStream]::new($m,[IO.Compression.CompressionMode]::Decompress)
 $o=[IO.MemoryStream]::new();$chunk=New-Object 'byte[]' 4096
 while($true){
  if($t.ElapsedMilliseconds -ge 120000){throw 'body bound'}
  $r=$g.Read($chunk,0,[Math]::Min(4096,$bn+1-[int]$o.Length));if($r -eq 0){break}
  $o.Write($chunk,0,$r);if($o.Length -gt $bn){throw 'body size'}
 }
 $b=$o.ToArray();if($b.Length -ne $bn -or (T13H $b) -cne $bh){throw 'body identity'}
 $v=$u.GetString($b)|ConvertFrom-Json
 if(((@($v.PSObject.Properties.Name)|Sort-Object)-join '|') -cne 'parameters|script' -or $v.script -isnot [string] -or (T13H ($u.GetBytes($v.script))) -cne $sh){throw 'source identity'}
 $keys='PayloadManifestJson|PayloadManifestSha256|PlanSha256|RunId|Step|TrustedRootThumbprint'.Split('|')
 $names=@($keys)+@('ExecuteReviewedStep')
 if(((@($v.parameters.PSObject.Properties.Name)|Sort-Object)-join '|') -cne (($names|Sort-Object)-join '|')){throw 'parameter names'}
 if($v.parameters.ExecuteReviewedStep -isnot [bool] -or $v.parameters.ExecuteReviewedStep -ne $true){throw 'reviewed step'}
 $values=@();foreach($k in $keys){if($v.parameters.$k -isnot [string]){throw 'parameter type'};$values+=T13H ($u.GetBytes($v.parameters.$k))}
 if((T13H ($u.GetBytes($values -join '|'))) -cne $ph){throw 'parameter identity'}
 if($t.ElapsedMilliseconds -ge 120000){throw 'decode bound'}
 $a=@{};foreach($k in $v.parameters.PSObject.Properties){$a[$k.Name]=$k.Value}
 & ([ScriptBlock]::Create($v.script)) @a
}catch{exit 2}
finally{foreach($s in @($g,$m,$o)){if($null -ne $s){$s.Dispose()}}}
