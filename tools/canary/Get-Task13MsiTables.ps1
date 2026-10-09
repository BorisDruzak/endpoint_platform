# Read-only diagnostic replacement for the recovery comparator's NativeRows.
# Caller supplies Bound and durable Task13Mark; external watchdog remains required.
function Get-Task13MsiTables {
 param($Msi,[string]$Cache,
  [ValidateRange(1,6000)][int]$MaxRows=6000,
  [ValidateRange(1,64)][int]$MaxFields=64,
  [ValidateRange(1,128)][int]$ChunkRows=128,
  [ValidateRange(1,20)][int]$TableSeconds=20,
  [ValidateRange(1,5)][int]$ChunkSeconds=5)
 $all=[Diagnostics.Stopwatch]::StartNew()
 $totals=[ordered]@{tables=0;views=0;executes=0;rows=0;fields=0;fetches=0;field_count_calls=0;duplicates=0}
 Task13Mark 'ENTER' 'MSI_TABLES.SUMMARY'
 Task13Mark 'ENTER' 'MSI_TABLES.OPEN_DATABASE' @{mode=0}
 $db=$Msi.OpenDatabase($Cache,0)
 Task13Mark 'RETURN' 'MSI_TABLES.OPEN_DATABASE' @{ms=$all.ElapsedMilliseconds}
 $result=[ordered]@{}
 foreach($table in @('Component','Feature','FeatureComponents','ServiceInstall','ServiceControl')){
  Bound
  $clock=[Diagnostics.Stopwatch]::StartNew();$chunk=[Diagnostics.Stopwatch]::StartNew()
  $counts=[ordered]@{views=0;executes=0;rows=0;fields=0;fetches=0;field_count_calls=0;chunks=0;duplicates=0;fetch_ticks=0L;field_count_ticks=0L;field_ticks=0L;frequency=[Diagnostics.Stopwatch]::Frequency}
  $rows=@()
  $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
  $view=$null;$chunkStart=0;$chunkActive=$false
  try{
   Task13Mark 'ENTER' ('MSI_TABLES.'+$table+'.SUMMARY') @{table_seconds=$TableSeconds;chunk_seconds=$ChunkSeconds;max_rows=$MaxRows;max_fields=$MaxFields}
   Task13Mark 'ENTER' ('MSI_TABLES.'+$table+'.OPEN')
   $view=$db.OpenView(('SELECT * FROM `'+$table+'`'))
   $counts.views++
   Task13Mark 'RETURN' ('MSI_TABLES.'+$table+'.OPEN') @{ms=$clock.ElapsedMilliseconds}
   Task13Mark 'ENTER' ('MSI_TABLES.'+$table+'.EXECUTE')
   $view.Execute()
   $counts.executes++
   Task13Mark 'RETURN' ('MSI_TABLES.'+$table+'.EXECUTE') @{ms=$clock.ElapsedMilliseconds}
   while($true){
    if(-not $chunkActive){
     $chunk.Restart();$chunkStart=$counts.rows;$chunkActive=$true
     Task13Mark 'ENTER' ('MSI_TABLES.'+$table+'.ROWS') @{completed_rows=$counts.rows;completed_fields=$counts.fields;max_chunk_rows=$ChunkRows}
    }
    Bound
    if($clock.Elapsed.TotalSeconds -ge $TableSeconds -or $chunk.Elapsed.TotalSeconds -ge $ChunkSeconds){throw 'MSI stage time bound'}
    $t=[Diagnostics.Stopwatch]::GetTimestamp();$record=$view.Fetch()
    $counts.fetch_ticks+=([Diagnostics.Stopwatch]::GetTimestamp()-$t);$counts.fetches++
    if($null -eq $record){break}
    if($counts.rows -ge $MaxRows){throw 'MSI rows bound'}
    # Cache metadata exactly once per record; do not fetch the record again.
    $t=[Diagnostics.Stopwatch]::GetTimestamp();$n=$record.FieldCount()
    $counts.field_count_ticks+=([Diagnostics.Stopwatch]::GetTimestamp()-$t);$counts.field_count_calls++
    if($n -lt 1 -or $n -gt $MaxFields){throw 'MSI fields bound'}
    $values=@()
    for($i=1;$i -le $n;$i++){
     Bound
     if($clock.Elapsed.TotalSeconds -ge $TableSeconds -or $chunk.Elapsed.TotalSeconds -ge $ChunkSeconds){throw 'MSI stage time bound'}
     $t=[Diagnostics.Stopwatch]::GetTimestamp();$values+=[string]$record.StringData($i)
     $counts.field_ticks+=([Diagnostics.Stopwatch]::GetTimestamp()-$t);$counts.fields++
    }
    # Length-prefix each value: collision-free even if a string contains delimiters.
    $key=($values|ForEach-Object{$_.Length.ToString()+':'+$_}) -join ''
    if(-not $seen.Add($key)){$counts.duplicates++;throw 'MSI duplicate record'}
    $rows+=,@($values);$counts.rows++
    if(($counts.rows-$chunkStart) -ge $ChunkRows){
     $counts.chunks++
     Task13Mark 'RETURN' ('MSI_TABLES.'+$table+'.ROWS') @{completed_rows=$counts.rows;completed_fields=$counts.fields;chunk_ms=$chunk.ElapsedMilliseconds}
     $chunkActive=$false
    }
   }
   if($clock.Elapsed.TotalSeconds -ge $TableSeconds -or $chunk.Elapsed.TotalSeconds -ge $ChunkSeconds){throw 'MSI stage time bound'}
   if($chunkActive){$counts.chunks++;Task13Mark 'RETURN' ('MSI_TABLES.'+$table+'.ROWS') @{completed_rows=$counts.rows;completed_fields=$counts.fields;chunk_ms=$chunk.ElapsedMilliseconds};$chunkActive=$false}
   Task13Mark 'ENTER' ('MSI_TABLES.'+$table+'.SORT') @{rows=$counts.rows}
   $result[$table]=@($rows | Sort-Object {$_ -join '|'} -CaseSensitive)
   if($clock.Elapsed.TotalSeconds -ge $TableSeconds){throw 'MSI stage time bound'}
   Task13Mark 'RETURN' ('MSI_TABLES.'+$table+'.SORT') @{ms=$clock.ElapsedMilliseconds}
  }catch{
   Task13Mark 'FAIL' ('MSI_TABLES.'+$table) @{rows=$counts.rows;fields=$counts.fields;fetches=$counts.fetches;duplicates=$counts.duplicates;ms=$clock.ElapsedMilliseconds}
   throw
  }finally{
   if($null -ne $view){Task13Mark 'ENTER' ('MSI_TABLES.'+$table+'.CLOSE');$view.Close();Task13Mark 'RETURN' ('MSI_TABLES.'+$table+'.CLOSE')}
  }
  $counts.ms=$clock.ElapsedMilliseconds
  Task13Mark 'RETURN' ('MSI_TABLES.'+$table+'.SUMMARY') $counts
  $totals.tables++;$totals.views+=$counts.views;$totals.executes+=$counts.executes;$totals.rows+=$counts.rows;$totals.fields+=$counts.fields;$totals.fetches+=$counts.fetches;$totals.field_count_calls+=$counts.field_count_calls
 }
 $totals.ms=$all.ElapsedMilliseconds
 Task13Mark 'RETURN' 'MSI_TABLES.SUMMARY' $totals
 return $result
}
