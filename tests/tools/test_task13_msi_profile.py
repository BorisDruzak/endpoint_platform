"""Synthetic MSI records; no installer or device operations."""
import json
from pathlib import Path
import subprocess
import sys

import pytest

pytestmark = [pytest.mark.no_db, pytest.mark.skipif(sys.platform != "win32", reason="PowerShell 5.1")]
SCRIPT = Path(__file__).resolve().parents[2] / "tools/canary/Get-Task13MsiTables.ps1"
FAKES = r'''
$global:Calls=@{open=0;execute=0;fetch=0;fieldcount=0;field=0;close=0}
$global:Marks=[Collections.Generic.List[object]]::new()
function Task13Mark($phase,$stage,$counts){$global:Marks.Add(@{phase=$phase;stage=$stage;counts=$counts})}
function Bound {}
class Record {
 [string[]]$values
 Record([string[]]$v){$this.values=$v}
 [int]FieldCount(){$global:Calls.fieldcount++;return $this.values.Length}
 [string]StringData([int]$n){$global:Calls.field++;return $this.values[$n-1]}
}
class View {
 [object[]]$rows;[int]$position=0
 View([object[]]$r){$this.rows=$r}
 [void]Execute(){$global:Calls.execute++}
 [object]Fetch(){$global:Calls.fetch++;if($this.position -ge $this.rows.Length){return $null};$r=[Record]::new($this.rows[$this.position]);$this.position++;return $r}
 [void]Close(){$global:Calls.close++}
}
class Database {
 [object[]]$rows
 Database([object[]]$r){$this.rows=$r}
 [object]OpenView([string]$q){$global:Calls.open++;return [View]::new($this.rows)}
}
class Installer {
 [object[]]$rows
 Installer([object[]]$r){$this.rows=$r}
 [object]OpenDatabase([string]$p,[int]$mode){if($mode -ne 0){throw 'write mode'};return [Database]::new($this.rows)}
}
function OriginalRows($msi,$cache){
 $db=$msi.OpenDatabase($cache,0);$result=[ordered]@{}
 foreach($table in @('Component','Feature','FeatureComponents','ServiceInstall','ServiceControl')){
  $view=$db.OpenView(('SELECT * FROM `'+$table+'`'));$view.Execute();$rows=@()
  try{while($null -ne ($record=$view.Fetch())){
   $values=@();for($n=1;$n -le $record.FieldCount();$n++){$values+=[string]$record.StringData($n)}
   $rows+=,@($values);if($rows.Count -gt 6000){throw 'MSI rows bound'}
  }}finally{$view.Close()}
  $result[$table]=@($rows|Sort-Object {$_ -join '|'} -CaseSensitive)
 }
 return $result
}
'''


def run(tmp_path: Path, body: str) -> dict:
    script = tmp_path / "test.ps1"
    script.write_text("$ErrorActionPreference='Stop'\n. '" + str(SCRIPT) + "'\n" + FAKES + body)
    r = subprocess.run(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script)], capture_output=True, timeout=30)
    assert r.returncode == 0, r.stderr.decode(errors="replace")
    return json.loads(r.stdout)


def test_one_pass_caches_field_count_and_preserves_sorted_rows(tmp_path):
    v = run(tmp_path, r'''
$original=OriginalRows ([Installer]::new(@(@('b','2'),@('a','1')))) 'synthetic'
$global:Calls=@{open=0;execute=0;fetch=0;fieldcount=0;field=0;close=0}
$r=Get-Task13MsiTables ([Installer]::new(@(@('b','2'),@('a','1')))) 'synthetic'
@{result=$r;original=$original;calls=$global:Calls;marks=$global:Marks.ToArray()}|ConvertTo-Json -Depth 12 -Compress
''')
    assert len(v["result"]) == 5
    # PowerShell 5.1 can serialize array wrappers with Count/value properties.
    # Compare the exact reference shape, including those properties.
    assert v["result"] == v["original"]
    assert all([r.get("value", r) if isinstance(r, dict) else r for r in rows] == [["a", "1"], ["b", "2"]] for rows in v["result"].values())
    assert v["calls"] == dict(open=5, execute=5, fetch=15, fieldcount=10, field=20, close=5)
    summaries = [x["counts"] for x in v["marks"] if x["stage"] == "MSI_TABLES.SUMMARY"]
    assert summaries[-1]["rows"] == 10 and summaries[-1]["fields"] == 20


@pytest.mark.parametrize("case,error", [("duplicate", "duplicate"), ("rows", "rows bound"), ("fields", "fields bound")])
def test_bounds_fail_closed_and_close_view(tmp_path, case, error):
    rows = {"duplicate": "@(@('a','1'),@('a','1'))", "rows": "@(@('a','1'),@('b','2'))", "fields": "@(,@('a','1'))"}[case]
    args = {"duplicate": "", "rows": "-MaxRows 1", "fields": "-MaxFields 1"}[case]
    v = run(tmp_path, f"""
try{{$r=Get-Task13MsiTables ([Installer]::new({rows})) 'synthetic' {args};throw 'expected failure'}}catch{{$errorText=$_.Exception.Message}}
@{{error=$errorText;calls=$global:Calls;marks=$global:Marks.ToArray()}}|ConvertTo-Json -Depth 12 -Compress
""")
    assert error in v["error"]
    assert v["calls"]["close"] == 1
    assert not any(x["stage"] == "MSI_TABLES.SUMMARY" and x["phase"] == "RETURN" for x in v["marks"])


@pytest.mark.parametrize("rows,count", [("@()", 0), ("@(,@('a','1'))", 1), ("@(0..128|ForEach-Object{,@($_.ToString(),'value')})", 129)])
def test_empty_single_and_chunk_boundary_match_reference(tmp_path, rows, count):
    v = run(tmp_path, f"""
$a=OriginalRows ([Installer]::new({rows})) 'synthetic'
$global:Calls=@{{open=0;execute=0;fetch=0;fieldcount=0;field=0;close=0}}
$b=Get-Task13MsiTables ([Installer]::new({rows})) 'synthetic'
@{{original=$a;result=$b;calls=$global:Calls;marks=$global:Marks.ToArray()}}|ConvertTo-Json -Depth 12 -Compress
""")
    assert v["result"] == v["original"]
    assert v["calls"]["fieldcount"] == count * 5
    assert v["calls"]["fetch"] == (count + 1) * 5
    assert v["calls"]["field"] == count * 2 * 5


def test_aggregate_preserves_native_ref_and_false_return(tmp_path):
    aggregate = SCRIPT.with_name("Task13AggregateProfile.ps1")
    v = run(tmp_path, f". '{aggregate}'\n" + r'''
Add-Type 'public static class RefTest { public static int Call(ref int x){x+=2;return 7;} public static bool False(){return false;} }'
[int]$state=1;$native=[RefTest]
$rc=$(Task13AggEnter 'Call';$native::Call([ref]$state);Task13AggReturn 'Call')
$falseValue=$(Task13AggEnter 'False';$native::False();Task13AggReturn 'False')
Task13ProfileFlush
@{state=$state;rc=$rc;is_int=($rc -is [int]);false_value=$falseValue;marks=$global:Marks.ToArray()}|ConvertTo-Json -Depth 8 -Compress
''')
    assert v["state"] == 3 and v["rc"] == 7 and v["is_int"]
    assert v["false_value"] is False
    assert all(x["counts"]["started"] == x["counts"]["returned"] == 1 for x in v["marks"])


def test_chunk_time_bound_fails_without_fetch_and_closes_view(tmp_path):
    v = run(tmp_path, r'''
function Bound {Start-Sleep -Milliseconds 1100}
try{$r=Get-Task13MsiTables ([Installer]::new(@(,@('a','1')))) 'synthetic' -ChunkSeconds 1;throw 'expected failure'}catch{$errorText=$_.Exception.Message}
@{error=$errorText;calls=$global:Calls;marks=$global:Marks.ToArray()}|ConvertTo-Json -Depth 12 -Compress
''')
    assert "time bound" in v["error"]
    assert v["calls"]["close"] == 1 and v["calls"]["fetch"] == 0
    assert any(x["phase"] == "FAIL" for x in v["marks"])


def test_incomplete_aggregate_is_unknown(tmp_path):
    v = run(tmp_path, f". '{SCRIPT.with_name('Task13AggregateProfile.ps1')}'\n" + r'''
Task13AggEnter 'Interrupted'
Task13ProfileFlush
@{marks=$global:Marks.ToArray()}|ConvertTo-Json -Depth 8 -Compress
''')
    assert v["marks"][0]["counts"]["started"] == 1
    assert v["marks"][0]["counts"]["returned"] == 0
    assert v["marks"][1]["phase"] == "UNKNOWN"
