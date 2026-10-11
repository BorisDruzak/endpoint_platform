"""Deterministic separately derived compare-only helper and exact transport bytes."""
import base64
import json
import re
import subprocess
import tempfile
from pathlib import Path

from .codec import require, sha256, uuid
from .history import read_file

CANARY = Path(__file__).resolve().parent.parent
CORRECTED = {"Get-Task13MsiTables.ps1": "13c5a93944ee4b4386e3f81f2dcf0cdde020864949b7b480f3e15d55af73d3fc",
             "Task13AggregateProfile.ps1": "0221009b6857f633c4117e65bfd6d1d02bea3079ca20717f5777d9e3a41422b4",
             "Watch-Task13DiagnosticProcess.ps1": "b5d547a1b5d865ff7f3bb85aa7391c4d5aeeb68d0c3bd23eae6fafb8a51a5527"}


def seal_sources(entries):
    require(type(entries) is dict and entries, "nonempty source closure")
    return {"schema": "task13_execution_sources_v1", "entries": {
        name: {"bytes": len(raw), "sha256": sha256(raw)} for name, raw in sorted(entries.items())}}


def verify_sources(closure, entries):
    require(closure == seal_sources(entries), "execution source closure changed")


def replace_once(source, old, new):
    require(source.count(old) == 1, "exact source patch boundary")
    return source.replace(old, new, 1)


def parse_sites(source):
    # Generated inputs are private. Windows-native restricted temporary directory.
    from .storage import ProtectedStore
    parent = Path(tempfile.gettempdir())
    store = ProtectedStore.create_root(parent / ("task13-ast-" + __import__("uuid").uuid4().hex))
    store.create("source.ps1", source.encode("utf-8"))
    store.create("ast.json", b"")
    result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-File",
                             str(CANARY / "Extract-Task13ContinuationAst.ps1"),
                             str(store.root / "source.ps1"), str(store.root / "ast.json")],
                            capture_output=True, timeout=30)
    require(result.returncode == 0 and not result.stderr, "generated PowerShell parse failed")
    rows = json.loads(store.read("ast.json").decode("utf-8-sig"))
    rows.sort(key=lambda row: row["start"])
    require(all(a["end"] <= b["start"] for a, b in zip(rows, rows[1:])), "overlapping native sites")
    return rows


def build_execution_sources(prefix, continuation_id, guest_root):
    uuid(continuation_id)
    require(guest_root == "C:\\Task13Continuation-" + continuation_id.replace("-", ""), "fixed guest root")
    entries = {name: read_file(CANARY / name) for name in CORRECTED}
    require(all(sha256(entries[name]) == pin for name, pin in CORRECTED.items()), "corrected committed source pins")
    for name in ("Write-Task13ContinuationJournal.ps1", "Extract-Task13ContinuationAst.ps1"):
        entries[name] = read_file(CANARY / name)
    original = read_file(prefix.root / "Invoke-Task13RecoveryGuest.draft.ps1")
    require(sha256(original) == prefix.plan["helper_hashes"]["Invoke-Task13RecoveryGuest.draft.ps1"], "original helper changed")
    source = original.decode("utf-8").replace("\r\n", "\n")
    source = replace_once(source, "[ValidateSet('inspect','capture','compare','marker','restored')]", "[ValidateSet('compare')]")
    first = source.index("  if($Step -eq 'inspect'){")
    last = source.index("  }else{\n    Protected $recovery;Protected $baseline", first)
    source = source[:first] + "  {\n    Protected $recovery;Protected $baseline" + source[last + len("  }else{\n    Protected $recovery;Protected $baseline"):]
    source = replace_once(source, "  {\n    Protected", "  if($Step -eq 'compare'){\n    Protected")
    source = replace_once(source, "    if($Step -eq 'restored' -and (Test-Path -LiteralPath $marker)){throw 'restore witness survived'}\n", "")
    source = replace_once(source, "status=($(if($Step -eq 'restored'){'RESTORED_GUEST_COMPARATOR_PASS'}else{'GUEST_COMPARATOR_PASS'}))", "status='GUEST_COMPARATOR_PASS'")
    a = source.index("function NativeRows(")
    b = source.index("\nfunction ", a + 1)
    shim = "function NativeRows($msi,[string]$cache){return (Get-Task13MsiTables $msi $cache)}"
    source = source[:a] + shim + source[b:]
    for row in reversed(parse_sites(source)):
        a, b = row["start"], row["end"]
        require(source[a:b] == row["expression"], "native AST source mismatch")
        name = re.sub("[^A-Za-z0-9_]", "", row["name"])
        source = source[:a] + "$(Task13AggEnter 'NATIVE." + name + "'; " + source[a:b] + "; Task13AggReturn 'NATIVE." + name + "')" + source[b:]
    reader = entries["Get-Task13MsiTables.ps1"].decode("utf-8").replace("\r\n", "\n")
    source = replace_once(source, shim, reader + "\n" + shim)
    source = replace_once(source, "function InspectEnter([string]$stage){", "function InspectEnter([string]$stage){\n  Task13ProfileFlush;Task13Mark 'ENTER' ('FACTS.'+$stage)")
    entries["helper.ps1"] = source.encode("utf-8")
    parse_sites(source)  # Verify final generated AST, including injected reader.
    params = {"Step": "compare", "RunId": prefix.plan["run_id"], "PlanSha256": prefix.seal["plan_sha256"],
              "PayloadManifestJson": read_file(prefix.root / "canonical-msi81-payload-manifest.json").decode(),
              "PayloadManifestSha256": prefix.plan["payload_manifest_sha256"],
              "TrustedRootThumbprint": prefix.plan["trusted_root_thumbprint"], "ExecuteReviewedStep": True,
              "ExpectedBaselineSha256": prefix.binding["baseline_sha256"],
              "SnapshotIdentitySha256": prefix.binding["snapshot_identity_sha256"],
              "PredecessorSha256": prefix.binding["original_tip"]}
    argv, wire = prefix.controller.guest_transport(entries["helper.ps1"], params, sha256(entries["helper.ps1"]),
                                                   recovery_exact_count=True, frame_metadata={})
    wrapper = base64.b64decode(argv[-1].split(" ")[-1]).decode("utf-16-le")
    prelude = ("$global:Task13Root='" + guest_root + "';$global:Task13Run='" + continuation_id + "';"
               "$global:Task13Clock=[Diagnostics.Stopwatch]::StartNew();$global:Task13Seq=0;"
               "$global:Task13Birth=[Diagnostics.Process]::GetCurrentProcess().StartTime.ToUniversalTime().ToFileTimeUtc()\n"
               + entries["Write-Task13ContinuationJournal.ps1"].decode() + "\n"
               + entries["Task13AggregateProfile.ps1"].decode() + "\n"
               "Task13Mark 'ENTER' 'WRAPPER'\n"
               "$identity=@{root=$global:Task13Root;run=$global:Task13Run;pid=$PID;birth=$global:Task13Birth}|ConvertTo-Json -Compress\n"
               "[Task13Watch]::Save" )
    # Workload has no dependency on the watchdog's in-process type.
    prelude = prelude.removesuffix("[Task13Watch]::Save") + (
        "$ib=[Text.UTF8Encoding]::new($false).GetBytes($identity);"
        "$f=[IO.FileStream]::new((Join-Path $global:Task13Root 'identity.json'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read,4096,[IO.FileOptions]::WriteThrough);"
        "try{$f.Write($ib,0,$ib.Length);$f.Flush($true)}finally{$f.Dispose()}\n"
        "$arm=[Diagnostics.Stopwatch]::StartNew();while(-not(Test-Path -LiteralPath (Join-Path $global:Task13Root 'watchdog-armed.json'))){if($arm.ElapsedMilliseconds -gt 10000){throw 'watchdog not armed'};Start-Sleep -Milliseconds 50};Task13Mark 'RETURN' 'WATCHDOG_ARMED'\n")
    wrapper = replace_once(wrapper, "$m=$null;$g=$null;$bodyStream=$null", prelude + "$m=$null;$g=$null;$bodyStream=$null")
    wrapper = replace_once(wrapper, "& ([ScriptBlock]::Create($v.script)) @a",
                           "Task13Mark 'ENTER' 'SCRIPTBLOCK.INVOKE';& ([ScriptBlock]::Create($v.script)) @a;Task13ProfileFlush;Task13Mark 'RETURN' 'SCRIPTBLOCK.INVOKE';Task13Mark 'RETURN' 'WRAPPER'")
    wrapper = replace_once(wrapper, "}catch{exit 2}", "}catch{Task13ProfileFlush;Task13Mark 'FAIL' $_.Exception.GetType().Name;exit 2}")
    entries["wrapper.ps1"], entries["wire.bin"] = wrapper.encode("utf-16-le"), wire
    parse_sites(wrapper)
    return entries
