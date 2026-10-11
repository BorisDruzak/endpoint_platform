"""Deterministic separately derived compare-only helper and exact transport bytes."""
import base64
import json
import re
import subprocess
import tempfile
from pathlib import Path

from .codec import require, sha256, uuid, canonical
from .history import read_file
from .journal import FACTS,NATIVE_ALLOWED

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


def delivery_bootstrap(binding):
    """Compact verifier for the existing RECOVERY_EXACT_COUNT packet format."""
    from .codec import integer, hex256
    from .operations import thin_script
    n = integer(binding['wire_bytes'], 1, 4*1024*1024)
    body = integer(binding['body_utf8_bytes'], 1, 8*1024*1024)
    for name in ('wire_sha256', 'body_utf8_sha256', 'helper_sha256'):
        hex256(binding[name])
    pins = binding['parameter_hashes']
    require(type(pins) is dict and set(pins) == {'Step','RunId','PlanSha256','PayloadManifestJson',
            'PayloadManifestSha256','TrustedRootThumbprint'}, 'fixed delivery parameter pins')
    for pin in pins.values(): hex256(pin)
    # One projection pin binds the same sorted per-string SHA256 checks without
    # carrying six high-entropy digests through the command line separately.
    projection = sha256('|'.join(pin for name,pin in sorted(pins.items())).encode('ascii'))
    constants = (f"$n={n};$bn={body};$wh='{binding['wire_sha256']}';"
                 f"$bh='{binding['body_utf8_sha256']}';$sh='{binding['helper_sha256']}';$ph='{projection}';\n")
    verifier = read_file(CANARY/'Read-Task13SealedPacket.ps1').decode('utf-8')
    return thin_script(constants+verifier).encode('utf-8')


def build_stdin_delivery(prefix, script, data=b''):
    """Reuse the sealed controller factory, including its size and public pins."""
    require(type(script) is str and type(data) is bytes, 'exact delivery inputs')
    source = script
    if data:
        # The unchanged workload wrapper still reads the exact original wire.
        # Its private reader becomes available only after the outer packet is verified.
        text = data.decode('ascii')
        require(all(ch in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=' for ch in text),
                'original inner wire must be exact base64 ASCII')
        source = ("$task13OriginalIn=[Console]::In;$task13InnerIn=[IO.StringReader]::new('"+text+"');"
                  "try{[Console]::SetIn($task13InnerIn);& {"+script+"\n}}"
                  "finally{[Console]::SetIn($task13OriginalIn);$task13InnerIn.Dispose()}")
    raw = source.encode('utf-8')
    params = {'Step':'compare','RunId':prefix.plan['run_id'],'PlanSha256':prefix.seal['plan_sha256'],
              'PayloadManifestJson':read_file(prefix.root/'canonical-msi81-payload-manifest.json').decode(),
              'PayloadManifestSha256':prefix.plan['payload_manifest_sha256'],
              'TrustedRootThumbprint':prefix.plan['trusted_root_thumbprint'],'ExecuteReviewedStep':True}
    binding = {}
    _, packet = prefix.controller.guest_transport(raw,params,sha256(raw),recovery_exact_count=True,frame_metadata=binding)
    binding['parameter_hashes'] = {name:sha256(value.encode('utf-8')) for name,value in params.items() if type(value) is str}
    return delivery_bootstrap(binding), packet, binding


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
    source = replace_once(source, "status='GUEST_COMPARATOR_PASS';run_id=$RunId.ToString();",
                           "status='GUEST_COMPARATOR_PASS';run_id=$RunId.ToString();plan_sha256=$PlanSha256;")
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
    source = replace_once(source, "function InspectEnter([string]$stage){", "function InspectEnter([string]$stage){\n  Task13ProfileFlush;if($null -ne $global:Task13FactsActive){Task13Mark 'RETURN' ('FACTS.'+$global:Task13FactsActive)};$global:Task13FactsActive=$stage;Task13Mark 'ENTER' ('FACTS.'+$stage)")
    entries["helper.ps1"] = source.encode("utf-8")
    require(re.findall(r"InspectEnter '([^']+)'",source)==FACTS
            and set(re.findall(r"Task13AggEnter 'NATIVE.([^']+)'",source))==NATIVE_ALLOWED,
            'exact helper/journal stage contract')
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
    entries["guest-ssh-prefix.json"] = canonical({"argv":argv[:-1]})
    wrapper = base64.b64decode(argv[-1].split(" ")[-1]).decode("utf-16-le")
    prelude = ("$global:Task13Root='" + guest_root + "';$global:Task13Run='" + continuation_id + "';"
               "$global:Task13Clock=[Diagnostics.Stopwatch]::StartNew();$global:Task13Seq=0;$global:Task13FactsActive=$null;"
               "$global:Task13Birth=[Diagnostics.Process]::GetCurrentProcess().StartTime.ToUniversalTime().ToFileTimeUtc()\n"
               "$identity=@{root=$global:Task13Root;run=$global:Task13Run;pid=$PID;birth=$global:Task13Birth}|ConvertTo-Json -Compress\n")
    prelude += (
        "$ib=[Text.UTF8Encoding]::new($false).GetBytes($identity);"
        "$f=[IO.FileStream]::new((Join-Path $global:Task13Root 'identity.json'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read,4096,[IO.FileOptions]::WriteThrough);"
        "try{$f.Write($ib,0,$ib.Length);$f.Flush($true)}finally{$f.Dispose()}\n"
        "$arm=[Diagnostics.Stopwatch]::StartNew();while(-not(Test-Path -LiteralPath (Join-Path $global:Task13Root 'watchdog-armed.json'))){if($arm.ElapsedMilliseconds -gt 10000){throw 'watchdog not armed'};Start-Sleep -Milliseconds 50}\n"
        + entries["Write-Task13ContinuationJournal.ps1"].decode() + "\n"
        + entries["Task13AggregateProfile.ps1"].decode() + "\n"
        "Task13Mark 'ENTER' 'WRAPPER';Task13Mark 'RETURN' 'WATCHDOG_ARMED'\n")
    wrapper = replace_once(wrapper, "$m=$null;$g=$null;$bodyStream=$null", prelude + "$m=$null;$g=$null;$bodyStream=$null")
    wrapper = replace_once(wrapper, "$read=[Console]::In.Read($buffer,$position,$requested);$calls++",
        "Task13Mark 'ENTER' 'STDIN.READ' @{requested=$requested;position=$position;call=$calls};$read=[Console]::In.Read($buffer,$position,$requested);Task13Mark 'RETURN' 'STDIN.READ' @{requested=$requested;returned=$read;position=($position+$read);call=$calls};$calls++")
    wrapper = replace_once(wrapper, "$read=$g.Read($chunk,0,$take)",
                           "Task13Mark 'ENTER' 'PAYLOAD.GZIP_READ';$read=$g.Read($chunk,0,$take);Task13Mark 'RETURN' 'PAYLOAD.GZIP_READ'")
    wrapper = replace_once(wrapper, "& ([ScriptBlock]::Create($v.script)) @a",
                           "Task13Mark 'ENTER' 'SCRIPTBLOCK.INVOKE';& ([ScriptBlock]::Create($v.script)) @a;Task13ProfileFlush;if($null -ne $global:Task13FactsActive){Task13Mark 'RETURN' ('FACTS.'+$global:Task13FactsActive);$global:Task13FactsActive=$null};Task13Mark 'RETURN' 'SCRIPTBLOCK.INVOKE';Task13Mark 'RETURN' 'WRAPPER'")
    wrapper = replace_once(wrapper, "}catch{exit 2}", "}catch{Task13ProfileFlush;Task13Mark 'FAIL' $_.Exception.GetType().Name;exit 2}")
    entries["wrapper.ps1"], entries["wire.bin"] = wrapper.encode("utf-16-le"), wire
    parse_sites(wrapper)
    return entries
