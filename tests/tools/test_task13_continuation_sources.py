import os
import subprocess
from pathlib import Path
import re
from uuid import uuid4

import pytest

from tools.canary.task13_continuation.codec import canonical
from tools.canary.task13_continuation.sources import seal_sources, verify_sources, build_execution_sources
from tools.canary.task13_continuation.journal import validate_journal
from tools.canary.task13_continuation.history import verify_historical_prefix

pytestmark = pytest.mark.no_db


def test_any_closure_byte_substitution_refuses():
    entries = {"helper.ps1": b"compare", "wrapper.ps1": b"wrapper", "wire.bin": b"wire"}
    closure = seal_sources(entries)
    verify_sources(closure, entries)
    for name in entries:
        with pytest.raises(ValueError):
            verify_sources(closure, {**entries, name: entries[name] + b" "})


def journal(identity):
    return b"".join(canonical(dict(identity, seq=n, ms=n, utc="2026-10-11T00:00:00Z",
                                  phase=p, stage=s, counts=None)) + b"\n"
                    for n, (p, s) in enumerate([("ENTER", "WRAPPER"), ("RETURN", "WATCHDOG_ARMED"),
                                                ("ENTER", "SCRIPTBLOCK.INVOKE"),
                                                ("RETURN", "SCRIPTBLOCK.INVOKE"),
                                                ("RETURN", "WRAPPER")], 1))


def test_journal_requires_complete_identity_bound_finish():
    identity = {"run": str(uuid4()), "pid": 12, "birth": 123}
    raw = journal(identity)
    validate_journal(raw, identity)
    for bad in [raw[:-1], raw[:-20], raw.replace(b'"pid":12', b'"pid":13'),
                raw.replace(b'"seq":2', b'"seq":9'), raw.replace(b'"RETURN"', b'"UNKNOWN"')]:
        with pytest.raises(ValueError):
            validate_journal(bad, identity)


@pytest.mark.skipif(os.name != "nt", reason="native protected journal compilation")
def test_owned_native_journal_writer(tmp_path):
    from tools.canary.task13_continuation.storage import ProtectedStore
    store = ProtectedStore.create_root(tmp_path / "journal")
    writer = Path(__file__).resolve().parents[2] / "tools/canary/Write-Task13ContinuationJournal.ps1"
    code = ("$ErrorActionPreference='Stop';$global:Task13Root='" + str(store.root) + "';"
            "$global:Task13Run='" + str(uuid4()) + "';$global:Task13Birth=123;$global:Task13Seq=0;"
            "$global:Task13Clock=[Diagnostics.Stopwatch]::StartNew();. '" + str(writer) + "';"
            "Task13Mark 'ENTER' 'WRAPPER';Task13Mark 'RETURN' 'WATCHDOG_ARMED';"
            "Task13Mark 'ENTER' 'SCRIPTBLOCK.INVOKE';Task13Mark 'RETURN' 'SCRIPTBLOCK.INVOKE';"
            "Task13Mark 'RETURN' 'WRAPPER'")
    result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", code],
                            capture_output=True, timeout=20)
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    from tools.canary.task13_continuation.codec import parse_json
    raw = ProtectedStore(store.root, require_protected=False).read("stages.jsonl")
    first = parse_json(raw.splitlines()[0])
    validate_journal(raw, {k: first[k] for k in ("run", "pid", "birth")})


@pytest.mark.skipif(os.name != "nt",reason="owned native guest support types")
def test_guest_support_types_compile_and_refuse_replacement(tmp_path):
    from tools.canary.task13_continuation.storage import ProtectedStore
    base = Path(__file__).resolve().parents[2]/"tools/canary"
    csharp = []
    for name in ("Prepare-Task13ContinuationWatchdog.ps1","Read-Task13ContinuationEvidence.ps1"):
        source = (base/name).read_text()
        block = re.search(r"Add-Type -TypeDefinition @'\n(.*?)\n'@",source,re.S)
        assert block
        csharp.append("Add-Type -TypeDefinition @'\n"+block[1]+"\n'@\n")
    root = tmp_path/"owned-root"
    code = "$ErrorActionPreference='Stop';"+"\n".join(csharp)
    code += ("[Task13ExclusiveRoot]::Create('"+str(root)+"');"
             "try{[Task13ExclusiveRoot]::Create('"+str(root)+"');throw 'replacement accepted'}catch [IO.IOException]{};"
             "[IO.File]::WriteAllText('"+str(root/"owned.json")+"','owned');"
             "[Task13RetainedEvidence]::Hold('"+str(root)+"');"
             "[Text.Encoding]::UTF8.GetString([Task13RetainedEvidence]::Read('"+str(root/"owned.json")+"'))")
    result = subprocess.run(["powershell.exe","-NoProfile","-NonInteractive","-Command",code],
                            capture_output=True,timeout=20)
    assert result.returncode == 0,result.stderr.decode(errors="replace")
    assert result.stdout.strip() == b"owned"
    ProtectedStore(root)  # Restrictive owner/DACL were atomically installed.


@pytest.mark.skipif(not os.environ.get("TASK13_HISTORICAL_ROOT"), reason="private retained prefix input")
def test_actual_compare_sources_keep_original_facts_and_parse():
    prefix = verify_historical_prefix(os.environ["TASK13_HISTORICAL_ROOT"])
    cid = str(uuid4())
    entries = build_execution_sources(prefix, cid, "C:\\Task13Continuation-" + cid.replace("-", ""))
    helper = entries["helper.ps1"].decode()
    assert "[ValidateSet('compare')]" in helper
    assert "Get-Task13MsiTables $msi $cache" in helper
    assert "Task13AggEnter 'NATIVE." in helper
    assert "run_id=$RunId.ToString();plan_sha256=$PlanSha256" in helper
    assert "POST_SNAPSHOT_MARKER_CREATED" not in helper
    verify_sources(seal_sources(entries), entries)
    from tools.canary.task13_continuation.operations import build_operations
    operations = build_operations(prefix,cid,entries,Path('C:/Task13OwnedOfflineBundle'))
    assert operations['allowed_seq'] == 4
    assert {'entry-guest.ps1','entry-prepare.ps1','entry-collect.ps1','provider-stdin.bin'} <= entries.keys()
