"""Build fixed private observation commands from sealed original sources."""
import ast
import base64
import gzip
import re
from pathlib import Path
from uuid import UUID

from .codec import canonical, require, sha256, parse_json,digest
from .process_identity import reference_registry
from .history import read_file, MANIFEST_SHA
from .sources import CANARY, replace_once
from . import windows


def thin_script(source):
    raw = source.encode("utf-16-le")
    compressed = base64.b64encode(gzip.compress(raw,mtime=0)).decode()
    return ("$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';"
            "$m=[IO.MemoryStream]::new([Convert]::FromBase64String('"+compressed+"'));"
            "$g=[IO.Compression.GzipStream]::new($m,[IO.Compression.CompressionMode]::Decompress);"
            "$o=[IO.MemoryStream]::new();try{$g.CopyTo($o);$b=$o.ToArray();"
            "if($b.Length -ne "+str(len(raw))+" -or $b.Length -gt 65536){throw 'entry bound'};"
            "$h=[Security.Cryptography.SHA256]::Create();try{$s=([BitConverter]::ToString($h.ComputeHash($b))).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()};"
            "if($s -cne '"+sha256(raw)+"'){throw 'entry source'};& ([ScriptBlock]::Create([Text.UnicodeEncoding]::new($false,$false,$true).GetString($b)))"
            "}finally{$g.Dispose();$m.Dispose();$o.Dispose()}")


def provider_command(prefix):
    raw = original_source(prefix,"task13_provider_isolation.draft.py")
    tree = ast.parse(raw)
    function = next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name == "ownership")
    assignments = [node for node in function.body if isinstance(node,ast.Assign)
                   and isinstance(node.targets[0],ast.Name) and node.targets[0].id in ("rollout_filter","sql")]
    require(len(assignments) == 2, "fixed read-only provider SQL boundary")
    namespace = {"DEVICE":prefix.plan["device_id"],"UUID":UUID,"rollout_id":None}
    exec(compile(ast.Module(body=assignments,type_ignores=[]),"sealed_provider_sql","exec"),namespace)
    calls = [node for node in ast.walk(function) if isinstance(node,ast.Call)
             and isinstance(node.func,ast.Attribute) and node.func.attr == "bounded_process"]
    require(len(calls) == 1,"fixed provider transport boundary")
    argv = ast.literal_eval(calls[0].args[0])
    require(type(argv) is list and all(type(v) is str for v in argv)
            and "StrictHostKeyChecking=yes" in argv and "BatchMode=yes" in argv, "strict provider SSH")
    return argv,namespace["sql"].encode()


def original_source(prefix,name):
    manifest_raw = read_file(prefix.root/"source-closure-manifest.json")
    require(sha256(manifest_raw) == MANIFEST_SHA,"original observation manifest")
    spec = next(v for v in parse_json(manifest_raw)["entries"] if v["name"] == name)
    raw = read_file(prefix.root/name)
    require(sha256(raw) == spec["sha256"] and len(raw) == spec["bytes"],"original observation source pin")
    return raw


def build_operations(prefix, cid, entries, bundle):
    guest_root = "C:\\Task13Continuation-"+cid.replace("-","")
    ssh = parse_json(entries["guest-ssh-prefix.json"])["argv"]
    require("StrictHostKeyChecking=yes" in ssh and "BatchMode=yes" in ssh,"strict guest SSH")
    provider_argv,sql = provider_command(prefix)
    native_ssh = next(path for path in windows.system_core_paths() if path.name == 'ssh.exe')
    for argv in (ssh,provider_argv):
        require(argv[0] in ('ssh','ssh.exe',str(native_ssh)), 'sealed SSH executable selector')
        argv[0] = str(native_ssh)
    inventory = original_source(prefix,"Observe-RecoveryLeaves.ps1").decode()
    inventory = replace_once(inventory,"RUN_UUID_PLACEHOLDER",prefix.plan["run_id"])
    current = original_source(prefix,"Observe-NativeWrapperCurrent.ps1").decode()
    current = replace_once(current,"a43598a5-59f9-4a01-8486-cea0d4924709",prefix.plan["run_id"])
    registry=reference_registry(prefix)
    entries['process-references.json']=canonical(registry)
    entries['Observe-Task13ProcessIdentity.ps1']=read_file(CANARY/'Observe-Task13ProcessIdentity.ps1')
    process_identity=("& {"+entries['Observe-Task13ProcessIdentity.ps1'].decode()+"} -RunId '"+registry['run_id']
        +"' -ExpectedVmUuid '"+registry['vm_uuid']+"' -RegistrySha256 '"+digest(registry)
        +"' -Ids @("+','.join(str(r['pid']) for r in registry['refs'])+")")
    for name in ("Observe-Task13ContinuationGuest.ps1","Prepare-Task13ContinuationWatchdog.ps1","Read-Task13ContinuationEvidence.ps1"):
        entries[name] = read_file(CANARY/name)
    original = original_source(prefix,"Invoke-Task13RecoveryGuest.draft.ps1").decode()
    networks = set(re.findall(r"MACAddress -eq '([0-9A-F:]{17})' -and \$_\.IPAddress -contains '([0-9.]+)'",original))
    require(len(networks) == 1,"fixed original guest network assertion")
    mac,ip = next(iter(networks))
    guest = ("& {"+entries["Observe-Task13ContinuationGuest.ps1"].decode()+"} -RunId '"+prefix.plan["run_id"]
             +"' -PlanSha256 '"+prefix.binding["original_plan_sha256"]+"' -ExpectedBaselineSha256 '"+prefix.binding["baseline_sha256"]
             +"' -ExpectedVmUuid '"+prefix.plan["vm_uuid"]+"' -ExpectedDeviceId '"+prefix.plan["device_id"]
             +"' -ExpectedMac '"+mac+"' -ExpectedIp '"+ip+"'")
    prepare = ("& {"+entries["Prepare-Task13ContinuationWatchdog.ps1"].decode()+"} -Run '"+cid+"' -Root '"+guest_root
               +"' -WatchdogBase64 '"+base64.b64encode(entries["Watch-Task13DiagnosticProcess.ps1"]).decode()
               +"' -ExpectedSha256 '"+sha256(entries["Watch-Task13DiagnosticProcess.ps1"])+"'")
    collect = "& {"+entries["Read-Task13ContinuationEvidence.ps1"].decode()+"} -Run '"+cid+"' -Root '"+guest_root+"'"
    scripts = {"inventory":inventory,"current":current,"guest":guest,"prepare":prepare,"collect":collect,"process_identity":process_identity,
               "workload":entries["wrapper.ps1"].decode("utf-16-le"),
               "clock_guest":"$ErrorActionPreference='Stop';@{status='CLOCK_OBSERVED';kind='guest';run_id='"+prefix.plan["run_id"]+"';utc=[DateTime]::UtcNow.ToString('o')}|ConvertTo-Json -Compress"}
    for name,source in scripts.items():
        entries["entry-"+name+".ps1"] = thin_script(source).encode("utf-8")
    entries["provider-stdin.bin"] = sql
    package = str(bundle)
    sites = management_sites(prefix.controller.HYPERVISOR_PYTHON)
    child = "import sys;sys.path[:0]="+repr([str(p) for p in sites])+";sys.path.insert(0,"+repr(package)+");from tools.canary.task13_continuation.management import main;main()"
    return {"schema":"task13_fixed_operations_v1","allowed_seq":4,"allowed_step":"compare-after-start",
            "continuation_id":cid,"guest_root":guest_root,"guest_ssh":ssh,"provider_argv":provider_argv,
            "management_argv":[prefix.controller.HYPERVISOR_PYTHON,"-I","-S","-B","-c",child],
            "management_request":{"root":str(prefix.root),"action":"state","run_id":prefix.plan["run_id"],
                                  "snapshot":prefix.plan["snapshot"],"generation":prefix.receipts[0]["initial_vm_generation"]}}


def management_sites(executable):
    require(Path(executable).parent.name == 'Python314','fixed original management interpreter')
    return [Path.home()/'AppData/Roaming/Python/Python314/site-packages',Path(executable).parent/'Lib/site-packages']
