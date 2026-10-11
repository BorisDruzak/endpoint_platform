"""Offline protected execution bundle. Preparation never contacts a target."""
import json
import subprocess
import shlex
import sys
from pathlib import Path
from uuid import uuid4

from .codec import canonical, digest, require, sha256
from .history import verify_historical_prefix, read_file
from .operations import build_operations
from .sources import build_execution_sources, seal_sources, CANARY
from .storage import ProtectedStore
from .permission import capture_permission
from . import windows


def prepare_bundle(original_root, root):
    prefix = verify_historical_prefix(original_root)
    store = ProtectedStore.create_root(root)
    cid = str(uuid4())
    entries = build_execution_sources(prefix,cid,"C:\\Task13Continuation-"+cid.replace("-",""))
    for component in ("tools","tools/canary","tools/canary/task13_continuation"):
        ProtectedStore.create_root(store.root/component)
    for folder in ("tools","tools/canary"):
        entries[folder+"/__init__.py"] = b'"""Protected continuation bundle namespace."""\n'
    for path in sorted(Path(__file__).parent.glob("*.py")):
        entries["tools/canary/task13_continuation/"+path.name] = read_file(path)
    operations = build_operations(prefix,cid,entries,store.root)
    operations["management_argv"][1:1] = ["-X","pycache_prefix="+str(store.root/"no-pyc")]
    entries["operations.json"] = canonical(operations)
    claims = prefix.root/"continuation-v1-claims"
    entries["control.json"] = canonical({"schema":"task13_bootstrap_control_v1","original_root":str(prefix.root.absolute()),
                                         "claim_home":str(claims.absolute()),"original_binding":prefix.binding})
    entries["operator-request.json"] = canonical(capture_permission())
    entries["original-source-closure.json"] = read_file(prefix.root/"source-closure-manifest.json")
    bootstrap = ("import sys\nfrom pathlib import Path\nROOT=Path("+repr(str(store.root))+ ")\n"
                 "sys.dont_write_bytecode=True\nsys.pycache_prefix=str(ROOT/'no-pyc')\nsys.path.insert(0,str(ROOT))\n"
                 "from tools.canary.task13_continuation.loader import bootstrap_entry\n"
                 "if __name__=='__main__': bootstrap_entry(ROOT)\n")
    entries["bootstrap.py"] = bootstrap.encode()
    # Pin both interpreters and their Python/native library implementations.
    discovery = "import json,sys;print(json.dumps({'base':sys.base_prefix,'executable':sys.executable}))"
    second = json.loads(subprocess.run([prefix.controller.HYPERVISOR_PYTHON,"-I","-B","-c",discovery],
                                      capture_output=True,check=True,timeout=10).stdout)
    runtime_paths = {Path(sys.executable).absolute(),Path(second["executable"]).absolute()}
    system_paths = windows.system_core_paths()
    require(Path(operations["guest_ssh"][0]).absolute() in system_paths
            and Path(operations["provider_argv"][0]).absolute() in system_paths,"canonical installed SSH binary")
    runtime_paths.update(system_paths)
    for base in {Path(sys.base_prefix),Path(second["base"])}:
        runtime_paths.update(base.glob("*.dll"))
        runtime_paths.update(path for path in (base/"Lib").rglob("*")
                             if path.is_file() and path.suffix.lower() in (".py",".pyd",".dll",".zip"))
        runtime_paths.update((base/"DLLs").glob("*.pyd"))
        runtime_paths.update((base/"DLLs").glob("*.dll"))
    runtime_paths.add(Path.home()/".ssh/known_hosts")
    config = Path.home()/".ssh/config"
    pending,seen = [config],set()
    while pending:
        path = pending.pop().absolute()
        if path in seen:
            continue
        seen.add(path);runtime_paths.add(path)
        text = read_file(path).decode("utf-8-sig")
        for line in text.splitlines():
            fields = shlex.split(line,comments=True)
            if not fields:
                continue
            if fields[0].casefold() == "include":
                for pattern in fields[1:]:
                    pattern_path = Path(pattern).expanduser()
                    if not pattern_path.is_absolute(): pattern_path = config.parent/pattern_path
                    matches = list(pattern_path.parent.glob(pattern_path.name))
                    require(matches,"SSH include must resolve")
                    pending.extend(matches)
            require(not (fields[0].casefold() == "match" and "exec" in [v.casefold() for v in fields[1:]]),
                    "dynamic SSH Match exec requires separately closed transport")
    runtime = {}
    for path in sorted(runtime_paths):
        links = path.stat().st_nlink if path in system_paths else 1
        with windows.retained(path,security=False,expected_links=links) as handle:
            raw = windows.read_handle(handle,path,expected_links=links)
        runtime[str(path)] = {"bytes":len(raw),"sha256":sha256(raw),"hardlink_count":links}
    closure = {"schema":"task13_reviewed_closure_v1","continuation_id":cid,
               "execution":seal_sources(entries),"runtime":runtime,"original_binding":prefix.binding}
    for name,raw in entries.items():
        target = store.root/Path(name)
        ProtectedStore(target.parent).create(target.name,raw)
    store.create("closure.json",canonical(closure))
    # The independent reviewer writes review.json and trust.json after inspecting
    # these exact bytes. No self-issued PASS exists and no execute flag is set.
    return {"continuation_id":cid,"source_closure_sha256":digest(closure),"entries":len(entries),
            "runtime_files":len(runtime),"root":str(store.root)}
