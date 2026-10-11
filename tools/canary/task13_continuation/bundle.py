"""Offline protected execution bundle. Preparation never contacts a target."""
import json
import subprocess
import shlex
import sys
from pathlib import Path
from uuid import uuid4

from .codec import canonical, digest, require, sha256
from .history import verify_historical_prefix, read_file
from .operations import build_operations, management_sites
from .sources import build_execution_sources, seal_sources, CANARY
from .storage import ProtectedStore
from .permission import capture_permission,capture_execution_permission
from .recovery import capture_recovery
from . import windows


def runtime_sources(base, *, management=False, sites=None):
    base=Path(base)
    paths=set(base.glob('*.dll'))
    paths.update(p for p in (base/'Lib').rglob('*') if p.is_file()
                 and 'site-packages' not in p.parts and p.suffix.lower() in ('.py','.pyd','.dll','.zip'))
    paths.update((base/'DLLs').glob('*.pyd'));paths.update((base/'DLLs').glob('*.dll'))
    if management:
        for site in sites or [base/'Lib/site-packages']:
            for name in ('paramiko','bcrypt','cryptography','nacl','cffi','pycparser','invoke','yaml'):
                paths.update(p for p in (site/name).rglob('*') if p.is_file() and p.suffix.lower() in ('.py','.pyd','.dll','.zip'))
            paths.update(site.glob('_cffi_backend*.pyd'))
            paths.update(site.glob('argparse.py'))
    return paths


def prepare_bundle(original_root, root, *, separate_seq04=False,readonly_recovery=False):
    require(type(separate_seq04) is bool and type(readonly_recovery) is bool,'explicit separate step selector')
    require(not (readonly_recovery and separate_seq04),'read-only recovery forbids seq04')
    prefix = verify_historical_prefix(original_root)
    request=capture_execution_permission(prefix) if separate_seq04 else capture_permission()
    require(readonly_recovery==(request['scope']=='readonly-unknown-recovery'),'explicit read-only recovery request required')
    if readonly_recovery:
        from .readonly_recovery import capture_readonly_recovery
        recovery=capture_readonly_recovery(prefix)
    else:recovery = capture_recovery(prefix)
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
                                         "claim_home":str(claims.absolute()),"original_binding":prefix.binding,
                                         "root_interpreter":str(Path(sys._base_executable).absolute())})
    entries["operator-request.json"] = canonical(request)
    if separate_seq04:
        from .gate_admission import capture_gate
        entries['gate-admission.json']=canonical(capture_gate(prefix))
    entries["recovery.json"] = canonical(recovery)
    entries["original-source-closure.json"] = read_file(prefix.root/"source-closure-manifest.json")
    bootstrap = ("import sys\nfrom pathlib import Path\nROOT=Path("+repr(str(store.root))+ ")\n"
                 "if not (sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode): raise SystemExit('isolated no-site bytecode-free startup required')\n"
                 "sys.dont_write_bytecode=True\nsys.pycache_prefix=str(ROOT/'no-pyc')\nsys.path.insert(0,str(ROOT))\n"
                 "from tools.canary.task13_continuation.loader import bootstrap_entry\n"
                 "if __name__=='__main__': bootstrap_entry(ROOT)\n")
    entries["bootstrap.py"] = bootstrap.encode()
    # Pin both interpreters and their Python/native library implementations.
    discovery = "import json,sys;print(json.dumps({'base':sys.base_prefix,'executable':sys.executable}))"
    second = json.loads(subprocess.run([prefix.controller.HYPERVISOR_PYTHON,"-I","-S","-B","-c",discovery],
                                      capture_output=True,check=True,timeout=10).stdout)
    runtime_paths = {Path(sys.executable).absolute(),Path(sys._base_executable).absolute(),Path(second["executable"]).absolute()}
    system_paths = windows.system_core_paths()
    require(Path(operations["guest_ssh"][0]).absolute() in system_paths
            and Path(operations["provider_argv"][0]).absolute() in system_paths,"canonical installed SSH binary")
    runtime_paths.update(system_paths)
    runtime_paths.update(runtime_sources(sys.base_prefix))
    sites=management_sites(second['executable'])
    runtime_paths.update(runtime_sources(second['base'],management=True,sites=sites))
    venv_config=Path(sys.executable).parent.parent/'pyvenv.cfg'
    if venv_config.exists(): runtime_paths.add(venv_config)
    # Confirm every loaded Paramiko dependency resolves inside the pinned set;
    # -S avoids any unrelated .pth/sitecustomize execution before this check.
    dependency_probe = ("import sys,json;sys.path[:0]="+repr([str(p) for p in sites])+";import paramiko;"
                        "print(json.dumps({'version':paramiko.__version__,'files':[m.__file__ for m in sys.modules.values() if getattr(m,'__file__',None)]}))")
    dependencies=json.loads(subprocess.run([second['executable'],'-I','-S','-B','-c',dependency_probe],capture_output=True,check=True,timeout=10).stdout)
    require(dependencies['version']=='4.0.0','reviewed Paramiko version')
    require(all(Path(name).absolute() in runtime_paths for name in dependencies['files'] if not name.startswith('<')),
            'management import outside closed runtime')
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
