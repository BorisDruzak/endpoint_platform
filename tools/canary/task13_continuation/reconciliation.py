"""Pure current-state predicates, using sealed original read-only guards."""
import ast
import hashlib
import re
import types
from types import SimpleNamespace
from datetime import datetime, timedelta, timezone

from .codec import digest, instant, require, sha256, parse_json
from .history import read_file, MANIFEST_SHA
from .process_identity import identity_states

CONSTITUENTS = {"management", "provider", "guest", "inventory", "current", "clock_guest", "clock_management", "process_identity"}


def dispatch_freshness(state):
    """Preparse validated brackets; final check performs no I/O or source parsing."""
    finished=tuple(instant(row['finished_utc']) for row in state['constituents'].values())
    clocks=tuple(instant(state['constituents']['clock_'+kind]['finished_utc']) for kind in ('guest','management'))
    provider=instant(state['constituents']['provider']['observation']['provider_utc'])
    def check(at):
        now=instant(at)
        require(all(0<=(now-value).total_seconds()<=60 for value in finished),'stale dispatch constituent')
        require(all(0<=(now-value).total_seconds()<=5 for value in clocks),'stale dispatch clock')
        require(-5<=(now-provider).total_seconds()<=60,'stale dispatch owner observation')
    return check


def guards(prefix):
    manifest_raw = read_file(prefix.root / "source-closure-manifest.json")
    require(sha256(manifest_raw) == MANIFEST_SHA, "sealed guard manifest")
    name = "task13_zero_owner_recovery_runner.py"
    entry = next(v for v in parse_json(manifest_raw)["entries"] if v["name"] == name)
    raw = read_file(prefix.root / name)
    require(sha256(raw) == entry["sha256"] and len(raw) == entry["bytes"], "original guard source")
    names = {"require", "transport_complete", "owners_guard", "reachable_runtime_guard", "inventory_guard", "clock_guard"}
    tree = ast.parse(raw)
    selected = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
    require({node.name for node in selected} == names, "fixed pure original guard set")
    namespace = {"datetime":datetime, "timedelta":timedelta, "timezone":timezone, "re":re, "hashlib":hashlib}
    exec(compile(ast.Module(body=selected,type_ignores=[]), name, "exec"), namespace)
    return namespace


def legacy(envelope, run_id, tag):
    # Raw-bound transport has already been checked, these fields describe that proof.
    return {"tag":tag, "observation":envelope["observation"], "transport":{
        **envelope, "run_id":run_id, "tag":tag, "error_bytes":0,
        "output_bytes":len(__import__("base64").b64decode(envelope["stdout_b64"])),
        "dispatch_confirmed":True,"persistence_confirmed":True}}


def validate_current(prefix, envelope, identity=None):
    manifest_raw = read_file(prefix.root/"source-closure-manifest.json")
    require(sha256(manifest_raw) == MANIFEST_SHA,"current validator closure")
    specs = {v["name"]:v for v in parse_json(manifest_raw)["entries"]}
    name = "task13_zero_owner_recovery_adapter.py"
    raw = read_file(prefix.root/name)
    require(sha256(raw) == specs[name]["sha256"],"current validator source")
    tree = ast.parse(raw)
    klass = next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name == "FixedAdapter")
    method = next(n for n in klass.body if isinstance(n,ast.FunctionDef) and n.name == "current_quiescence")
    index = next(i for i,n in enumerate(method.body) if isinstance(n,ast.Assign)
                 and isinstance(n.targets[0],ast.Name) and n.targets[0].id == "result")
    body = method.body[index+1:]
    require(isinstance(body[-1],ast.Expr) and isinstance(body[-1].value,ast.Call)
            and isinstance(body[-1].value.func,ast.Attribute) and body[-1].value.func.attr == "persist",
            "fixed current predicate-only boundary")
    function = ast.FunctionDef(name="validate_only",args=ast.arguments(posonlyargs=[],args=[ast.arg(arg=n) for n in ("self","result","plan")],
                          kwonlyargs=[],kw_defaults=[],defaults=[]),body=body[:-1],decorator_list=[],returns=None,type_params=[])
    selected = [n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in {"sealed","require"}]
    namespace = {"ast":ast,"types":types,"timedelta":timedelta,"hashlib":hashlib}
    if identity is not None:
        states=identity_states(prefix,identity)
        def identity_admit(row):
            state=states.get(row['pid'],'IDENTITY_UNKNOWN')
            return ((state=='PROCESS_ABSENT' and row['present'] is False)
                    or (state=='PID_REUSED' and row['present'] is True))
        namespace['identity_admit']=identity_admit
        expected=ast.dump(ast.parse("row['present'] is False",mode='eval').body)
        class PresenceCorrection(ast.NodeTransformer):
            count=0
            def visit_For(self,node):
                iterator=node.iter
                if (isinstance(iterator,ast.Call) and isinstance(iterator.func,ast.Name) and iterator.func.id=='zip'
                    and len(iterator.args)==2 and isinstance(iterator.args[0],ast.Subscript)
                    and isinstance(iterator.args[0].value,ast.Name) and iterator.args[0].value.id=='value'
                    and isinstance(iterator.args[0].slice,ast.Constant) and iterator.args[0].slice.value in ('known','pair')):
                    return self.generic_visit(node)
                return node
            def visit_Compare(self,node):
                if ast.dump(node)==expected:
                    self.count+=1
                    return ast.copy_location(ast.Call(func=ast.Name(id='identity_admit',ctx=ast.Load()),args=[ast.Name(id='row',ctx=ast.Load())],keywords=[]),node)
                return self.generic_visit(node)
        correction=PresenceCorrection()
        loops=[node for node in function.body if isinstance(node,ast.For)
               and isinstance(node.iter,ast.Call) and isinstance(node.iter.func,ast.Name)
               and node.iter.func.id=='zip']
        require(len(loops)==2,'exact sealed known/pair loops')
        for node in loops:correction.visit(node)
        require(correction.count==2,'exact two sealed PID presence predicates: '+str(correction.count))
    module = ast.fix_missing_locations(ast.Module(body=[*selected,function],type_ignores=[]))
    exec(compile(module,"sealed_current_predicates","exec"),namespace)
    holder = SimpleNamespace(root=prefix.root,c=prefix.controller,pins={k:v["sha256"] for k,v in specs.items()})
    namespace["validate_only"](holder,legacy(envelope,prefix.plan["run_id"],"current"),prefix.plan)


def validate_state(prefix, capsule, state, at):
    from .receipt import observation
    require(state["schema"] == "task13_reconciled_state_v1" and state["original"] == prefix.binding
            and state["status"] == "PASS" and state["predicate_version"] == "task13_readonly_reconciliation_v1"
            and set(state["constituents"]) == CONSTITUENTS
            and state["constituent_sha256"] == digest(state["constituents"]), "complete live reconciliation")
    rows = {name:observation(envelope,capsule,maximum=60) for name,envelope in state["constituents"].items()}
    identity_envelope=state['constituents']['process_identity']
    identity_utc=instant(rows['process_identity']['utc'])
    require(instant(identity_envelope['dispatch_utc'])-timedelta(seconds=5)<=identity_utc
            <=instant(identity_envelope['finished_utc'])+timedelta(seconds=5),'identity observation clock bracket')
    c, g, plan = prefix.controller, guards(prefix), prefix.plan
    now = instant(at)
    for name,envelope in state["constituents"].items():
        require(0 <= (now-instant(envelope["finished_utc"])).total_seconds() <= 60, "stale reconciliation constituent")
    for kind in ("guest","management"):
        envelope = legacy(state["constituents"]["clock_"+kind],plan["run_id"],"clock-"+kind)
        g["clock_guard"](c,envelope,kind,plan["run_id"],at)
    provider = legacy(state["constituents"]["provider"],plan["run_id"],"provider")
    g["owners_guard"](c,provider,plan["run_id"],at)
    g["reachable_runtime_guard"](c,provider["observation"])
    g["inventory_guard"](rows["inventory"],plan,prefix.binding["baseline_sha256"])
    validate_current(prefix,state["constituents"]["current"],rows['process_identity'])
    guest = rows["guest"]
    require(guest["run_id"] == plan["run_id"] and guest["plan_sha256"] == prefix.binding["original_plan_sha256"]
            and guest["vm_uuid"] == plan["vm_uuid"] and guest["device_id"] == plan["device_id"]
            and type(guest["network_matches"]) is int and guest["network_matches"] == 1
            and guest["status"] == "QUIESCENT_NATIVE81_OBSERVED" and guest["service_state"] == "Running"
            and guest["current"] == "versions/3.2.81" and guest["update_owners"] == []
            and guest["msi_in_progress"] is False and guest["msiexec"] == []
            and guest["baseline_sha256"] == prefix.binding["baseline_sha256"] and guest["marker_absent"] is True,
            "current SCM/MSI/update/baseline predicates")
    management = rows["management"]
    require(management["status"] == "CONTINUATION_MANAGEMENT_OBSERVED"
            and management["run_id"] == plan["run_id"] and management["active_tasks"] == []
            and management["state"]["status"].strip() == "status: running", "current VM/task predicates")
    initial = prefix.receipts[0]["initial_lvs"]
    identity = sorted([{k:v[k] for k in ("lv_name","lv_uuid","origin","lv_size")}
                       for v in initial if v["lv_name"].startswith("vm-")],key=lambda v:v["lv_name"])
    require(management["state"]["config"]["vmgenid"] == prefix.receipts[0]["initial_vm_generation"], "VM generation changed")
    c.lvm_topology(management["state"]["lvs"],initial,plan["snapshot"],"PRE_ROLLBACK",prefix.snapshot,identity)
    snapshot = c.snapshot_identity(management["metadata"],management["saved_config_normalized"],
        management["volumes"],prefix.snapshot["creation_dispatch_utc"],prefix.snapshot["creation_finished_utc"])
    require(snapshot == prefix.snapshot and digest(snapshot) == prefix.binding["snapshot_identity_sha256"], "snapshot identity changed")
