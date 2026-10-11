"""Pure current-state predicates, using sealed original read-only guards."""
import ast
import hashlib
import re
from datetime import datetime, timedelta, timezone

from .codec import digest, instant, require, sha256, parse_json
from .history import read_file, MANIFEST_SHA

CONSTITUENTS = {"management", "provider", "guest", "inventory", "clock_guest", "clock_management"}


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


def validate_state(prefix, capsule, state, at):
    from .receipt import observation
    require(state["schema"] == "task13_reconciled_state_v1" and state["original"] == prefix.binding
            and state["status"] == "PASS" and state["predicate_version"] == "task13_readonly_reconciliation_v1"
            and set(state["constituents"]) == CONSTITUENTS
            and state["constituent_sha256"] == digest(state["constituents"]), "complete live reconciliation")
    rows = {name:observation(envelope,capsule,maximum=60) for name,envelope in state["constituents"].items()}
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
    guest = rows["guest"]
    require(guest["run_id"] == plan["run_id"] and guest["plan_sha256"] == prefix.binding["original_plan_sha256"]
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
