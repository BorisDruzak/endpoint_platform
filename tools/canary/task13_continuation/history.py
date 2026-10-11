"""Verify the immutable historical prefix without granting live authorization.

Old predicates and clocks are never patched. Only sealed, pure original
snapshot/topology helpers are reused; expiry remains enforced by old executors.
"""
import os
import types
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path

from .codec import canonical, digest, instant, integer, parse_json, require, sha256, uuid

SEQUENCE = ("capture", "stop-for-snapshot", "snapshot", "start-after-snapshot")
ORIGINAL_FILES = {
    "plan.json": "bbddf13f084c6be9c7fed8fc2041df88953aabb33915ce12631eeab0f1c7fa5d",
    "run-seal.json": "6f30d2b3698498f4daa55aa2a8f1fd6e4181e3a20498c8ce8a7de4da37d74590",
    "receipt-00-capture.json": "cfee02365b325be914625d0e17155d2dcf50707158f21fc571516fc83c0f579c",
    "receipt-01-stop-for-snapshot.json": "3dfa3995369e4c2052de8d8f6f4dee878fe3596fccb386e9af758e6c641c57ed",
    "receipt-02-snapshot.json": "bab49be079688046908ae66c8e4ff0b75260b7fe3d10f11c76ca2243640ca5cb",
    "receipt-03-start-after-snapshot.json": "cdd42d87efa105f78957240838b96e0232784869d36f5335396aa341168cf4fd",
}
MANIFEST_SHA = "6abe8fc674d09f2f0d1deabc07494d54c0b2d6d16ed2fa307c269900227226cb"
BASELINE_SHA = "cdbdf079698747b2af32e7749291388099f04275e10c13995616c8d1206e1534"
SNAPSHOT_SHA = "923000023d7996498bd6ce51b822a171e626c04335c9403cd2e1f7d1e59074d5"


def read_file(path: Path, limit=64 * 1024 * 1024, *, allow_empty=False) -> bytes:
    """Nonoperational reader; native retained-handle storage strengthens live use."""
    path = Path(path)
    for ancestor in (path, *path.parents):
        stat = ancestor.lstat()
        require(not ancestor.is_symlink() and not getattr(stat, "st_file_attributes", 0) & 0x400,
                "historical reparse point")
    with path.open("rb") as stream:
        stat = os.fstat(stream.fileno())
        require(stat.st_nlink == 1 and (0 if allow_empty else 1) <= stat.st_size <= limit, "historical file bound")
        raw = stream.read(limit + 1)
        require(len(raw) == stat.st_size, "historical read changed")
        return raw


def _relative(name):
    require(type(name) is str and name and "\\" not in name and ":" not in name,
            "closure relative path")
    path = Path(name)
    require(not path.is_absolute() and all(p not in (".", "..") for p in name.split("/")),
            "closure path traversal")
    return path


def validate_original_blobs(blobs: dict[str, bytes]):
    require(set(blobs) == set(ORIGINAL_FILES), "exact four-receipt prefix required")
    for name, expected in ORIGINAL_FILES.items():
        require(sha256(blobs[name]) == expected, "original retained bytes changed")
        require(digest(parse_json(blobs[name])) == expected, "original canonical object changed")


@dataclass(frozen=True)
class HistoricalPrefix:
    root: Path
    original_blobs: tuple[tuple[str, bytes], ...]
    binding_bytes: bytes
    evidence_manifest_bytes: bytes
    controller: types.ModuleType

    @property
    def binding(self):
        return parse_json(self.binding_bytes)

    @property
    def plan(self):
        return parse_json(dict(self.original_blobs)["plan.json"])

    @property
    def seal(self):
        return parse_json(dict(self.original_blobs)["run-seal.json"])

    @property
    def receipts(self):
        return [parse_json(dict(self.original_blobs)[f"receipt-{i:02d}-{step}.json"])
                for i, step in enumerate(SEQUENCE)]

    @property
    def snapshot(self):
        return self.receipts[2]["snapshot_identity"]


def _transport(transport, plan, tag):
    require(transport["status"] == "TRANSPORT_COMPLETE"
            and transport["run_id"] == plan["run_id"] and transport["tag"] == tag,
            "historical accepted transport identity")
    require(type(transport["exit_code"]) is int and transport["exit_code"] == 0
            and type(transport["error_bytes"]) is int and transport["error_bytes"] == 0,
            "historical native transport exit")
    for key in ("stdin_confirmed", "dispatch_confirmed", "persistence_confirmed"):
        require(transport[key] is True, "historical unconfirmed transport")
    integer(transport["output_bytes"], high=262144)
    integer(transport["dispatch_mono_ns"])
    integer(transport["finished_mono_ns"], low=transport["dispatch_mono_ns"])


def verify_historical_prefix(root: Path) -> HistoricalPrefix:
    root = Path(root)
    manifest_raw = read_file(root / "source-closure-manifest.json")
    require(sha256(manifest_raw) == MANIFEST_SHA, "historical source closure changed")
    manifest = parse_json(manifest_raw)
    require(manifest["schema"] == "task13_zero_owner_recovery_source_closure_v1"
            and manifest["source_only"] is True, "original source closure schema")
    source_data = {}
    for group, field, base in (("entries", "name", root),
                              ("prerequisites", "relative_path", root.parent)):
        seen = set()
        for item in manifest[group]:
            require(set(item) == {field, "bytes", "sha256"}, "source entry schema")
            name = item[field]
            require(name.casefold() not in seen, "source closure case alias")
            seen.add(name.casefold())
            raw = read_file(base / _relative(name))
            require(len(raw) == integer(item["bytes"], low=1)
                    and sha256(raw) == item["sha256"], "original source hash/size changed")
            if group == "entries":
                source_data[name] = raw
    records = root / "zero-owner-recovery-records"
    blobs = {name: read_file(records / name) for name in ORIGINAL_FILES}
    validate_original_blobs(blobs)
    plan, seal = parse_json(blobs["plan.json"]), parse_json(blobs["run-seal.json"])
    require(seal["plan"] == plan and seal["plan_sha256"] == digest(plan), "seal plan binding")
    require(seal["baseline_sha256"] == BASELINE_SHA, "historical baseline anchor")
    uuid(plan["run_id"])
    require(plan["snapshot"] == "pre82-real81-staged-" + plan["run_id"].replace("-", "")[:16],
            "historical snapshot name")
    require(instant(plan["expires_utc"]) - instant(plan["created_utc"]) == timedelta(seconds=1200),
            "original fixed duration")
    require(integer(plan["deadline_mono_ns"]) - integer(plan["created_mono_ns"]) == 1200 * 10**9,
            "original monotonic duration")
    for name, expected in plan["helper_hashes"].items():
        require(name in source_data and sha256(source_data[name]) == expected, "original helper pin")
    controller_name = "task13_recovery_controller.draft.py"
    controller = types.ModuleType("sealed_historical_task13_controller")
    controller.__file__ = str(root / controller_name)
    exec(compile(source_data[controller_name], controller.__file__, "exec"), controller.__dict__)
    require(plan["device_id"] == controller.DEVICE and plan["vm_uuid"] == controller.UUID100,
            "original target identity")
    receipts = [parse_json(blobs[f"receipt-{i:02d}-{step}.json"]) for i, step in enumerate(SEQUENCE)]
    all_raw = {p.name: read_file(p) for p in records.glob("*.json")}
    require(len(all_raw) <= 1024, "retained evidence count bound")
    values = {name: parse_json(raw) for name, raw in all_raw.items()}
    envelopes = [(name, value) for name, value in values.items()
                 if name.endswith("-accepted-observation.json")]
    previous, last, mono = digest(seal), instant(plan["created_utc"]), plan["created_mono_ns"]
    snapshot, historical_clocks = None, 0
    initial = receipts[0]["initial_lvs"]
    generation = uuid(receipts[0]["initial_vm_generation"])
    controller.lvm_topology(initial, initial, plan["snapshot"], "INITIAL")
    identity = sorted([{k: v[k] for k in ("lv_name", "lv_uuid", "origin", "lv_size")}
                       for v in initial if v["lv_name"].startswith("vm-")], key=lambda v: v["lv_name"])
    for seq, item in enumerate(receipts):
        require(type(item["seq"]) is int and item["seq"] == seq and item["step"] == SEQUENCE[seq]
                and item["status"] == "COMPLETE" and item["run_id"] == plan["run_id"]
                and item["run_seal_sha256"] == digest(seal) and item["previous_sha256"] == previous
                and item["baseline_sha256"] == BASELINE_SHA, "historical receipt chain")
        sent, done = instant(item["dispatch_utc"]), instant(item["finished_utc"])
        require(last <= sent <= done <= instant(plan["expires_utc"]), "historical UTC chronology")
        require(mono <= integer(item["dispatch_mono_ns"]) <= integer(item["finished_mono_ns"])
                < plan["deadline_mono_ns"], "historical monotonic chronology")
        matches = [env for _, env in envelopes if digest(env["transport"]) == item["transport_sha256"]]
        require(len(matches) == 1, "unique historical transport reference")
        env = matches[0]
        transport, tag = env["transport"], env["tag"]
        _transport(transport, plan, tag)
        candidate, dispatch = values[tag + "-result.json"], values[tag + "-dispatch.json"]
        require(candidate["status"] == "OUTCOME_CANDIDATE_NOT_ACCEPTED"
                and candidate["candidate_status"] == "TRANSPORT_COMPLETE"
                and candidate["requires_supervisor_acceptance"] is True, "historical candidate schema")
        require({**candidate, "status": "TRANSPORT_COMPLETE", "persistence_confirmed": True} == transport,
                "original caller acceptance changed")
        require(all(dispatch[k] == candidate[k] for k in ("run_id", "tag", "dispatch_utc", "dispatch_mono_ns")),
                "historical dispatch identity")
        require(transport["dispatch_utc"] == item["dispatch_utc"]
                and transport["dispatch_mono_ns"] == item["dispatch_mono_ns"]
                and instant(transport["finished_utc"]) <= done
                and transport["finished_mono_ns"] <= item["finished_mono_ns"], "receipt transport bookends")
        owner_record = values["ownership-before-" + item["step"] + ".json"]
        owner_matches = [e for _, e in envelopes if e["tag"] == owner_record["tag"]]
        require(len(owner_matches) == 1, "historical ownership acceptance reference")
        expected_runtime = "FRESH_AUTHENTICATED81_OBSERVED" if seq <= 1 else "NOT_OBSERVABLE_GUEST_STOPPED"
        require(owner_record == {**owner_matches[0], "runtime_acceptance": expected_runtime},
                "historical ownership record changed")
        owner_transport = owner_record["transport"]
        _transport(owner_transport, plan, owner_record["tag"])
        owner = owner_record["observation"]
        require(owner["device_id"] == plan["device_id"] and owner["device_owners"] == []
                and type(owner["visible_recommendations"]) is int and owner["visible_recommendations"] == 0
                and owner["rollout_targets"] == [], "historical ownership predicate")
        require(0 <= (sent - instant(owner_transport["finished_utc"])).total_seconds() <= 60
                and -5 <= (sent - instant(owner["provider_utc"])).total_seconds() <= 60,
                "historical ownership freshness at dispatch")
        if seq <= 1:
            instance = owner["latest_instance"]
            require(instance["agent_version"] == instance["launcher_version"] == "3.2.81"
                    and 0 <= (instant(owner["provider_utc"]) - instant(instance["last_seen_at"])).total_seconds() <= 60,
                    "historical reachable runtime identity")
            sessions = [s for s in owner["sessions"] if s["device_instance_id"] == instance["id"]
                        and s["closed_at"] is None and instant(s["expires_at"]) > instant(owner["provider_utc"])
                        and 0 <= (instant(owner["provider_utc"]) - instant(s["last_seen_at"])).total_seconds() <= 60]
            require(len(sessions) == 1, "historical authenticated session")
        for kind, outer in item["clock_brackets"].items():
            historical = outer["status"] == "HISTORICAL_GUEST_CLOCK_NOT_FRESH"
            if historical:
                require(kind == "guest" and seq in (2, 3), "unexpected historical clock")
                bracket = outer["last_validated_bracket"]
                historical_clocks += 1
            else:
                bracket = outer
            require(bracket["status"] == "FRESH_CLOCK_BRACKET_VALIDATED", "original clock schema")
            clocks = [e for _, e in envelopes if e["observation"].get("status") == "CLOCK_OBSERVED"
                      and e["observation"].get("kind") == kind
                      and e["transport"]["dispatch_utc"] == bracket["root_dispatch_utc"]
                      and e["transport"]["finished_utc"] == bracket["root_finished_utc"]]
            require(len(clocks) == 1, "original clock reference")
            clock = clocks[0]
            _transport(clock["transport"], plan, clock["tag"])
            require(clock["observation"]["utc"] == bracket["remote_utc"], "original remote clock")
            start, end = instant(bracket["root_dispatch_utc"]), instant(bracket["root_finished_utc"])
            require(0 <= (end - start).total_seconds() <= 5
                    and start - timedelta(seconds=5) <= instant(bracket["remote_utc"])
                    <= end + timedelta(seconds=5), "original clock observation bracket")
            if not historical:
                require(0 <= (sent - end).total_seconds() <= 5, "original clock freshness at dispatch")
        if seq == 0:
            observation = env["observation"]
            require(digest(observation) == item["guest_observation_sha256"] == seal["capture_sha256"]
                    and digest(observation["native_proof"]) == seal["native_sha256"], "capture/native binding")
            require(observation["baselineSha256"] == BASELINE_SHA
                    and observation["plan_sha256"] == digest(plan)
                    and observation["run_id"] == plan["run_id"] and observation["status"] == "BASELINE_CAPTURED",
                    "original guest Facts identity")
            inventory = [e for _, e in envelopes if digest(e["observation"]) == item["inventory_sha256"]]
            require(len(inventory) == 1, "historical inventory reference")
            value = inventory[0]["observation"]
            require(value["status"] == "EXACT_RECOVERY_LEAVES" and value["run_id"] == plan["run_id"]
                    and value["directory_protected"] is True and len(value["leaves"]) == 1, "baseline inventory")
            leaf = value["leaves"][0]
            require(leaf["name"] == "baseline.json" and leaf["sha256"] == BASELINE_SHA
                    and leaf["protected"] is True and leaf["reparse"] is False
                    and type(leaf["hardlink_count"]) is int and leaf["hardlink_count"] == 1,
                    "historical baseline leaf")
            source_binding = values[tag + "-source-dispatch-binding.json"]
            require(source_binding["run_id"] == plan["run_id"]
                    and source_binding["plan_sha256"] == digest(plan)
                    and source_binding["helper_sha256"] == plan["helper_hashes"]["Invoke-Task13RecoveryGuest.draft.ps1"],
                    "retained original source-dispatch binding")
        else:
            value, proof = env["observation"], item["postcondition"]
            action = value["action"]
            require(value["status"] == "MANAGEMENT_OPERATION_COMPLETE" and value["step"] == item["step"]
                    and value["run_id"] == plan["run_id"] and action == proof["action"], "management binding")
            require(type(action["exit_code"]) is int and action["exit_code"] == 0
                    and type(action["error_bytes"]) is int and action["error_bytes"] == 0,
                    "historical management exit")
            require(value["active_before"] == value["active_after"] == [], "historical active tasks")
            before_active, after_active = value["active_before_receipt"], value["active_after_receipt"]
            require(before_active["ordinal"] < action["ordinal"] < after_active["ordinal"], "action ordinals")
            require(all(type(a["exit_code"]) is int and a["exit_code"] == 0
                        and type(a["error_bytes"]) is int and a["error_bytes"] == 0
                        for a in (before_active, after_active)), "historical active observations")
            require(value["before"]["lvs"] == proof["lvm_before"]
                    and value["after"]["lvs"] == proof["lvm_after"], "actual LVM rows")
            if seq == 2:
                snapshot = item["snapshot_identity"]
                checked = controller.snapshot_identity(snapshot["metadata"], item["saved_config"],
                    snapshot["volumes"], proof["action"]["dispatch_utc"], proof["action"]["finished_utc"])
                require(snapshot == checked and digest(snapshot) == SNAPSHOT_SHA, "historical snapshot identity")
                require(snapshot["config_sha256"] == digest(item["saved_config"]) == seal["config_sha256"]
                        and snapshot["metadata"]["name"] == plan["snapshot"]
                        and sent <= instant(snapshot["creation_dispatch_utc"])
                        <= instant(snapshot["creation_finished_utc"]) <= done, "original snapshot creation/config")
            elif snapshot is not None:
                require(item["snapshot_identity_sha256"] == digest(snapshot), "different original snapshot")
            controller.lvm_topology(proof["lvm_before"], initial, plan["snapshot"], "PRE_ROLLBACK",
                                    None if seq <= 2 else snapshot, identity)
            controller.lvm_topology(proof["lvm_after"], initial, plan["snapshot"], "PRE_ROLLBACK",
                                    snapshot if seq >= 2 else None, identity)
            require(proof["vm_generation"] == generation and proof["lvm_phase_after"] == "PRE_ROLLBACK",
                    "historical VM generation/phase")
        previous, last, mono = digest(item), done, item["finished_mono_ns"]
    provider_count = 0
    for _, env in envelopes:
        if env["tag"].startswith("provider-zero-owners") and env["transport"]["finished_mono_ns"] < mono:
            value = env["observation"]
            _transport(env["transport"], plan, env["tag"])
            require(value["migration"] == "0037_launcher_foundation" and value["device_id"] == plan["device_id"]
                    and value["device_owners"] == [] and type(value["visible_recommendations"]) is int
                    and value["visible_recommendations"] == 0 and value["rollout_targets"] == [],
                    "retained historical ownership predicates")
            provider_count += 1
    require(provider_count == 4 and previous == ORIGINAL_FILES["receipt-03-start-after-snapshot.json"],
            "full historical prefix")
    require(all(sha256(read_file(records / name)) == sha256(raw) for name, raw in all_raw.items()),
            "historical records changed during verification")
    binding = {"original_run_id": plan["run_id"], "original_plan_sha256": digest(plan),
               "original_run_seal_sha256": digest(seal), "original_tip": previous,
               "baseline_sha256": BASELINE_SHA, "snapshot_identity_sha256": SNAPSHOT_SHA,
               "verified_receipt_count": 4, "historical_guest_brackets": historical_clocks,
               "source_entries": len(manifest["entries"]), "source_prerequisites": len(manifest["prerequisites"]),
               "original_files": ORIGINAL_FILES, "raw_output_retained": False,
               "historical_evidence_sha256": digest({name: sha256(raw) for name, raw in all_raw.items()})}
    return HistoricalPrefix(root, tuple(blobs.items()), canonical(binding),
                            canonical({name: sha256(raw) for name, raw in all_raw.items()}), controller)
