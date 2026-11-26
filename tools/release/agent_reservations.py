"""Reserve a shared Windows/ALT version on an append-only Git branch."""

from __future__ import annotations

from argparse import ArgumentParser, Namespace
import ast
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from uuid import UUID


LEDGER_REF = "refs/heads/codex/agent-release-reservations"
LEDGER_FILE = "reservations.json"
VERSION = r"(?:0|[1-9][0-9]{0,4})(?:\.(?:0|[1-9][0-9]{0,4})){2}"
PACKAGE = re.compile(rf"(?P<version>{VERSION})(?:[-+][A-Za-z0-9.+~-]+)?")
NATIVE_RECORD = re.compile(rf"(?:windows|linux|alt|agent|initial-runtime)-({VERSION})(?:[-.]|$)")
SOURCE_VERSION = re.compile(rf"^[+-]\s*AGENT_VERSION\s*=\s*[\"']({VERSION})[\"']", re.MULTILINE)
PLATFORMS = ("windows", "alt", "both")
GIT_OID = re.compile(r"[0-9a-f]{40}")
ARTIFACT_SHA = re.compile(r"[0-9a-f]{64}")
PRIMARY_ARTIFACT = {"windows": "setup", "alt": "archive"}
Version = tuple[int, int, int]


def add_arguments(parser: ArgumentParser) -> None:
    parser.add_argument("--platform", required=True, choices=PLATFORMS)
    parser.add_argument("--after", required=True, help="minimum predecessor and requested version series")
    parser.add_argument("--request-id", required=True, type=UUID, help="stable operation ID for retries")
    parser.add_argument("--production-snapshot", required=True, type=Path)
    parser.add_argument("--staging-snapshot", required=True, type=Path)
    parser.add_argument("--candidate-inventory", required=True, type=Path)
    parser.add_argument("--dry-run", action="store_true", help="calculate without writing the remote ledger")


def _git(root: Path, *args: str, data: bytes | None = None) -> bytes:
    result = _run_git(root, *args, data=data)
    if result.returncode:
        raise ValueError(f"Git {args[0]} failed; check the checkout, remote access and Git identity")
    return result.stdout


def _run_git(root: Path, *args: str, data: bytes | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(root), *args], input=data, capture_output=True, timeout=60,
        env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
    )


def _version(text: str, *, wrapper: bool = False) -> Version:
    match = PACKAGE.fullmatch(text)
    if not match or (not wrapper and text != match["version"]):
        raise ValueError(f"Invalid agent version: {text!r}")
    major, minor, patch = map(int, match["version"].split("."))
    return major, minor, patch


def _format(version: Version) -> str:
    return ".".join(map(str, version))


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _remote_head(root: Path) -> str | None:
    raw = _git(root, "ls-remote", "--refs", "origin", LEDGER_REF).decode().strip()
    if not raw:
        return None
    oid, ref = raw.split("\t")
    if ref != LEDGER_REF or not GIT_OID.fullmatch(oid):
        raise ValueError("Unexpected Git reservation ref")
    return oid


def _ledger(root: Path, oid: str | None) -> list[dict]:
    if oid is None:
        return []
    _git(root, "fetch", "--no-tags", "--no-write-fetch-head", "origin", oid)
    state = json.loads(_git(root, "show", f"{oid}:{LEDGER_FILE}"))
    if type(state["schema_version"]) is not int or state["schema_version"] != 1:
        raise ValueError("Unsupported reservation ledger schema")
    entries = state["reservations"]
    if not isinstance(entries, list):
        raise ValueError("Expected a list in reservation ledger")
    versions, requests = set(), set()
    for entry in entries:
        version = _version(entry["version"])
        request_id = UUID(entry["request_id"])
        if version in versions or request_id in requests:
            raise ValueError("Duplicate version or request in reservation ledger")
        if (entry["state"] != "reserved" or entry["platform"] not in PLATFORMS
                or str(request_id) != entry["request_id"]
                or not GIT_OID.fullmatch(entry["source_revision"])):
            raise ValueError("Invalid record in reservation ledger")
        if "build_revision" in entry and not GIT_OID.fullmatch(entry["build_revision"]):
            raise ValueError("Invalid build revision in reservation ledger")
        unsigned = entry.get("alt_unsigned_build")
        if "alt_unsigned_build" in entry and (
            entry["platform"] not in ("alt", "both") or not isinstance(unsigned, dict)
            or "build_revision" not in entry
            or any(unsigned.get(key) != entry[key] for key in ("request_id", "version", "build_revision"))
            or not isinstance(unsigned.get("build_receipt_sha256"), str)
            or not ARTIFACT_SHA.fullmatch(unsigned["build_receipt_sha256"])
        ):
            raise ValueError("Invalid unsigned ALT build in reservation ledger")
        for platform, candidate in entry.get("candidates", {}).items():
            if (platform not in PRIMARY_ARTIFACT or entry["platform"] not in (platform, "both")
                    or candidate["platform"] != platform or candidate["state"] not in ("candidate", "rejected")
                    or any(candidate[key] != entry[key] for key in ("version", "request_id", "build_revision"))
                    or not ARTIFACT_SHA.fullmatch(candidate["artifacts"][PRIMARY_ARTIFACT[platform]]["sha256"])
                    or (platform == "alt" and unsigned is not None
                        and candidate.get("build_receipt_sha256") != unsigned["build_receipt_sha256"])
                    or (candidate["state"] == "rejected") != ("rejection" in candidate)):
                raise ValueError("Invalid candidate in reservation ledger")
        versions.add(version)
        requests.add(request_id)
    return entries


def _bound_request(entries: list[dict], binding: dict) -> dict | None:
    for entry in entries:
        if entry["request_id"] == binding["request_id"]:
            if any(entry[key] != value for key, value in binding.items()):
                raise ValueError("Reservation request ID is already bound to different inputs")
            return entry
    return None


def _find_request(entries: list[dict], request_id: str) -> dict:
    for entry in entries:
        if entry["request_id"] == request_id:
            return entry
    raise ValueError("Reservation request ID was not found")


def reservation_status(args: Namespace) -> dict:
    root = args.repo_root
    return _find_request(_ledger(root, _remote_head(root)), str(args.request_id))


def _observed(path: Path, now: datetime) -> tuple[dict, dict]:
    raw = path.read_bytes()
    value = json.loads(raw)
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise ValueError(f"Unsupported inventory schema: {path.name}")
    observed = datetime.fromisoformat(value["observed_at"])
    if observed.tzinfo is None or not timedelta(0) <= now - observed <= timedelta(minutes=30):
        raise ValueError(f"Inventory needs an observation from the preceding 30 minutes: {path.name}")
    return value, {"observed_at": value["observed_at"], "sha256": hashlib.sha256(raw).hexdigest()}


def _versions(values: list) -> set[Version]:
    if not isinstance(values, list):
        raise ValueError("Expected a list of occupied versions")
    return {_version(value, wrapper=True) for value in values}


def _inventories(args: Namespace) -> tuple[set[Version], set[Version], dict]:
    now = datetime.now(timezone.utc)
    production, prod_receipt = _observed(args.production_snapshot, now)
    staging, stage_receipt = _observed(args.staging_snapshot, now)
    if production == staging:
        raise ValueError("Provide separately captured production and staging snapshots")
    candidates, signed_receipt = _observed(args.candidate_inventory, now)
    floor = _versions(candidates["windows"]) | _versions(candidates["alt"])
    taken = set(floor)
    for snapshot in (production, staging):
        catalog = snapshot["occupied_versions"]
        for name in ("windows_installer", "windows_agent", "windows_full_setup", "linux_native"):
            floor.update(_versions(catalog[name]))
        if not isinstance(catalog["core"], list):
            raise ValueError("Expected a list of Core catalog entries")
        for build in catalog["core"]:
            if not build["platform"] or not build["channel"]:
                raise ValueError("Core entry requires platform and channel")
            version = _version(build["version"], wrapper=True)
            taken.add(version)
            if build["channel"] == "stable" and build["platform"] in ("windows_amd64", "linux_amd64"):
                floor.add(version)
    return floor, taken | floor, {
        "production": prod_receipt, "staging": stage_receipt, "signing_hosts": signed_receipt,
    }


def _git_versions(root: Path) -> tuple[set[Version], set[Version]]:
    if _git(root, "rev-parse", "--is-shallow-repository").strip() != b"false":
        raise ValueError("Fetch release history before reserving an agent version")
    remote_refs = _git(root, "ls-remote", "--refs", "--heads", "--tags", "origin").splitlines()
    revisions = sorted({line.split(b"\t", 1)[0] for line in remote_refs})
    if not revisions or any(not re.fullmatch(rb"[0-9a-f]{40}", oid) for oid in revisions):
        raise ValueError("Expected committed history on the release remote")
    revision_input = b"\n".join(revisions) + b"\n"
    known = _git(root, "cat-file", "--batch-check", data=revision_input)
    missing = [line.split()[0] for line in known.splitlines() if line.endswith(b" missing")]
    if missing:
        _git(root, "fetch", "--no-tags", "--no-write-fetch-head", "--refmap=", "--stdin", "origin",
             data=b"\n".join(missing) + b"\n")
    paths = _git(
        root, "log", "--all", "HEAD", "--stdin", "--format=", "--name-only", "--diff-filter=ACMR", "--",
        "docs/releases", ":(glob)packaging/windows/initial-runtime-*.json", data=revision_input,
    ).decode().splitlines()
    floor = set()
    for path in paths:
        match = NATIVE_RECORD.match(Path(path).name)
        if match:
            floor.add(_version(match[1]))
    changes = _git(
        root, "log", "--all", "HEAD", "--stdin", "--format=", "--no-color", "--no-ext-diff",
        "--no-textconv", "--unified=0", "-p", "--", "pc_agent/version.py", data=revision_input,
    ).decode()
    occupied = {_version(match) for match in SOURCE_VERSION.findall(changes)}
    return floor, occupied | floor


def _next_version(after: Version, floor: set[Version], taken: set[Version]) -> Version:
    major, minor, _ = after
    if major > 255 or minor > 255:
        raise ValueError("Requested series does not fit Windows Installer version fields")
    latest = max({after} | {version for version in floor if version[:2] == after[:2]})
    for patch in range(latest[2] + 1, 65536):
        version = major, minor, patch
        if version not in taken:
            return version
    raise ValueError("No unused version remains in the requested native release series")


def _append(root: Path, parent: str | None, entries: list[dict], action: str) -> bool:
    blob = _git(root, "hash-object", "-w", "--stdin", data=_json_bytes({
        "schema_version": 1, "reservations": entries,
    })).decode().strip()
    tree = _git(root, "mktree", data=f"100644 blob {blob}\t{LEDGER_FILE}\n".encode()).decode().strip()
    parents = ("-p", parent) if parent is not None else ()
    commit = _git(root, "commit-tree", tree, *parents, "-m", f"chore(release): {action}")
    # A concurrent append makes this a sibling commit, rejected by an ordinary push.
    pushed = _run_git(root, "push", "--porcelain", "origin", f"{commit.decode().strip()}:{LEDGER_REF}")
    return pushed.returncode == 0


def reserve(args: Namespace) -> dict:
    root = args.repo_root
    after = _version(args.after)
    binding = {
        "request_id": str(args.request_id),
        "platform": args.platform,
        "after": args.after,
        "source_revision": _git(root, "rev-parse", "--verify", "HEAD^{commit}").decode().strip(),
    }
    head = _remote_head(root)
    entries = _ledger(root, head)
    if existing := _bound_request(entries, binding):
        return existing
    floor, taken, receipts = _inventories(args)
    git_floor, git_taken = _git_versions(root)
    for _ in range(8):
        reserved = {_version(entry["version"]) for entry in entries}
        version = _next_version(after, floor | git_floor | reserved, taken | git_taken | reserved)
        record = {
            **binding, "version": _format(version), "state": "proposed" if args.dry_run else "reserved",
            "ledger_ref": LEDGER_REF, "inventories": receipts,
        }
        if args.dry_run:
            return record
        record["reserved_at"] = datetime.now(timezone.utc).isoformat()
        if _append(root, head, [*entries, record], "reserve agent version"):
            return record
        current = _remote_head(root)
        if current == head:
            raise ValueError("Git rejected the reservation; retry with the same request ID")
        head = current
        entries = _ledger(root, head)
        if existing := _bound_request(entries, binding):
            return existing
    raise ValueError("Reservation ledger is busy; retry with the same request ID")


def bind_source(args: Namespace) -> dict:
    """Pin the single build commit allowed by an existing reservation."""
    root = args.repo_root
    if _git(root, "status", "--porcelain", "--untracked-files=all").strip():
        raise ValueError("Bind the build source from a clean checkout")
    revision = _git(root, "rev-parse", "--verify", "HEAD^{commit}").decode().strip()
    version_file = _git(root, "show", f"{revision}:pc_agent/version.py")
    assignments = [
        node.value
        for node in ast.parse(version_file).body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "AGENT_VERSION" for target in node.targets)
    ]
    if len(assignments) != 1 or not isinstance(assignments[0], ast.Constant):
        raise ValueError("Expected one literal AGENT_VERSION in the build revision")
    if not isinstance(assignments[0].value, str):
        raise ValueError("AGENT_VERSION must be a string")

    request_id = str(args.request_id)
    for _ in range(8):
        head = _remote_head(root)
        entries = _ledger(root, head)
        reserved = _find_request(entries, request_id)
        if "build_revision" in reserved:
            if reserved["build_revision"] != revision:
                raise ValueError("Reservation is already bound to a different build revision")
            return reserved
        if assignments[0].value != reserved["version"]:
            raise ValueError("Build revision AGENT_VERSION differs from the reserved version")
        ancestor = _run_git(root, "merge-base", "--is-ancestor", reserved["source_revision"], revision)
        if ancestor.returncode != 0:
            raise ValueError("Build revision must descend from the reserved source revision")
        bound = {**reserved, "build_revision": revision, "bound_at": datetime.now(timezone.utc).isoformat()}
        updated = [bound if entry is reserved else entry for entry in entries]
        if _append(root, head, updated, "bind agent build source"):
            return bound
        if _remote_head(root) == head:
            raise ValueError("Git rejected the binding; retry with the same request ID")
    raise ValueError("Reservation ledger is busy; retry with the same request ID")


def _with_candidate(entries: list[dict], reserved: dict, candidate: dict) -> list[dict]:
    updated = {**reserved, "candidates": {**reserved.get("candidates", {}), candidate["platform"]: candidate}}
    return [updated if entry is reserved else entry for entry in entries]


def record_alt_build(args: Namespace) -> dict:
    """Record the verified unsigned build for one reservation before handoff."""
    from tools.release.agent_candidate_artifacts import MAX_METADATA, _fingerprint
    from tools.release.agent_qualification import inspect_unsigned_alt_build

    root, request_id = args.repo_root, str(args.request_id)
    digest = _fingerprint(args.build_receipt, MAX_METADATA)["sha256"]
    proof = None
    for _ in range(8):
        head = _remote_head(root)
        entries = _ledger(root, head)
        reserved = _find_request(entries, request_id)
        if reserved["platform"] not in ("alt", "both") or "build_revision" not in reserved:
            raise ValueError("Bind the ALT build source before recording its receipt")
        binding = {key: reserved[key] for key in ("request_id", "version", "build_revision")}
        if proof is not None and any(proof[key] != value for key, value in binding.items()):
            raise ValueError("Reservation changed while checking the unsigned ALT build")
        if existing := reserved.get("alt_unsigned_build"):
            if existing["build_receipt_sha256"] != digest:
                raise ValueError("Different ALT build receipt is already recorded")
            return existing
        if "alt" in reserved.get("candidates", {}):
            raise ValueError("This ALT candidate was recorded without an unsigned build entry")
        if proof is None:
            if inspect_unsigned_alt_build(args.build_receipt, binding) != digest:
                raise ValueError("ALT build receipt changed during verification")
            proof = {**binding, "build_receipt_sha256": digest,
                     "recorded_at": datetime.now(timezone.utc).isoformat()}
        updated = {**reserved, "alt_unsigned_build": proof}
        if _append(root, head, [updated if entry is reserved else entry for entry in entries],
                   "record unsigned ALT agent build"):
            return proof
        if _remote_head(root) == head:
            raise ValueError("Git rejected the ALT build receipt; retry with the same request ID")
    raise ValueError("Reservation ledger is busy; retry with the same request ID")


def record_candidate(args: Namespace) -> dict:
    """Record one immutable artifact set for a platform of the bound build."""
    from tools.release.agent_candidate_artifacts import MAX_METADATA, _fingerprint, inspect_candidate

    root, request_id = args.repo_root, str(args.request_id)
    receipt = getattr(args, "build_receipt", None)
    if receipt is not None and args.platform != "alt":
        raise ValueError("The build receipt option is only for ALT native candidates")
    proof = None
    for _ in range(8):
        head = _remote_head(root)
        entries = _ledger(root, head)
        reserved = _find_request(entries, request_id)
        if reserved["platform"] not in (args.platform, "both"):
            raise ValueError("Platform is outside the reservation")
        if "build_revision" not in reserved:
            raise ValueError("Bind the build source before recording artifacts")
        binding = {key: reserved[key] for key in ("request_id", "version", "build_revision")}
        if proof is None:
            proof = {**binding, "platform": args.platform, "evidence": "artifact_fingerprints",
                     **inspect_candidate(args, reserved)}
        elif any(proof[key] != value for key, value in binding.items()):
            raise ValueError("Reservation changed while checking candidate artifacts")
        candidates = reserved.get("candidates", {})
        if args.platform in candidates:
            existing = candidates[args.platform]
            if any(existing.get(key) != value for key, value in proof.items()):
                raise ValueError("Different artifacts are already recorded for this platform")
            if receipt is not None and "build_receipt_sha256" not in proof:
                if _fingerprint(receipt, MAX_METADATA)["sha256"] != existing.get("build_receipt_sha256"):
                    raise ValueError("ALT build receipt differs from the recorded receipt")
            return existing
        if args.platform == "alt":
            from tools.release.agent_alt_native import verify_candidate_handoff

            if receipt is None:
                raise ValueError("Recording a new ALT candidate requires its qualification build receipt")
            unsigned = reserved.get("alt_unsigned_build")
            if unsigned is None:
                raise ValueError("Record the unsigned ALT build before recording its signed candidate")
            expected = unsigned["build_receipt_sha256"]
            if "build_receipt_sha256" not in proof:
                if _fingerprint(receipt, MAX_METADATA)["sha256"] != expected:
                    raise ValueError("ALT build receipt differs from the recorded unsigned build")
                proof["build_receipt_sha256"] = verify_candidate_handoff(args, proof)
            if proof["build_receipt_sha256"] != expected:
                raise ValueError("ALT build receipt differs from the recorded unsigned build")
        recorded = {**proof, "state": "candidate", "recorded_at": datetime.now(timezone.utc).isoformat()}
        if _append(root, head, _with_candidate(entries, reserved, recorded),
                   f"record {args.platform} agent candidate"):
            return recorded
        if _remote_head(root) == head:
            raise ValueError("Git rejected the candidate record; retry with the same request ID")
    raise ValueError("Reservation ledger is busy; retry with the same request ID")


def reject_candidate(args: Namespace) -> dict:
    """Record an operator rejection without drawing conclusions about exposure."""
    from endpoint_contracts.update_safety import validate_public_update_prose

    digest = args.sha256.lower()
    if not ARTIFACT_SHA.fullmatch(digest):
        raise ValueError("Reject requires the exact SHA-256 digest")
    reason = validate_public_update_prose(args.reason, field_name="reason", max_length=256, required=True)
    root, request_id = args.repo_root, str(args.request_id)
    for _ in range(8):
        head = _remote_head(root)
        entries = _ledger(root, head)
        reserved = _find_request(entries, request_id)
        candidate = reserved.get("candidates", {}).get(args.platform)
        if candidate is None:
            raise ValueError("Record the platform candidate before rejecting it")
        if candidate["artifacts"][PRIMARY_ARTIFACT[args.platform]]["sha256"] != digest:
            raise ValueError("Requested digest differs from the recorded candidate")
        if candidate["state"] == "rejected":
            if candidate["rejection"]["reason"] != reason:
                raise ValueError("Candidate already rejected with a different reason")
            return candidate
        if candidate["state"] != "candidate":
            raise ValueError("Rejection requires a recorded candidate")
        rejected = {**candidate, "state": "rejected", "rejection": {
            "reason": reason, "rejected_at": datetime.now(timezone.utc).isoformat(),
        }}
        if _append(root, head, _with_candidate(entries, reserved, rejected),
                   f"reject {args.platform} agent candidate"):
            return rejected
        if _remote_head(root) == head:
            raise ValueError("Git rejected the lifecycle record; retry with the same request ID")
    raise ValueError("Reservation ledger is busy; retry with the same request ID")
