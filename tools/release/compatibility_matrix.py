"""Plan native Windows and ALT tests from read-only provider observations."""

from argparse import ArgumentParser
from collections import Counter
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
from uuid import UUID


VERSION = re.compile(r"(?:0|[1-9][0-9]{0,4})(?:\.(?:0|[1-9][0-9]{0,4})){2}")
SHA256 = re.compile(r"[0-9a-f]{64}")
GIT_SHA = re.compile(r"[0-9a-f]{40}")
ALT_RPM_DIGESTS = ("core_rpm_sha256", "user_sensor_rpm_sha256")
ALT_NATIVE_IDENTITY = ("version", "source_revision", *ALT_RPM_DIGESTS)
NATIVE_CONTRACT = {"windows": "endpoint_installation_event_v1", "alt": "endpoint_linux_installation_event_v1"}
INSTANCE_PLATFORM = {"windows": "windows_amd64", "alt": "linux_amd64"}
PROFILE_FIELDS = ("os_name", "os_build", "os_edition", "architecture", "core_version", "foundation_version",
                  "setup_client_version", "support_version", "state_schema", "acl_profile", "local_transaction")
INVENTORY_FIELDS = ("observed_at", "os_name", "os_version", "os_build", "os_edition", "architecture")
RUNTIME_FIELDS = ("core_version", "foundation_version", "setup_client_version", "support_version")
ROUTE_STEPS = {"direct": 0, "observer_bootstrap": 1, "legacy_bridge_return": 2}


def _observed_at(record, now):
    timestamp = datetime.fromisoformat(record["observed_at"])
    if timestamp.tzinfo is None or not -timedelta(seconds=30) <= now - timestamp <= timedelta(minutes=30):
        raise ValueError("Use an observation from the preceding 30 minutes")
    return timestamp


def _array(record, key):
    value = record[key]
    if not isinstance(value, (list, tuple)) or any(not isinstance(row, dict) for row in value):
        raise ValueError(f"Expected an array of objects in {key}")
    return value


def _by_device(rows):
    result = {}
    for row in rows:
        key = row["device_id"]
        if not isinstance(key, str) or not key or key in result:
            raise ValueError("Device evidence requires a unique device ID")
        result[key] = row
    return result


def _relevant(row, platform):
    system, contract = row["platform"], row["native_contract"]
    if contract is None:
        os_name = ((row.get("inventory") or {}).get("os_name") or "").casefold()
        deb = row.get("enrollment_package_kind") == "deb" or os_name.split(" ", 1)[0] in ("ubuntu", "debian")
        if deb:
            return False
        if os_name.startswith("windows") or os_name.startswith("alt"):
            observed = "windows" if os_name.startswith("windows") else "alt"
            return observed == platform
    # Retain ambiguous cards in each applicable platform plan until resolved.
    return (system == INSTANCE_PLATFORM[platform] or contract == NATIVE_CONTRACT[platform]
            or (system is None and contract is None))


def _known_native(row, platform):
    if (row["installation_state"] != "installed" or row["native_contract"] != NATIVE_CONTRACT[platform]
            or row["native"] is None):
        return False
    native = row["native"]
    package_keys = ("msi_sha256",) if platform == "windows" else ALT_RPM_DIGESTS
    return (VERSION.fullmatch(native.get("version") or "") and GIT_SHA.fullmatch(native.get("source_revision") or "")
            and all(SHA256.fullmatch(native.get(key) or "") for key in package_keys))


def _matches_profile(observation, row):
    if observation is None or not row.get("native_event_id") or observation["native_event_id"] != row["native_event_id"]:
        return None
    profile = observation["profile"]
    if not all(isinstance(profile.get(field), str) and profile[field].strip().lower() not in ("", "unknown")
               for field in PROFILE_FIELDS):
        return None
    if any(row.get(field) and row[field] != profile[field] for field in RUNTIME_FIELDS):
        return None
    return {key: profile[key] for key in PROFILE_FIELDS}


def _inventory_conflicts(profile, inventory, platform):
    observed = {field: value.strip().casefold() for field in INVENTORY_FIELDS[1:]
                if isinstance(value := inventory.get(field), str) and value.strip().casefold() not in ("", "unknown")}
    conflicts = [field for field in ("os_edition", "architecture")
                 if field in observed and observed[field] != profile[field].strip().casefold()]
    if "os_name" in observed and any(name.split()[0] != platform for name in (
            observed["os_name"], profile["os_name"].strip().casefold())):
        conflicts.append("os_name")
    build = profile["os_build"].strip().casefold()
    if platform == "windows":
        major_build = observed.get("os_build")
        if major_build and build != major_build and not build.startswith(major_build + "."):
            conflicts.append("os_build")
    elif (version := observed.get("os_version")) and build != version:
        conflicts.append("os_build")
    return conflicts


def _partial_profile(row):
    inventory = {field: value for field in INVENTORY_FIELDS
                 if (value := (row.get("inventory") or {}).get(field))}
    observed = {field: row[field] for field in (*RUNTIME_FIELDS, "launcher_version") if row.get(field)}
    if inventory:
        observed["inventory"] = inventory
    if row.get("packages"):
        observed["packages"] = row["packages"]
    missing = [field for field in PROFILE_FIELDS if not (observed.get(field) or inventory.get(field))]
    return observed, missing


def _case(row, target, decision, evidence):
    platform = target["platform"]
    case = {"device_id": row["device_id"], "source": row["native"],
            "installation_state": row["installation_state"], "connected": row["seen_wss"]}
    for fields in (("setup_status", "setup_target_id"), ("preparation_status", "preparation_target_id"),
                   ("core_status", "core_target_version", "core_target_sha256")):
        if row[fields[0]]:
            case.update({key: row.get(key) for key in fields})
    if decision:
        case["console"] = {key: decision[key] for key in ("status", "safe_code")}
    profile = _matches_profile(evidence, row)
    conflicts = _inventory_conflicts(profile, row.get("inventory") or {}, platform) if profile else []
    if conflicts:
        case["conflicting_profile_fields"] = conflicts
    elif profile:
        case["profile"] = profile
    if row["setup_status"] == "recovery_required" or row["preparation_status"] in ("recovering_client", "recovering_source"):
        reason = "native_recovery_required"
    elif any(row[key] for key in ("setup_status", "preparation_status", "core_status")):
        reason = "active_operation"
    elif not _known_native(row, platform):
        reason = "native_installation_unknown" if row["installation_state"] != "removed" else "installation_removed"
    elif row["platform"] and row["platform"] != INSTANCE_PLATFORM[platform]:
        reason = "platform_observations_disagree"
    elif not row["seen_wss"]:
        reason = "waiting_reconnect"
    elif conflicts:
        reason = "inventory_profile_mismatch"
    elif not profile:
        reason = "native_profile_incomplete"
    elif profile["local_transaction"] != "settled":
        reason = "native_transaction_unsettled"
    elif platform == "alt" and not re.search(r"\bALT\b", profile["os_name"], re.IGNORECASE):
        reason = "alt_distribution_unconfirmed"
    elif tuple(map(int, row["native"]["version"].split("."))) >= tuple(map(int, target["version"].split("."))):
        reason = "same_or_newer_native_version"
    elif platform == "windows" and not decision:
        reason = "windows_preview_missing"
    elif decision and (decision["status"], decision["safe_code"]) not in (
            ("eligible", "eligible"), ("blocked", "source_not_qualified")):
        reason = decision["safe_code"]
    elif platform == "windows" and profile["foundation_version"] != row["native"]["version"]:
        reason = "native_foundation_mismatch"
    elif decision and "native_route" in decision and decision["native_route"] is None:
        reason = "native_route_unconfirmed"
    else:
        if decision and "native_route" in decision:
            case["native_route"] = decision["native_route"]
        return {**case, "category": "REQUIRED", "reason": "observed_native_source",
                "test": "native_transition"}
    if not profile or conflicts:
        observed, missing = _partial_profile(row)
        if observed:
            case["observed_profile"] = observed
        case["missing_profile_fields"] = missing
    return {**case, "category": "HOLD", "reason": reason}


def _validate_native_route(route):
    if route is None:
        return
    if not isinstance(route, dict) or set(route) != {"kind", "steps"}:
        raise ValueError("Invalid Windows native route")
    steps = _array(route, "steps")
    if ROUTE_STEPS.get(route["kind"]) != len(steps):
        raise ValueError("Invalid Windows native route step count")
    for step in steps:
        if (set(step) != {"build_id", "version", "sha256"} or str(UUID(step["build_id"])) != step["build_id"]
                or not VERSION.fullmatch(step["version"]) or not SHA256.fullmatch(step["sha256"])):
            raise ValueError("Windows native route requires exact bridge build identity")


def _preview_rows(preview, planning, target, now):
    if preview is None:
        return {}
    _observed_at(preview, now)
    if target["platform"] != "windows":
        raise ValueError("Windows preview requires a Windows target")
    release = next((row for row in _array(planning, "windows_targets") if row["release_id"] == preview["release_id"]), None)
    if (release is None or (release["version"], release["sha256"]) != (target["version"], target["sha256"])
            or preview["sha256"] != target["sha256"]):
        raise ValueError("Windows preview release ID and digest differ from the observed target")
    result = preview["response"]
    if result["read_only"] is not True or result["truncated"] is not False or preview["scope"] != "all_active":
        raise ValueError("Windows preview must cover all active devices without truncation")
    rows = _by_device(_array(result, "data"))
    if result["evaluated_count"] != len(rows):
        raise ValueError("Windows preview count differs from its decisions")
    for row in rows.values():
        _validate_native_route(row.get("native_route"))
    return rows


def _group_cases(cases):
    grouped = {}
    result = []
    for case in cases:
        if case["category"] == "HOLD":
            result.append(case)
            continue
        profile = {key: value for key, value in case.items() if key != "device_id"}
        key = json.dumps(profile, sort_keys=True)
        if key not in grouped:
            grouped[key] = {**profile, "device_ids": []}
            result.append(grouped[key])
        grouped[key]["device_ids"].append(case["device_id"])
    for cohort in grouped.values():
        cohort["device_count"] = len(cohort["device_ids"])
    return result


def _reuse_windows_evidence(cases, planning, target, preview, reviewed, environment, now):
    if target["platform"] != "windows" or preview is None or not SHA256.fullmatch(environment or ""):
        raise ValueError("Windows Lab evidence requires an exact Windows preview and qualification environment SHA-256")
    _observed_at(reviewed, now)
    active = {row["qualification_id"]: row for row in _array(planning, "windows_qualifications")
              if row["release_id"] == preview["release_id"] and row["sha256"] == target["sha256"]
              and datetime.fromisoformat(row["qualified_at"]) <= now <= datetime.fromisoformat(row["expires_at"])}
    reviewed_ids = set()
    by_foundation = {}
    for row in _array(reviewed, "qualifications"):
        qualification_id = row["qualification_id"]
        if qualification_id in reviewed_ids or any(str(UUID(row[key])) != row[key]
                                                     for key in ("qualification_id", "evidence_assignment_id")):
            raise ValueError("Windows Lab evidence requires unique canonical qualification and assignment IDs")
        reviewed_ids.add(qualification_id)
        if any(not SHA256.fullmatch(row[key]) for key in ("target_sha256", "environment_sha256", "receipt_sha256")):
            raise ValueError("Windows Lab evidence requires exact target, environment and receipt digests")
        _validate_native_route(row["native_route"])
        current = active.get(qualification_id)
        if (current is None or current["evidence_assignment_id"] != row["evidence_assignment_id"]
                or row["target_sha256"] != target["sha256"] or row["environment_sha256"] != environment):
            continue
        foundation = current["source_foundation"]
        if foundation in by_foundation:
            raise ValueError("Provider returned multiple current qualifications for the same Setup source")
        by_foundation[foundation] = current, row

    for case in cases:
        if (case.get("native_route") != {"kind": "direct", "steps": []}
                or case["console"] != {"status": "eligible", "safe_code": "eligible"}):
            continue
        profile = case["profile"]
        match = by_foundation.get(profile["foundation_version"])
        if match is None:
            continue
        current, review = match
        if (current["source_core"], current["source_setup_client"]) != (profile["core_version"], profile["setup_client_version"]):
            continue
        if (review["source"], review["profile"], review["native_route"]) != (case["source"], profile, case["native_route"]):
            continue
        case["satisfied_by"] = {**{key: review[key] for key in (
            "qualification_id", "evidence_assignment_id", "receipt_sha256")}, "expires_at": current["expires_at"]}


def _reuse_alt_evidence(cases, target, reviewed, lab_snapshot, environment, now):
    native = target.get("native_identity")
    if (target["platform"] != "alt" or not native or native["version"] != target["version"]
            or not GIT_SHA.fullmatch(native["source_revision"])
            or not all(SHA256.fullmatch(native[key]) for key in ALT_RPM_DIGESTS)
            or not SHA256.fullmatch(environment or "") or lab_snapshot is None):
        raise ValueError("ALT Lab evidence requires a verified RPM kit, Gateway snapshot and environment SHA-256")
    _observed_at(reviewed, now)
    if type(lab_snapshot["schema_version"]) is not int or lab_snapshot["schema_version"] != 1:
        raise ValueError("Unsupported ALT Lab Gateway snapshot schema")
    captured = datetime.fromisoformat(lab_snapshot["observed_at"])
    if captured.tzinfo is None or captured > now + timedelta(seconds=30):
        raise ValueError("Invalid ALT Lab Gateway observation time")
    transitions = {row["target_event_id"]: row for row in
                   _array(lab_snapshot["release_planning"], "alt_native_transitions")}
    matches = []
    seen = set()
    for review in _array(reviewed, "qualifications"):
        event_id = review["target_event_id"]
        if event_id in seen or any(str(UUID(review[key])) != review[key]
                                   for key in ("source_event_id", "target_event_id")):
            raise ValueError("ALT Lab evidence requires unique canonical native event IDs")
        seen.add(event_id)
        if any(not SHA256.fullmatch(review[key]) for key in ("target_sha256", "environment_sha256", "receipt_sha256")):
            raise ValueError("ALT Lab evidence requires exact target, environment and receipt digests")
        ack = transitions.get(event_id)
        if (ack is None or review["source_event_id"] != ack["source_event_id"]
                or review["target_sha256"] != target["sha256"] or review["environment_sha256"] != environment
                or {key: ack["target"].get(key) for key in ALT_NATIVE_IDENTITY} != native):
            continue
        applied = datetime.fromisoformat(ack["target_received_at"])
        expiry = datetime.fromisoformat(review["expires_at"])
        if applied.tzinfo is None or expiry.tzinfo is None:
            raise ValueError("ALT Lab Gateway and validity times must include a UTC offset")
        if applied <= captured <= expiry and applied <= now <= expiry <= applied + timedelta(days=30):
            matches.append((ack["source"], review))
    for case in cases:
        if case.get("test") != "native_transition":
            continue
        matching = [review for source, review in matches
                    if (source, review["profile"]) == (case["source"], case["profile"])]
        if matching:
            latest = max(matching, key=lambda review: datetime.fromisoformat(review["expires_at"]))
            case["satisfied_by"] = {key: latest[key] for key in (
                "source_event_id", "target_event_id", "receipt_sha256", "expires_at",
            )}


def _exposed_versions(planning, platform):
    setup_versions = {row["release_id"]: row["version"] for row in _array(planning, "windows_targets")}
    exposed = set((planning.get("historically_exposed_versions") or {}).get(platform, []))
    for row in _array(planning, "pending_enrollments"):
        if row["platform"] == platform:
            exposed.update((row["version"], row["release_id"]))
    for row in _array(planning, "enrollment_sources"):
        if row["platform"] != platform:
            continue
        if row["download_published"] or row["catalog_campaign_count"]:
            exposed.update((row["version"], row.get("installer_version")))
    for row in _array(planning, "devices"):
        if _relevant(row, platform):
            if row["native"]:
                exposed.add(row["native"].get("version"))
            exposed.update(row.get(key) for key in ("core_version", "foundation_version", "core_target_version"))
            if platform == "windows":
                exposed.add(setup_versions.get(row.get("setup_target_id")))
                exposed.add(setup_versions.get(row.get("preparation_target_id")))

    return exposed


def _lab_cases(rows, platform, production, staging):
    providers = [production, staging] if staging is not None else [production]
    has_history = len(providers) == 2 and all(
        isinstance(provider["release_planning"].get("historically_exposed_versions", {}).get(platform), list)
        for provider in providers
    )
    exposed = set().union(*(_exposed_versions(provider["release_planning"], platform) for provider in providers))
    seen = set()
    for row in sorted(rows, key=lambda row: (row["version"], row["sha256"])):
        if row["platform"] != platform:
            continue
        source = {key: row[key] for key in ("version", "sha256", "receipt_sha256")}
        identity = (source["version"], source["sha256"])
        if (identity in seen or not VERSION.fullmatch(source["version"]) or not SHA256.fullmatch(source["sha256"])
                or not SHA256.fullmatch(source["receipt_sha256"])):
            raise ValueError("Lab candidates need unique, exact artifact and receipt digests")
        seen.add(identity)
        if source["version"] in exposed:
            yield {"category": "HOLD", "reason": "lab_claim_conflicts_with_observed_exposure", "source": source}
        elif row["exposure"] != "lab_only" or row["reset"] != "verified":
            yield {"category": "HOLD", "reason": "lab_reset_or_exposure_unverified", "source": source}
        elif not has_history:
            yield {"category": "HOLD", "reason": "operational_exposure_history_missing", "source": source}
        else:
            yield {"category": "EXCLUDED", "reason": "unexposed_lab_with_verified_reset", "source": source}
            regression = row.get("regression_test")
            if regression:
                if not re.fullmatch(r"[a-z][a-z0-9_]{0,79}", regression):
                    raise ValueError("Invalid Lab regression test identifier")
                yield {"category": "REGRESSION", "reason": "targeted_lab_regression", "source": source, "test": regression}


def plan(snapshot, target, *, now, preview=None, profiles=None, lab_candidates=None,
         windows_lab_evidence=None, qualification_environment=None, staging_snapshot=None,
         alt_lab_evidence=None, alt_lab_snapshot=None):
    if type(snapshot["schema_version"]) is not int or snapshot["schema_version"] != 1:
        raise ValueError("Unsupported provider snapshot schema")
    _observed_at(snapshot, now)
    platform = target["platform"]
    planning = snapshot["release_planning"]
    decisions = _preview_rows(preview, planning, target, now)
    reviewed = {}
    if profiles is not None:
        _observed_at(profiles, now)
        reviewed = _by_device(_array(profiles, "devices"))
    cases = _group_cases(
        _case(row, target, decisions.get(key), reviewed.get(key))
        for key, row in sorted(_by_device(_array(planning, "devices")).items())
        if _relevant(row, platform)
    )
    if windows_lab_evidence is not None:
        _reuse_windows_evidence(cases, planning, target, preview, windows_lab_evidence, qualification_environment, now)
    if alt_lab_evidence is not None:
        if alt_lab_snapshot == snapshot or alt_lab_snapshot == staging_snapshot:
            raise ValueError("ALT reuse requires the isolated Gateway transition evidence")
        _reuse_alt_evidence(cases, target, alt_lab_evidence, alt_lab_snapshot, qualification_environment, now)
    elif alt_lab_snapshot is not None:
        raise ValueError("ALT Lab Gateway snapshot requires reviewed ALT Lab evidence")
    if qualification_environment is not None and windows_lab_evidence is None and alt_lab_evidence is None:
        raise ValueError("Qualification environment requires reviewed Lab evidence")
    pending = [row for row in _array(planning, "pending_enrollments") if row["platform"] == platform]
    for source in sorted(pending, key=lambda row: (row["version"], row["release_id"], row["status"])):
        cases.append({"category": "HOLD", "reason": "pending_enrollment", "source": source})
    enrollment = sorted((row for row in _array(planning, "enrollment_sources") if row["platform"] == platform),
                        key=lambda row: (row["version"], row["release_id"]))
    if lab_candidates is not None:
        _observed_at(lab_candidates, now)
        if staging_snapshot is not None:
            _observed_at(staging_snapshot, now)
            if (type(staging_snapshot["schema_version"]) is not int or staging_snapshot["schema_version"] != 1
                    or not snapshot.get("database_name") or not staging_snapshot.get("database_name")
                    or snapshot["database_name"] == staging_snapshot["database_name"]):
                raise ValueError("Lab exclusion requires separately captured production and staging snapshots")
        cases.extend(_lab_cases(_array(lab_candidates, "candidates"), platform, snapshot, staging_snapshot))
    cases.append({"category": "REQUIRED", "reason": "new_device_installation", "test": "factory_first_registration"})
    return {
        "schema_version": 1, "observed_at": snapshot["observed_at"], "target": target,
        "counts": dict(Counter(case["category"] for case in cases)), "cases": cases,
        "enrollment_sources": enrollment,
    }


def brief(report):
    target = report["target"]
    summary = Counter()
    for row in report["cases"]:
        caption = f'{row["category"]} {row["reason"]}'
        route = row.get("native_route")
        if route:
            caption += " " + route["kind"]
            if route["steps"]:
                caption += " [" + " -> ".join(step["version"] for step in route["steps"]) + "]"
        if "satisfied_by" in row:
            caption += " (existing qualification)"
        summary[caption] += 1
    lines = [f'{target["platform"]} {target["version"]} ({target["sha256"]})',
             f'Provider snapshot {report["observed_at"]}']
    lines.extend(f"- {caption} ({count})" for caption, count in sorted(summary.items()))
    return "\n".join(lines)


def add_observation_arguments(parser):
    parser.add_argument("--snapshot", required=True, type=Path)
    parser.add_argument("--windows-preview", type=Path)
    parser.add_argument("--profile-evidence", type=Path)
    parser.add_argument("--lab-candidates", type=Path)
    parser.add_argument("--staging-snapshot", type=Path, help="Independent provider history for Lab exclusions")
    parser.add_argument("--windows-lab-evidence", type=Path, help="Reviewed evidence for direct Windows transitions")
    parser.add_argument("--alt-lab-evidence", type=Path, help="Reviewed matching ALT transition receipts")
    parser.add_argument("--alt-lab-snapshot", type=Path, help="Read-only Gateway export retained from the isolated ALT Lab")
    parser.add_argument("--qualification-environment", help="SHA-256 of the reviewed current environment manifest")
    parser.add_argument("--format", choices=("json", "brief"), default="json")


def plan_from_files(args, target):
    return plan(
        json.loads(args.snapshot.read_bytes()), target, now=datetime.now(timezone.utc),
        preview=json.loads(args.windows_preview.read_bytes()) if args.windows_preview else None,
        profiles=json.loads(args.profile_evidence.read_bytes()) if args.profile_evidence else None,
        lab_candidates=json.loads(args.lab_candidates.read_bytes()) if args.lab_candidates else None,
        windows_lab_evidence=json.loads(args.windows_lab_evidence.read_bytes()) if args.windows_lab_evidence else None,
        qualification_environment=args.qualification_environment,
        staging_snapshot=json.loads(args.staging_snapshot.read_bytes()) if args.staging_snapshot else None,
        alt_lab_evidence=json.loads(args.alt_lab_evidence.read_bytes()) if args.alt_lab_evidence else None,
        alt_lab_snapshot=json.loads(args.alt_lab_snapshot.read_bytes()) if args.alt_lab_snapshot else None,
    )


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--platform", required=True, choices=tuple(NATIVE_CONTRACT))
    parser.add_argument("--target-version", required=True)
    parser.add_argument("--target-sha256", required=True, help="Windows Setup EXE or ALT native kit archive")
    add_observation_arguments(parser)
    args = parser.parse_args()
    try:
        if not VERSION.fullmatch(args.target_version) or not SHA256.fullmatch(args.target_sha256):
            raise ValueError("Expected the exact target version and lowercase SHA-256")
        result = plan_from_files(args, {"platform": args.platform, "version": args.target_version,
                                        "sha256": args.target_sha256})
    except (OSError, KeyError, TypeError, ValueError, AttributeError) as exc:
        parser.exit(1, f"Compatibility matrix failed: {exc}\n")
    print(brief(result) if args.format == "brief" else json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
