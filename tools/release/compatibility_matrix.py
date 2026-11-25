"""Plan native Windows and ALT tests from read-only provider observations."""

from argparse import ArgumentParser
from collections import Counter
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re


VERSION = re.compile(r"(?:0|[1-9][0-9]{0,4})(?:\.(?:0|[1-9][0-9]{0,4})){2}")
SHA256 = re.compile(r"[0-9a-f]{64}")
GIT_SHA = re.compile(r"[0-9a-f]{40}")
NATIVE_CONTRACT = {"windows": "endpoint_installation_event_v1", "alt": "endpoint_linux_installation_event_v1"}
INSTANCE_PLATFORM = {"windows": "windows_amd64", "alt": "linux_amd64"}
PROFILE_FIELDS = ("os_name", "os_build", "os_edition", "architecture", "core_version", "foundation_version",
                  "setup_client_version", "support_version", "state_schema", "acl_profile", "local_transaction")


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
    if platform == "alt" and contract != NATIVE_CONTRACT["alt"] and row.get("enrollment_package_kind") == "deb":
        return False
    # Retain ambiguous cards in each applicable platform plan until resolved.
    return (system == INSTANCE_PLATFORM[platform] or contract == NATIVE_CONTRACT[platform]
            or (system is None and contract is None))


def _known_native(row, platform):
    if (row["installation_state"] != "installed" or row["native_contract"] != NATIVE_CONTRACT[platform]
            or row["native"] is None):
        return False
    native = row["native"]
    package_key = "msi_sha256" if platform == "windows" else "core_rpm_sha256"
    return (VERSION.fullmatch(native.get("version") or "") and GIT_SHA.fullmatch(native.get("source_revision") or "")
            and SHA256.fullmatch(native.get(package_key) or ""))


def _matches_profile(observation, row):
    if observation is None or not row.get("native_event_id") or observation["native_event_id"] != row["native_event_id"]:
        return None
    profile = observation["profile"]
    if not all(isinstance(profile.get(field), str) and profile[field].strip().lower() not in ("", "unknown")
               for field in PROFILE_FIELDS):
        return None
    if any(row.get(field) and row[field] != profile[field] for field in
           ("core_version", "foundation_version", "setup_client_version", "support_version")):
        return None
    return {key: profile[key] for key in PROFILE_FIELDS}


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
    if profile:
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
    else:
        return {**case, "category": "REQUIRED", "reason": "observed_native_source",
                "test": "native_transition"}
    return {**case, "category": "HOLD", "reason": reason}


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


def _lab_cases(rows, platform, planning, pending, enrollment):
    setup_versions = {row["release_id"]: row["version"] for row in _array(planning, "windows_targets")}
    exposed = {row["version"] for row in pending}
    exposed.update(row["release_id"] for row in pending)
    for row in enrollment:
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
        else:
            yield {"category": "EXCLUDED", "reason": "unexposed_lab_with_verified_reset", "source": source}
            regression = row.get("regression_test")
            if regression:
                if not re.fullmatch(r"[a-z][a-z0-9_]{0,79}", regression):
                    raise ValueError("Invalid Lab regression test identifier")
                yield {"category": "REGRESSION", "reason": "targeted_lab_regression", "source": source, "test": regression}


def plan(snapshot, target, *, now, preview=None, profiles=None, lab_candidates=None):
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
    pending = [row for row in _array(planning, "pending_enrollments") if row["platform"] == platform]
    for source in sorted(pending, key=lambda row: (row["version"], row["release_id"], row["status"])):
        cases.append({"category": "HOLD", "reason": "pending_enrollment", "source": source})
    enrollment = sorted((row for row in _array(planning, "enrollment_sources") if row["platform"] == platform),
                        key=lambda row: (row["version"], row["release_id"]))
    if lab_candidates is not None:
        _observed_at(lab_candidates, now)
        cases.extend(_lab_cases(_array(lab_candidates, "candidates"), platform, planning, pending, enrollment))
    cases.append({"category": "REQUIRED", "reason": "new_device_installation", "test": "factory_first_registration"})
    return {
        "schema_version": 1, "observed_at": snapshot["observed_at"], "target": target,
        "counts": dict(Counter(case["category"] for case in cases)), "cases": cases,
        "enrollment_sources": enrollment,
    }


def brief(report):
    target = report["target"]
    summary = Counter((row["category"], row["reason"]) for row in report["cases"])
    lines = [f'{target["platform"]} {target["version"]} ({target["sha256"]})',
             f'Provider snapshot {report["observed_at"]}']
    lines.extend(f"- {category} {reason} ({count})" for (category, reason), count in sorted(summary.items()))
    return "\n".join(lines)


def add_observation_arguments(parser):
    parser.add_argument("--snapshot", required=True, type=Path)
    parser.add_argument("--windows-preview", type=Path)
    parser.add_argument("--profile-evidence", type=Path)
    parser.add_argument("--lab-candidates", type=Path)
    parser.add_argument("--format", choices=("json", "brief"), default="json")


def plan_from_files(args, target):
    return plan(
        json.loads(args.snapshot.read_bytes()), target, now=datetime.now(timezone.utc),
        preview=json.loads(args.windows_preview.read_bytes()) if args.windows_preview else None,
        profiles=json.loads(args.profile_evidence.read_bytes()) if args.profile_evidence else None,
        lab_candidates=json.loads(args.lab_candidates.read_bytes()) if args.lab_candidates else None,
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
