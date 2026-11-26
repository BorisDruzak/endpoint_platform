import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
import subprocess
import sys


CLI = Path(__file__).resolve().parents[2] / "tools/release/compatibility_matrix.py"
SHA = "a" * 64
SOURCE = "b" * 40
TIME = datetime.now(timezone.utc).isoformat()


def run(tmp_path, snapshot, platform="windows", *options):
    path = tmp_path / "snapshot.json"
    path.write_text(json.dumps(snapshot), encoding="utf-8")
    return subprocess.run(
        [sys.executable, str(CLI), "--snapshot", str(path), "--platform", platform,
         "--target-version", "3.2.278", "--target-sha256", SHA, *options],
        capture_output=True, text=True, encoding="utf-8", timeout=20,
    )


def device(id, version, *, platform="windows_amd64", online=False, setup=None):
    return {
        "device_id": id, "platform": platform, "seen_wss": online,
        "installation_state": "installed", "native_contract": "endpoint_installation_event_v1",
        "native": {"version": version, "source_revision": SOURCE, "msi_sha256": "c" * 64},
        "setup_status": setup, "preparation_status": None, "core_status": None,
    }


def snapshot(*devices):
    return {"schema_version": 1, "observed_at": TIME, "release_planning": {
        "devices": devices, "windows_targets": [], "enrollment_sources": [], "pending_enrollments": [],
    }}


def test_plan_retains_offline_and_unknown_transactions_without_guessing_profiles(tmp_path):
    source = snapshot(device("1", "3.2.205", online=True), device("2", "3.2.264"),
                      device("3", "3.2.205", setup="recovery_required"),
                      {**device("4", "3.2.205"), "native": None})
    result = run(tmp_path, source)
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["target"]["sha256"] == SHA
    assert report["counts"] == {"HOLD": 4, "REQUIRED": 1}
    holds = {row["device_id"]: row for row in report["cases"] if row["category"] == "HOLD"}
    assert holds["1"]["reason"] == "native_profile_incomplete"
    assert holds["2"]["reason"] == "waiting_reconnect"
    assert holds["3"]["reason"] == "native_recovery_required"
    assert holds["4"]["reason"] == "native_installation_unknown"
    assert report["cases"] == json.loads(run(tmp_path, source).stdout)["cases"]


def test_plan_refuses_stale_or_incomplete_provider_snapshot(tmp_path):
    source = snapshot()
    source["observed_at"] = "2000-01-01T00:00:00+00:00"
    rejected = run(tmp_path, source)
    assert rejected.returncode != 0
    assert "preceding 30 minutes" in rejected.stderr
    source["observed_at"] = TIME
    del source["release_planning"]["devices"]
    rejected = run(tmp_path, source)
    assert rejected.returncode != 0
    assert "devices" in rejected.stderr


def test_plan_keeps_pending_enrollment_as_a_separate_source(tmp_path):
    excluded_os = {**device("debian", "3.2.205", platform="linux_amd64"), "native": None,
                   "native_contract": None, "enrollment_package_kind": "deb"}
    source = snapshot(excluded_os)
    source["release_planning"]["pending_enrollments"] = [
        {"platform": "alt", "version": "3.2.265", "release_id": "alt-release", "status": "waiting_wss", "count": 2},
        {"platform": "windows", "version": "3.2.205", "release_id": "win-release", "status": "waiting_approval", "count": 3},
    ]
    result = run(tmp_path, source, "alt")
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["counts"] == {"HOLD": 1, "REQUIRED": 1}
    pending, fresh = report["cases"]
    assert pending["reason"] == "pending_enrollment"
    assert pending["source"]["version"] == "3.2.265"
    assert pending["source"]["count"] == 2
    assert fresh["test"] == "factory_first_registration"
    summary = run(tmp_path, source, "alt", "--format", "brief")
    assert summary.returncode == 0, summary.stderr
    assert "HOLD pending_enrollment (1)" in summary.stdout


def test_plan_groups_only_exact_profiles_and_keeps_canonical_blockers(tmp_path):
    ids = ("device-1", "device-2", "device-3", "device-4", "device-5", "device-6", "device-7")
    source = snapshot(*({**device(id, "3.2.205", online=True), "native_event_id": f"{id}-native"} for id in ids))
    source["release_planning"]["devices"][4]["foundation_version"] = "3.2.192"
    source["release_planning"]["devices"][5]["core_version"] = "3.2.264"
    source["observed_at"] = (datetime.now(timezone.utc) + timedelta(seconds=2)).isoformat()
    source["release_planning"]["windows_targets"] = [{"release_id": "target", "version": "3.2.278", "sha256": SHA}]
    profile = {
        "os_name": "Windows 10", "os_build": "19045", "os_edition": "Enterprise",
        "architecture": "x86_64", "core_version": "3.2.205", "foundation_version": "3.2.205",
        "setup_client_version": "1.0.11", "support_version": "absent", "state_schema": "v1",
        "acl_profile": "service_sid", "local_transaction": "settled",
    }
    evidence = {"observed_at": TIME, "devices": [
        {"device_id": id, "native_event_id": f"{id}-native", "profile": dict(profile)} for id in ids
    ]}
    evidence["devices"][2]["profile"].update(os_name="Windows 11", os_build="26100")
    evidence["devices"][4]["profile"]["foundation_version"] = "3.2.192"
    evidence["devices"][5]["profile"]["core_version"] = "3.2.264"
    preview = {"observed_at": TIME, "scope": "all_active", "release_id": "target", "sha256": SHA,
               "response": {"read_only": True, "truncated": False, "evaluated_count": len(ids), "data": [
                   {"device_id": id, "status": "blocked", "safe_code": "source_not_qualified",
                    "native_route": {"kind": "direct", "steps": []}} for id in ids]}}
    preview["response"]["data"][3].update(status="waiting", safe_code="waiting_source_confirmation")
    preview["response"]["data"][6]["native_route"] = None
    preview_path = tmp_path / "preview.json"
    evidence_path = tmp_path / "profiles.json"
    preview_path.write_text(json.dumps(preview), encoding="utf-8")
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
    options = ("--windows-preview", str(preview_path), "--profile-evidence", str(evidence_path))
    result = run(tmp_path, source, "windows", *options)
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    transitions = [case for case in report["cases"] if case.get("test") == "native_transition"]
    assert [case["device_ids"] for case in transitions] == [list(ids[:2]), [ids[2]], [ids[5]]]
    assert {case["native_route"]["kind"] for case in transitions} == {"direct"}
    holds = {case["device_id"]: case["reason"] for case in report["cases"] if case["category"] == "HOLD"}
    assert holds == {ids[3]: "waiting_source_confirmation", ids[4]: "native_foundation_mismatch",
                     ids[6]: "native_route_unconfirmed"}
    summary = run(tmp_path, source, "windows", *options, "--format", "brief")
    assert summary.returncode == 0, summary.stderr
    assert "REQUIRED observed_native_source direct (3)" in summary.stdout

    route = preview["response"]["data"][0]["native_route"]
    route["kind"] = "observer_bootstrap"
    preview_path.write_text(json.dumps(preview), encoding="utf-8")
    incomplete = run(tmp_path, source, "windows", *options)
    assert incomplete.returncode != 0 and "native route step count" in incomplete.stderr
    route["kind"] = "direct"

    preview["sha256"] = "f" * 64
    preview_path.write_text(json.dumps(preview), encoding="utf-8")
    mismatch = run(tmp_path, source, "windows", *options)
    assert mismatch.returncode != 0
    assert "digest differ" in mismatch.stderr


def test_reset_lab_candidate_is_excluded_only_without_operational_exposure(tmp_path):
    source = snapshot(device("production", "3.2.205"))
    inventory = {"observed_at": TIME, "candidates": [
        {"platform": "windows", "version": "3.2.253", "sha256": "d" * 64,
         "receipt_sha256": "e" * 64, "exposure": "lab_only", "reset": "verified",
         "regression_test": "recovery_after_interrupted_msi"},
    ]}
    path = tmp_path / "lab.json"
    path.write_text(json.dumps(inventory), encoding="utf-8")
    source["database_name"] = "endpoint_platform"
    source["release_planning"]["historically_exposed_versions"] = {"windows": [], "alt": []}
    staging = {**snapshot(), "database_name": "endpoint_staging_db"}
    staging["release_planning"]["historically_exposed_versions"] = {"windows": [], "alt": []}
    staging_path = tmp_path / "staging.json"
    staging_path.write_text(json.dumps(staging), encoding="utf-8")
    options = ("--lab-candidates", str(path), "--staging-snapshot", str(staging_path))
    result = run(tmp_path, source, "windows", *options)
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["counts"] == {"EXCLUDED": 1, "HOLD": 1, "REGRESSION": 1, "REQUIRED": 1}
    regression, = [case for case in report["cases"] if case["category"] == "REGRESSION"]
    assert regression["test"] == "recovery_after_interrupted_msi"
    assert regression["source"]["sha256"] == "d" * 64

    source["release_planning"]["pending_enrollments"] = [
        {"platform": "windows", "version": "3.2.253", "release_id": "candidate", "status": "waiting_wss", "count": 1}
    ]
    report = json.loads(run(tmp_path, source, "windows", *options).stdout)
    assert "EXCLUDED" not in report["counts"]
    assert any(case["reason"] == "lab_claim_conflicts_with_observed_exposure" for case in report["cases"])


def test_reuse_requires_current_provider_proof_and_the_exact_reviewed_profile(tmp_path):
    row = {**device("eval", "3.2.205", online=True), "native_event_id": "accepted-eval"}
    other = {**row, "device_id": "enterprise", "native_event_id": "accepted-enterprise"}
    provider = snapshot(row, other)
    planning = provider["release_planning"]
    release_id = "31d59cee-1f80-4caf-9151-504a9b21cdba"
    assignment_id = "efbca67f-f720-4c5a-86c1-606afe603341"
    qualification_id = "38eb913f-4b2c-4806-8b1a-b51a62f80a6c"
    environment = "d" * 64
    planning["windows_targets"] = [{"release_id": release_id, "version": "3.2.278", "sha256": SHA}]
    now = datetime.now(timezone.utc)
    qualification = {
        "qualification_id": qualification_id, "release_id": release_id, "evidence_assignment_id": assignment_id,
        "source_foundation": "3.2.205", "source_core": "3.2.205", "source_setup_client": "1.0.11", "sha256": SHA,
        "qualified_at": (now - timedelta(days=1)).isoformat(), "expires_at": (now + timedelta(days=29)).isoformat(),
    }
    planning["windows_qualifications"] = [qualification]
    route = {"kind": "direct", "steps": []}
    preview = {"observed_at": TIME, "scope": "all_active", "release_id": release_id, "sha256": SHA,
               "response": {"read_only": True, "truncated": False, "evaluated_count": 2, "data": [
                   {"device_id": value["device_id"], "status": "eligible", "safe_code": "eligible",
                    "native_route": route} for value in (row, other)]}}
    profile = {"os_name": "Windows 11", "os_build": "26100.1742", "os_edition": "EnterpriseSEval",
               "architecture": "x86_64", "core_version": "3.2.205", "foundation_version": "3.2.205",
               "setup_client_version": "1.0.11", "support_version": "1.1.8", "state_schema": "v1",
               "acl_profile": "service_sid", "local_transaction": "settled"}
    profiles = {"observed_at": TIME, "devices": [
        {"device_id": "eval", "native_event_id": "accepted-eval", "profile": profile},
        {"device_id": "enterprise", "native_event_id": "accepted-enterprise",
         "profile": {**profile, "os_edition": "EnterpriseS", "os_build": "26100.9457"}},
    ]}
    lab = {"qualification_id": qualification_id, "evidence_assignment_id": assignment_id,
           "target_sha256": SHA, "source": row["native"], "profile": profile, "native_route": route,
           "environment_sha256": environment, "receipt_sha256": "e" * 64}

    def matrix(*, evidence=lab, live=qualification):
        planning["windows_qualifications"] = [live]
        files = {"windows-preview": preview, "profile-evidence": profiles,
                 "windows-lab-evidence": {"observed_at": TIME, "qualifications": [evidence]}}
        options = ["--qualification-environment", environment]
        for name, content in files.items():
            path = tmp_path / f"{name}.json"
            path.write_text(json.dumps(content), encoding="utf-8")
            options.extend([f"--{name}", str(path)])
        result = run(tmp_path, provider, "windows", *options)
        assert result.returncode == 0, result.stderr
        return json.loads(result.stdout)["cases"]

    cases = matrix()
    matching, = [case for case in cases if "satisfied_by" in case]
    assert matching["device_ids"] == ["eval"]
    assert matching["category"] == "REQUIRED"
    assert matching["satisfied_by"] == {
        "qualification_id": qualification_id, "evidence_assignment_id": assignment_id,
        "receipt_sha256": lab["receipt_sha256"], "expires_at": qualification["expires_at"],
    }
    assert sum(case["category"] == "REQUIRED" for case in cases) == 3
    assert all("satisfied_by" not in case for case in matrix(evidence={**lab, "target_sha256": "f" * 64}))
    assert all("satisfied_by" not in case for case in matrix(evidence={**lab, "environment_sha256": "f" * 64}))
    changed_source = {**lab, "source": {**row["native"], "msi_sha256": "f" * 64}}
    assert all("satisfied_by" not in case for case in matrix(evidence=changed_source))
    assert all("satisfied_by" not in case for case in matrix(evidence={**lab, "native_route": None}))
    assert all("satisfied_by" not in case for case in matrix(live={**qualification, "expires_at": TIME}))
    assert all("satisfied_by" not in case for case in matrix(live={**qualification, "evidence_assignment_id": release_id}))
    assert all("satisfied_by" not in case for case in matrix(live={**qualification, "source_setup_client": "1.0.6"}))
    preview["response"]["data"][0].update(status="waiting", safe_code="waiting_source_confirmation")
    holds = matrix()
    assert any(case["category"] == "HOLD" and case["device_id"] == "eval" for case in holds)
    assert all("satisfied_by" not in case for case in holds)


def test_hold_surfaces_observed_inventory_and_specific_missing_facts(tmp_path):
    row = {**device("production", "3.2.205", online=True),
           "core_version": "3.2.264", "foundation_version": "3.2.205", "launcher_version": "3.2.205",
           "inventory": {"observed_at": TIME, "os_name": "Windows", "os_build": "26100",
                         "architecture": "x86_64", "hostname": "ignored"},
           "packages": [{"name": "endpoint-agent", "version": "3.2.205-alt6"}]}
    result = run(tmp_path, snapshot(row))
    assert result.returncode == 0, result.stderr
    held, = [case for case in json.loads(result.stdout)["cases"] if case["category"] == "HOLD"]
    assert held["reason"] == "native_profile_incomplete"
    assert held["observed_profile"]["inventory"] == {
        "observed_at": TIME, "os_name": "Windows", "os_build": "26100", "architecture": "x86_64",
    }
    assert held["observed_profile"]["launcher_version"] == "3.2.205"
    assert held["observed_profile"]["packages"] == row["packages"]
    assert {"os_edition", "state_schema", "acl_profile", "local_transaction"} <= set(held["missing_profile_fields"])
    assert "core_version" not in held["missing_profile_fields"]


def test_lab_exclusion_requires_fresh_distinct_history_and_staging(tmp_path):
    production = {**snapshot(), "database_name": "endpoint_platform"}
    staging = {**snapshot(), "database_name": "endpoint_staging_db"}
    lab = {"observed_at": TIME, "candidates": [
        {"platform": "windows", "version": "3.2.253", "sha256": "d" * 64,
         "receipt_sha256": "e" * 64, "exposure": "lab_only", "reset": "verified"},
    ]}
    lab_path = tmp_path / "lab.json"
    stage_path = tmp_path / "stage.json"
    lab_path.write_text(json.dumps(lab), encoding="utf-8")

    def reason(*args):
        result = run(tmp_path, production, "windows", "--lab-candidates", str(lab_path), *args)
        assert result.returncode == 0, result.stderr
        candidate, = [case for case in json.loads(result.stdout)["cases"] if case["category"] != "REQUIRED"]
        return candidate["reason"]

    assert reason() == "operational_exposure_history_missing"
    for provider in (production, staging):
        provider["release_planning"]["historically_exposed_versions"] = {"windows": [], "alt": []}
    staging["release_planning"]["historically_exposed_versions"]["windows"] = ["3.2.253"]
    stage_path.write_text(json.dumps(staging), encoding="utf-8")
    assert reason("--staging-snapshot", str(stage_path)) == "lab_claim_conflicts_with_observed_exposure"
    staging["release_planning"]["historically_exposed_versions"]["windows"].clear()
    stage_path.write_text(json.dumps(staging), encoding="utf-8")
    assert reason("--staging-snapshot", str(stage_path)) == "unexposed_lab_with_verified_reset"


def test_alt_reuse_is_bound_to_the_same_candidate_pair_gateway_and_complete_profile():
    from tools.release.compatibility_matrix import plan

    now = datetime.now(timezone.utc)
    row = {**device("production-alt", "3.2.183", platform="linux_amd64", online=True),
           "native_event_id": "production-native",
           "native_contract": "endpoint_linux_installation_event_v1",
           "native": {"version": "3.2.183", "source_revision": SOURCE,
                      "core_rpm_sha256": "c" * 64, "user_sensor_rpm_sha256": "d" * 64}}
    production = snapshot(row)
    profile = {"os_name": "ALT Workstation K", "os_build": "11.4", "os_edition": "K",
               "architecture": "x86_64", "core_version": "3.2.183", "foundation_version": "3.2.183",
               "setup_client_version": "absent", "support_version": "1.1.8", "state_schema": "v1",
               "acl_profile": "root_v1", "local_transaction": "settled"}
    profiles = {"observed_at": TIME, "devices": [
        {"device_id": row["device_id"], "native_event_id": row["native_event_id"], "profile": profile},
    ]}
    target_native = {"version": "3.2.278", "source_revision": "e" * 40,
                     "core_rpm_sha256": "f" * 64, "user_sensor_rpm_sha256": "1" * 64}
    target = {"platform": "alt", "version": "3.2.278", "sha256": SHA, "native_identity": target_native}
    applied = now - timedelta(days=1)
    ack = {"source_event_id": "e2f95044-b8d8-4401-9baa-ba4c9173a9ab",
           "target_event_id": "f52f95c9-ab20-4199-9a6b-372af16d48bc",
           "target_received_at": applied.isoformat(), "source": row["native"], "target": target_native}
    lab = {"schema_version": 1, "observed_at": (applied + timedelta(minutes=5)).isoformat(),
           "release_planning": {"alt_native_transitions": [ack]}}
    environment = "2" * 64
    evidence = {"source_event_id": ack["source_event_id"], "target_event_id": ack["target_event_id"],
                "target_sha256": SHA, "environment_sha256": environment, "receipt_sha256": "3" * 64,
                "profile": profile, "expires_at": (now + timedelta(days=14)).isoformat()}

    def reuse(review=evidence, lab_view=lab, candidate=target):
        reviewed = {"observed_at": TIME, "qualifications": [review]}
        report = plan(production, candidate, now=now, profiles=profiles,
                      alt_lab_evidence=reviewed, alt_lab_snapshot=lab_view, qualification_environment=environment)
        transition, = [case for case in report["cases"] if case.get("test") == "native_transition"]
        assert transition["category"] == "REQUIRED"
        return transition.get("satisfied_by")

    assert reuse()["target_event_id"] == ack["target_event_id"]
    assert not reuse(review={**evidence, "profile": {**profile, "os_build": "11.5"}})
    assert not reuse(review={**evidence, "target_sha256": "5" * 64})
    assert not reuse(review={**evidence, "environment_sha256": "5" * 64})
    assert not reuse(review={**evidence, "expires_at": applied.isoformat()})
    assert not reuse(candidate={**target, "native_identity": {**target_native, "core_rpm_sha256": "0" * 64}})
    assert not reuse(lab_view={**lab, "release_planning": {"alt_native_transitions": []}})


def test_platform_observations_keep_deb_and_windows_cards_out_of_alt_matrix(tmp_path):
    def observed(id, os, platform):
        return {**device(id, "3.2.183", platform=platform), "native_contract": None, "native": None,
                "inventory": {"os_name": os, "observed_at": TIME}}

    source = snapshot(observed("ubuntu", "Ubuntu", "linux_amd64"),
                      observed("debian", "Debian GNU/Linux", "linux_amd64"),
                      observed("windows", "Windows", None), observed("alt", "ALT", None),
                      observed("unknown", None, None))
    result = run(tmp_path, source, "alt")
    assert result.returncode == 0, result.stderr
    holds = [case["device_id"] for case in json.loads(result.stdout)["cases"] if case["category"] == "HOLD"]
    assert holds == ["alt", "unknown"]
