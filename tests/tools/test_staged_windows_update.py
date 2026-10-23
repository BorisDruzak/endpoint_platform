import copy

import pytest

from tools.canary.staged_windows_update import (
    EvidenceError,
    baseline_fingerprint,
    compare_benchmarks,
    evaluate_scenario,
    verify_matrix,
)


def observation(scenario="success-cold"):
    return {
        "schema_version": 1,
        "scenario": scenario,
        "baseline": "modern-with-ota",
        "baseline_fingerprint": "a" * 64,
        "source_revision": "b" * 40,
        "artifact_sha256": "c" * 64,
        "operation_id": "11111111-1111-4111-8111-111111111111",
        "terminal": "accepted",
        "msi_exit": 0,
        "foundation_before": "3.2.120",
        "core_before": "3.2.121",
        "foundation_after": "3.2.123",
        "core_after": "3.2.123",
        "candidate_version": "3.2.123",
        "checks": {
            "native_registration": True,
            "shared_bytes": True,
            "full_runtime_tree": True,
            "private_preservation": True,
            "fresh_server_wss": True,
            "policy_proof": True,
            "continuous_online_preparation": True,
            "same_ntfs_file_ids": True,
            "companions": True,
        },
        "durations": {"accepted_seconds": 300, "stop_to_new_wss_seconds": 65},
        "payload_capture_bytes": 1000,
        "payload_restore_bytes": 0,
    }


def test_report_does_not_infer_success_from_msi_exit():
    value = observation()
    value["terminal"] = "trial"
    assert evaluate_scenario(value)["verdict"] == "incomplete"
    value["terminal"] = "accepted"
    value["checks"]["fresh_server_wss"] = False
    assert evaluate_scenario(value)["verdict"] == "incomplete"


def test_report_requires_both_foundation_and_core_rollback():
    value = observation("early-crash")
    value["terminal"] = "rolled-back"
    value["core_after"] = value["core_before"]
    assert evaluate_scenario(value)["verdict"] == "incomplete"
    value["foundation_after"] = value["foundation_before"]
    assert evaluate_scenario(value)["verdict"] == "pass"


def test_benchmark_does_not_compare_different_baselines():
    cold, warm = observation(), observation("success-warm")
    warm["baseline_fingerprint"] = "d" * 64
    with pytest.raises(EvidenceError, match="baseline"):
        compare_benchmarks(cold, warm)


def test_report_withholds_pass_on_missing_scenario():
    report = verify_matrix([observation()])
    assert report["verdict"] == "incomplete"
    assert "modern-with-ota:no-proof" in report["missing"]
    assert "legacy:success-cold" in report["missing"]


@pytest.mark.parametrize("field,value", [
    ("candidate_version", "3.2.122"),
    ("source_revision", "e" * 40),
    ("artifact_sha256", "f" * 64),
])
def test_matrix_rejects_historical_fault_from_another_candidate(field, value):
    success, fault = observation(), observation("early-crash")
    fault.update(terminal="rolled-back", foundation_after=fault["foundation_before"],
                 core_after=fault["core_before"])
    fault[field] = value
    with pytest.raises(EvidenceError, match="candidate"):
        verify_matrix([success, fault])


@pytest.mark.parametrize("field,value", [
    ("baseline_fingerprint", "e" * 64),
    ("foundation_before", "3.2.119"),
    ("core_before", "3.2.120"),
])
def test_matrix_rejects_fault_from_a_different_installed_baseline(field, value):
    success, fault = observation(), observation("early-crash")
    fault[field] = value
    fault.update(terminal="rolled-back", foundation_after=fault["foundation_before"],
                 core_after=fault["core_before"])
    with pytest.raises(EvidenceError, match="baseline"):
        verify_matrix([success, fault])


def test_report_rejects_extra_private_fields():
    value = observation()
    value["device_credential"] = "never serialize this"
    with pytest.raises(EvidenceError, match="schema"):
        evaluate_scenario(value)


@pytest.mark.parametrize("field,value", [("payload_restore_bytes", 1), ("payload_capture_bytes", 0)])
def test_ordinary_success_requires_one_capture_without_restore(field, value):
    sample = observation()
    sample[field] = value
    assert evaluate_scenario(sample)["verdict"] == "incomplete"


def test_performance_failure_is_reported_without_losing_correctness_evidence():
    value = observation()
    value["durations"]["accepted_seconds"] = 601
    report = evaluate_scenario(value)
    assert report["verdict"] == "incomplete"
    assert "accepted_seconds" in report["unproven"]


def test_benchmark_requires_same_candidate_and_actual_two_samples():
    cold, warm = observation(), observation("success-warm")
    assert compare_benchmarks(cold, warm)["comparable"] is True
    warm["source_revision"] = "d" * 40
    with pytest.raises(EvidenceError, match="candidate"):
        compare_benchmarks(cold, warm)


def test_checks_are_actual_booleans_and_duplicate_scenarios_are_refused():
    value = observation()
    value["checks"]["policy_proof"] = 1
    with pytest.raises(EvidenceError):
        evaluate_scenario(value)
    with pytest.raises(EvidenceError, match="duplicate"):
        verify_matrix([observation(), copy.deepcopy(observation())])


def test_baseline_comparison_uses_verified_installed_media_and_core():
    value = {'eligibility': 'READY_FOR_SETUP_UPGRADE',
             'foundation': {'native_verified': True, 'version': '3.2.120', 'source_revision': 'a' * 40,
                            'package_sha256': 'b' * 64, 'product_code': '{11111111-1111-4111-8111-111111111111}'},
             'core': {'verified': True, 'version': '3.2.121', 'source_revision': 'c' * 40,
                      'package_sha256': 'd' * 64}}
    before = baseline_fingerprint(value)
    value['core']['package_sha256'] = 'e' * 64
    assert baseline_fingerprint(value) != before
    value['core']['verified'] = False
    with pytest.raises(EvidenceError, match='baseline'):
        baseline_fingerprint(value)


def test_run_is_never_authorized_by_diagnostic_evidence(tmp_path):
    from types import SimpleNamespace
    from tools.canary.staged_windows_update import run_on_dedicated_guest
    with pytest.raises(EvidenceError, match='explicit'):
        run_on_dedicated_guest(SimpleNamespace(execute_dedicated_guest=False))
