from copy import deepcopy
import json
from uuid import uuid4

import pytest


@pytest.fixture
def offline_trial(tmp_path):
    version, revision = "3.2.274", "a" * 40
    core = "endpoint-agent"
    sensor = "endpoint-agent-user-sensor"
    suffix = f"{version}-alt6.x86_64"
    candidate = {"request_id": str(uuid4()), "version": version, "build_revision": revision,
        "artifacts": {"archive": {"sha256": "b" * 64}},
        "members": {f"{core}-{suffix}.rpm": {"sha256": "c" * 64},
                    f"{sensor}-{suffix}.rpm": {"sha256": "d" * 64},
                    "endpoint-agent-setup": {}, "endpoint-rpm-release.asc": {}}}
    base = {"interfaces": ["lo"], "default_ipv4_route": False, "default_ipv6_route": False,
        "boot_id_digest": "e" * 64, "os_packages_digest": "f" * 64, "os_packages_count": 1,
        "os_package_profile": ["libssl3-3.3.3-alt1.x86_64"], "rpmdb_keys": ["pinned-key"],
        "ca_sha256": "1" * 64, "ca_mode": "0o600", "ca_directory_entries": ["ca.crt"],
        "identity_present": False, "credential_present": False, "claim_present": False, "config_present": False,
        "installation_sequence": 0, "installation_ack": 0, "installation_events": 0, "receipts": 0,
        "support_ssh_listener": False, "support_policy_failure_journal_count": 0}
    inactive = {"ActiveState": "inactive", "MainPID": "0", "NRestarts": "0", "query_exit": 0}
    units = {f"{core}.service": {**inactive, "LoadState": "loaded", "UnitFileState": "enabled"},
             "endpoint-support-access.service": {**inactive, "LoadState": "loaded", "UnitFileState": "disabled"},
             "endpoint-agent-setup-retry.timer": {"ActiveState": "active", "SubState": "waiting", "query_exit": 0},
             "endpoint-agent-setup-retry.service": {**inactive, "Result": "success"}}
    native = {"action": "install", "exit_code": 0, "id": str(uuid4()), "operation_id": None,
              "settled": False, "phase": "invocation_possible", "bootstrap": "pending"}
    before = {**base, "selector": None, "source": None, "native": dict.fromkeys(native),
              "durability_complete": None,
              "packages": {name: {"query_exit": 1, "verify_exit": None, "transaction": ""} for name in (core, sensor)},
              "units": {name: {"LoadState": "not-found"} for name in units}, "sensor_autostart_files": []}
    installed = {**base, "selector": {"schema_version": 1, "source_revision": revision, "version": version},
        "native": native, "durability_complete": True, "units": units, "sensor_autostart_files": ["endpoint-user-sensor.desktop"],
        "source": {"version": version, "source_revision": revision, "core_nevra": f"{core}-{suffix}",
                   "user_sensor_nevra": f"{sensor}-{suffix}", "core_rpm_sha256": "c" * 64,
                   "user_sensor_rpm_sha256": "d" * 64},
        "packages": {name: {"query_exit": 0, "verify_exit": 0, "transaction": f"{name}:{suffix}:1780050000:1780049999"}
                     for name in (core, sensor)}}
    rebooted = {**deepcopy(installed), "boot_id_digest": "2" * 64}
    after_timer = deepcopy(rebooted)
    after_timer["units"]["endpoint-agent-setup-retry.service"].update(ActiveState="failed", Result="exit-code")
    receipts = {"before": before, "after-install": installed, "after-reboot": rebooted, "after-timer": after_timer,
                "install": "stock_rpm_pair_test=0\nsetup_install_exit=21\n",
                "retry-timer-status": "Id=endpoint-agent-setup-retry.timer\nLastTriggerUSecMonotonic=1min 22ms\nResult=success\n\n"
                   "Result=exit-code\nExecMainStartTimestampMonotonic=60000000\nExecMainStatus=21\n"
                   "Id=endpoint-agent-setup-retry.service\n"}

    def write(name):
        value = receipts[name]
        (tmp_path / f"{name}.json").write_text(json.dumps(
            {"exited": 1, "exitcode": 0, "out-data": json.dumps(value) if isinstance(value, dict) else value}),
            encoding="utf-8")

    for key in receipts:
        write(key)
    return tmp_path, candidate, receipts, write


def test_offline_verification_keeps_bootstrap_pending(offline_trial):
    from tools.release.agent_alt_offline import verify

    directory, candidate, receipts, _ = offline_trial
    result = verify(candidate, directory)
    assert result["state"] == "offline_install_verified"
    assert result["scope"] == "factory_offline"
    assert result["native_rpm_exit"] == 0 and result["setup_exit"] == result["reconcile_exit"] == 21
    assert result["bootstrap"] == "pending" and result["installation_ack"] == 0
    assert result["kit_sha256"] == candidate["artifacts"]["archive"]["sha256"]
    assert result["operation_id"] == receipts["after-install"]["native"]["id"]
    assert set(result["receipt_sha256"]) == set(receipts)
    assert "timing" not in result


def test_offline_verification_replays_guest_elapsed_times(offline_trial):
    from tools.release.agent_alt_offline import verify

    directory, candidate, receipts, write = offline_trial
    measurements = {"kit_verification": 9000000000, "rpm_preflight": 2000000000, "setup_install": 19000000000}
    receipts["install"] += "offline_timing_ns=" + json.dumps(measurements) + "\n"
    write("install")
    assert verify(candidate, directory)["timing"] == {"state": "measured", "guest_elapsed_ns": measurements}


@pytest.mark.parametrize("line", [
    "offline_timing_ns={}\n",
    'offline_timing_ns={"kit_verification":1,"rpm_preflight":false,"setup_install":1}\n',
    'offline_timing_ns={"kit_verification":1,"rpm_preflight":1,"setup_install":-1}\n',
    'offline_timing_ns={"kit_verification":1,"kit_verification":2,"rpm_preflight":1,"setup_install":1}\n',
    'offline_timing_ns={"kit_verification":1,"rpm_preflight":1,"setup_install":1}\noffline_timing_ns={}\n',
])
def test_invalid_optional_timing_preserves_native_acceptance(offline_trial, line):
    from tools.release.agent_alt_offline import verify

    directory, candidate, receipts, write = offline_trial
    receipts["install"] += line
    write("install")
    report = verify(candidate, directory)
    assert report["timing"] == {"state": "invalid"}
    assert report["state"] == "offline_install_verified"


@pytest.mark.parametrize(("receipt", "field", "value", "reason"), [
    ("before", "claim_present", True, "clean enrollment"),
    ("after-install", "default_ipv4_route", True, "network isolation"),
    ("after-install", "durability_complete", False, "durable native"),
    ("after-reboot", "boot_id_digest", "e" * 64, "ordinary reboot"),
    ("after-timer", "installation_ack", 1, "clean enrollment"),
])
def test_offline_verification_refuses_unproved_boundaries(offline_trial, receipt, field, value, reason):
    from tools.release.agent_alt_offline import verify

    directory, candidate, receipts, write = offline_trial
    receipts[receipt][field] = value
    write(receipt)
    with pytest.raises(ValueError, match=reason):
        verify(candidate, directory)


def test_offline_verification_rejects_changed_transaction_and_wrong_rpm_digest(offline_trial):
    from tools.release.agent_alt_offline import verify

    directory, candidate, receipts, write = offline_trial
    candidate["members"]["endpoint-agent-3.2.274-alt6.x86_64.rpm"]["sha256"] = "3" * 64
    with pytest.raises(ValueError, match="exact signed RPM"):
        verify(candidate, directory)
    candidate["members"]["endpoint-agent-3.2.274-alt6.x86_64.rpm"]["sha256"] = "c" * 64
    receipts["after-timer"]["packages"]["endpoint-agent"]["transaction"] = (
        "endpoint-agent:3.2.274-alt6.x86_64:1780050100:1780050099")
    write("after-timer")
    with pytest.raises(ValueError, match="RPM transaction"):
        verify(candidate, directory)


def test_offline_verification_refuses_duplicate_retry_status_and_truncated_capture(offline_trial):
    from tools.release.agent_alt_offline import verify

    directory, candidate, receipts, write = offline_trial
    prior = receipts["retry-timer-status"]
    receipts["retry-timer-status"] = prior + "ExecMainStatus=0\n"
    write("retry-timer-status")
    with pytest.raises(ValueError, match="reconcile invocation was not observed"):
        verify(candidate, directory)
    receipts["retry-timer-status"] = prior.replace("1min 22ms", "0us")
    write("retry-timer-status")
    with pytest.raises(ValueError, match="reconcile invocation was not observed"):
        verify(candidate, directory)
    receipts["retry-timer-status"] = prior
    write("retry-timer-status")
    leaf = directory / "after-reboot.json"
    truncated = json.loads(leaf.read_bytes())
    leaf.write_text(json.dumps({**truncated, "out-truncated": True}), encoding="utf-8")
    with pytest.raises(ValueError, match="complete successful guest observation"):
        verify(candidate, directory)
