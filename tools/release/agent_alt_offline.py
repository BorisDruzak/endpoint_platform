"""Check an isolated ALT factory installation while enrollment is still pending."""

import hashlib
import re
from pathlib import Path
from uuid import UUID

from endpoint_contracts.runtime_payload import read_json
from tools.release import agent_reservations
from tools.release.agent_candidate_artifacts import SHA256, alt_rpm_names, verify_recorded_candidate


MAX_RECEIPT = 256 * 1024
CORE = "endpoint-agent"
SENSOR = "endpoint-agent-user-sensor"
RETRY = "endpoint-agent-setup-retry"
SNAPSHOTS = ("before", "after-install", "after-reboot", "after-timer")
SOFTWARE_BASELINE = ("os_packages_digest", "os_packages_count", "os_package_profile",
                     "rpmdb_keys", "ca_sha256", "ca_mode", "ca_directory_entries")


def _read_qga(directory: Path, name: str) -> tuple[str, str]:
    path = directory / f"{name}.json"
    with path.open("rb") as stream:
        raw = stream.read(MAX_RECEIPT + 1)
    receipt = read_json(raw, MAX_RECEIPT)
    if (type(receipt.get("exited")) not in (bool, int) or receipt["exited"] != 1
            or type(receipt.get("exitcode")) is not int or receipt["exitcode"] != 0
            or receipt.get("out-truncated", False) or not isinstance(receipt.get("out-data"), str)):
        raise ValueError(f"A complete successful guest observation is required: {name}")
    return receipt["out-data"], hashlib.sha256(raw).hexdigest()


def _check_isolated(snapshot):
    if (snapshot["interfaces"] != ["lo"] or snapshot["default_ipv4_route"] is not False
            or snapshot["default_ipv6_route"] is not False):
        raise ValueError("ALT factory trial requires network isolation")
    if (any(snapshot[key] is not False for key in ("identity_present", "credential_present", "claim_present",
                                                  "config_present"))
            or any(type(snapshot[key]) is not int or snapshot[key] != 0 for key in
                   ("installation_events", "installation_sequence", "installation_ack", "receipts"))):
        raise ValueError("ALT offline factory snapshots require clean enrollment state")
    if snapshot["support_ssh_listener"] is not False or snapshot["support_policy_failure_journal_count"] != 0:
        raise ValueError("Support must remain inactive before ALT enrollment")


def check_factory_baseline(before):
    _check_isolated(before)
    if (before["source"] is not None or before["selector"] is not None
            or any(value is not None for value in before["native"].values())
            or before["durability_complete"] is not None or before["sensor_autostart_files"]
            or any(before["units"][f"{name}.service"]["LoadState"] != "not-found"
                   for name in (CORE, "endpoint-support-access"))
            or any(before["packages"][name] != {"query_exit": 1, "transaction": "", "verify_exit": None}
                   for name in (CORE, SENSOR))):
        raise ValueError("An uninstalled factory ALT baseline is required")
    ca = tuple(before[key] for key in ("ca_directory_entries", "ca_sha256", "ca_mode"))
    if ca != ([], None, None) and not (ca[0] == ["ca.crt"] and SHA256.fullmatch(ca[1] or "") and ca[2] == "0o600"):
        raise ValueError("Expected an empty factory configuration or the unchanged public CA")


def check_installation(snapshot, expected):
    _check_isolated(snapshot)
    if snapshot["source"] != expected:
        raise ValueError("Native receipt must identify the exact signed RPM pair")
    if snapshot["selector"] != {"schema_version": 1, "source_revision": expected["source_revision"],
                                "version": expected["version"]}:
        raise ValueError("Installed ALT Core selector differs from the signed pair")
    native = snapshot["native"]
    if (str(UUID(native["id"])) != native["id"] or native["action"] != "install"
            or native["phase"] != "invocation_possible" or type(native["exit_code"]) is not int
            or native["exit_code"] != 0 or snapshot["durability_complete"] is not True
            or native["bootstrap"] != "pending" or native["settled"] is not False
            or native["operation_id"] is not None):
        raise ValueError("A durable native RPM zero with enrollment pending is required")
    packages = snapshot["packages"]
    transaction_ids = set()
    for name, key in ((CORE, "core_nevra"), (SENSOR, "user_sensor_nevra")):
        row = packages[name]
        release = expected[key].removeprefix(name + "-")
        match = re.fullmatch(re.escape(f"{name}:{release}:") + r"[1-9][0-9]*:([1-9][0-9]*)", row["transaction"])
        if (match is None or type(row["query_exit"]) is not int or row["query_exit"] != 0
                or type(row["verify_exit"]) is not int or row["verify_exit"] != 0):
            raise ValueError("Installed ALT RPM transaction or file verification differs")
        transaction_ids.add(match[1])
    if len(transaction_ids) != 1:
        raise ValueError("Core and UserSensor require the same RPM transaction")
    for name, enabled in ((CORE, "enabled"), ("endpoint-support-access", "disabled")):
        unit = snapshot["units"][f"{name}.service"]
        if (unit["query_exit"], unit["LoadState"], unit["ActiveState"], unit["UnitFileState"],
                unit["MainPID"], unit["NRestarts"]) != (0, "loaded", "inactive", enabled, "0", "0"):
            raise ValueError("Core and Support must stay inactive before ALT enrollment")
    if "endpoint-user-sensor.desktop" not in snapshot["sensor_autostart_files"]:
        raise ValueError("Installed ALT UserSensor autostart entry is missing")


def _check_reconcile(status, snapshot):
    service = f"{RETRY}.service"
    timer = f"{RETRY}.timer"
    observed = {}
    for block in status.strip().split("\n\n"):
        pairs = [line.split("=", 1) for line in block.splitlines()]
        values = dict(pairs)
        if len(values) != len(pairs) or values.get("Id") in observed:
            raise ValueError("The automatic ALT reconcile invocation was not observed")
        observed[values.get("Id")] = values
    if set(observed) != {timer, service}:
        raise ValueError("The automatic ALT reconcile invocation was not observed")
    last_trigger = observed[timer].get("LastTriggerUSecMonotonic")
    values = observed[service]
    if (observed[timer].get("Result") != "success" or last_trigger in (None, "", "0", "0us", "n/a")
            or values.get("ExecMainStatus") != "21" or values.get("Result") != "exit-code"
            or not re.fullmatch(r"[1-9][0-9]*", values.get("ExecMainStartTimestampMonotonic", ""))):
        raise ValueError("The automatic ALT reconcile invocation was not observed")
    units = snapshot["units"]
    unit = units[timer]
    if (unit["ActiveState"], unit["SubState"], units[service]["Result"]) != ("active", "waiting", "exit-code"):
        raise ValueError("ALT retry timer must remain active after reconciliation")


def recorded_source(candidate):
    version, revision = candidate["version"], candidate["build_revision"]
    members = candidate["members"]
    core, sensor = alt_rpm_names(members, version)
    return {"version": version, "source_revision": revision, "core_nevra": core.removesuffix(".rpm"),
            "user_sensor_nevra": sensor.removesuffix(".rpm"), "core_rpm_sha256": members[core]["sha256"],
            "user_sensor_rpm_sha256": members[sensor]["sha256"]}


def verify(candidate: dict, directory: Path) -> dict:
    receipts = {name: _read_qga(directory, name) for name in (*SNAPSHOTS, "install", "retry-timer-status")}
    before, installed, rebooted, after_timer = (read_json(receipts[name][0].encode("utf-8"), MAX_RECEIPT)
                                              for name in SNAPSHOTS)
    check_factory_baseline(before)
    for snapshot in (before, installed, rebooted, after_timer):
        if (not SHA256.fullmatch(snapshot["boot_id_digest"])
                or not SHA256.fullmatch(snapshot["os_packages_digest"])
                or any(snapshot[key] != before[key] for key in SOFTWARE_BASELINE)):
            raise ValueError("The stock ALT baseline or CA changed during the trial")
    if (before["boot_id_digest"] != installed["boot_id_digest"]
            or installed["boot_id_digest"] == rebooted["boot_id_digest"]
            or rebooted["boot_id_digest"] != after_timer["boot_id_digest"]):
        raise ValueError("Receipts must span one ordinary reboot after installation")
    source = recorded_source(candidate)
    for snapshot in (installed, rebooted, after_timer):
        check_installation(snapshot, source)
        if snapshot["native"] != installed["native"] or snapshot["packages"] != installed["packages"]:
            raise ValueError("The native operation and RPM transaction must survive reboot and reconcile")
    install = receipts["install"][0].splitlines()
    if [line for line in install if line.startswith(("stock_rpm_pair_test=", "setup_install_exit="))] != [
            "stock_rpm_pair_test=0", "setup_install_exit=21"]:
        raise ValueError("The ALT dependency check and pre-enrollment Setup status are required")
    _check_reconcile(receipts["retry-timer-status"][0], after_timer)
    return {"schema_version": 1, "platform": "alt", "scope": "factory_offline", "state": "offline_install_verified",
            "request_id": candidate["request_id"], "kit_sha256": candidate["artifacts"]["archive"]["sha256"],
            "native_source": source, "operation_id": installed["native"]["id"], "bootstrap": "pending",
            "native_rpm_exit": 0, "setup_exit": 21, "reconcile_exit": 21, "installation_ack": 0,
            "stock_os_inventory_sha256": before["os_packages_digest"],
            "stock_os_profile": before["os_package_profile"],
            "receipt_sha256": {name: digest for name, (_, digest) in receipts.items()}}


def verify_recorded_trial(args) -> dict:
    candidate = verify_recorded_candidate(agent_reservations.reservation_status(args), "alt", args.artifacts_dir)
    return verify(candidate, args.evidence_dir)
