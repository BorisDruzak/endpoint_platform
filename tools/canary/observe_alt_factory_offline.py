"""Capture secret-free ALT factory evidence from a disconnected Lab guest."""

import hashlib
import json
import os
from pathlib import Path
import platform
import stat
import subprocess


PACKAGES = ("endpoint-agent", "endpoint-agent-user-sensor")
UNITS = ("endpoint-agent.service", "endpoint-support-access.service",
         "endpoint-agent-setup-retry.service", "endpoint-agent-setup-retry.timer")
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
MAX_STATE = 1024 * 1024


def _run(*args, check=True):
    return subprocess.run(args, text=True, check=check, capture_output=True, env=ENV,
                          stdin=subprocess.DEVNULL, timeout=30)


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _read_state(path):
    if not os.path.lexists(path):
        return None
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or not 0 < info.st_size <= MAX_STATE:
        raise ValueError("Expected a bounded root-owned native state file")
    with path.open("rb") as stream:
        raw = stream.read(MAX_STATE + 1)
    if len(raw) > MAX_STATE:
        raise ValueError("Expected a bounded root-owned native state file")
    return json.loads(raw)


def _rpm_evidence(name):
    fmt = "%{NAME}:%{VERSION}-%{RELEASE}.%{ARCH}:%{INSTALLTIME}:%{INSTALLTID}"
    query = _run("rpm", "-q", "--qf", fmt, name, check=False)
    verify = _run("rpm", "-V", name, check=False) if query.returncode == 0 else None
    return {"query_exit": query.returncode, "transaction": query.stdout.strip() if verify else "",
            "verify_exit": verify.returncode if verify else None}


def collect():
    if (os.geteuid() != 0 or platform.machine() != "x86_64"
            or platform.freedesktop_os_release().get("ID") != "altlinux"):
        raise ValueError("Collect factory evidence inside the dedicated ALT x64 guest")
    interfaces = sorted(path.name for path in Path("/sys/class/net").iterdir())
    v4 = bool(_run("ip", "-4", "route", "show", "default").stdout.strip())
    v6 = bool(_run("ip", "-6", "route", "show", "default").stdout.strip())
    if interfaces != ["lo"] or v4 or v6:
        raise ValueError("The ALT factory guest must have only loopback and no default route")

    config = Path("/etc/endpoint-agent")
    ca = config / "ca.crt"
    local = Path("/var/lib/endpoint-agent-installation")
    data = Path("/var/lib/endpoint-agent")
    selector_path = Path("/opt/endpoint-agent/current.json")
    ca_entries = sorted(path.name for path in config.iterdir()) if config.exists() else []
    if ca_entries not in ([], ["ca.crt"]):
        raise ValueError("The offline factory guest must have no enrollment configuration")
    state = _read_state(local / "state.json") or {}
    selector = _read_state(selector_path)
    if selector is not None:
        selector = {key: selector[key] for key in ("schema_version", "source_revision", "version")}
    operation = state.get("operation") or {}
    source = operation.get("source")
    if source is not None:
        source = {key: source[key] for key in ("version", "source_revision", "core_nevra",
            "core_rpm_sha256", "user_sensor_nevra", "user_sensor_rpm_sha256")}
    all_packages = _run("rpm", "-qa").stdout.splitlines()
    os_packages = sorted(name for name in all_packages if not name.startswith(("endpoint-agent-", "gpg-pubkey-")))
    os_profile = _run("rpm", "-q", "plasma-workspace", "kwin-x11", "libqt6-core", "libqt6-gui",
                      "libkf6idletime", "libssl3", "libcrypto3", "glibc-core").stdout.splitlines()
    units = {}
    for name in UNITS:
        command = _run("systemctl", "show", name, "-p", "LoadState,ActiveState,SubState,UnitFileState,NRestarts,Result,MainPID")
        units[name] = {**dict(line.split("=", 1) for line in command.stdout.splitlines() if "=" in line),
                       "query_exit": command.returncode}
    ca_digest = ca_mode = None
    if os.path.lexists(ca):
        ca_info = ca.lstat()
        if not stat.S_ISREG(ca_info.st_mode) or ca_info.st_uid != 0 or not 0 < ca_info.st_size <= MAX_STATE:
            raise ValueError("Invalid ALT factory CA file")
        ca_digest, ca_mode = _sha(ca.read_bytes()), oct(stat.S_IMODE(ca_info.st_mode))
    exists = os.path.lexists
    return {
        "boot_id_digest": _sha(Path("/proc/sys/kernel/random/boot_id").read_bytes()), "interfaces": interfaces,
        "default_ipv4_route": v4, "default_ipv6_route": v6, "os_packages_digest": _sha("\n".join(os_packages).encode()),
        "os_packages_count": len(os_packages), "os_package_profile": os_profile,
        "rpmdb_keys": sorted(name for name in all_packages if name.startswith("gpg-pubkey-")),
        "ca_sha256": ca_digest, "ca_mode": ca_mode,
        "ca_directory_entries": ca_entries,
        "config_present": exists(config / "config.yaml"), "credential_present": exists(data / "device-credential"),
        "identity_present": exists(data / "enrollment-identity.json") or bool(state.get("device_id")),
        "claim_present": exists("/etc/credstore/endpoint-enrollment-claim"), "selector": selector,
        "native": {key: operation.get(key) for key in ("action", "id", "operation_id", "phase", "exit_code", "settled", "bootstrap")},
        "source": source, "durability_complete": (operation.get("durability") or {}).get("complete"),
        "installation_sequence": state.get("sequence", 0), "installation_ack": state.get("acknowledged", 0),
        "installation_events": len(list(local.glob("event-*.json"))), "receipts": len(list(local.glob("receipt-*.json"))),
        "units": units, "packages": {name: _rpm_evidence(name) for name in PACKAGES},
        "support_ssh_listener": bool(_run("ss", "-H", "-ltn", "sport = :22222").stdout.strip()),
        "support_policy_failure_journal_count": _run("journalctl", "-b", "--no-pager", "-o", "cat", "-u",
            "endpoint-support-access.service").stdout.count("ENDPOINT_SUPPORT_POLICY_FAILURE"),
        "sensor_autostart_files": sorted(path.name for path in Path("/etc/xdg/autostart").glob("*endpoint*")),
    }


if __name__ == "__main__":
    print(json.dumps(collect(), separators=(",", ":"), sort_keys=True))
