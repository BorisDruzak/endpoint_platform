"""QGA entrypoint for the isolated ALT trial. The runner supplies the exact kit."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tarfile
from time import monotonic_ns


ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}


def _run(*args, env=ENV, check=True, seconds=45):
    return subprocess.run(args, capture_output=True, stdin=subprocess.DEVNULL,
                          env=env, check=check, timeout=seconds)


def _sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _check_guest(uuid):
    if (os.geteuid() != 0 or Path("/sys/class/dmi/id/product_uuid").read_text().strip().lower() != uuid
            or [p.name for p in Path("/sys/class/net").iterdir()] != ["lo"]
            or any(_run("ip", family, "route", "show", "default").stdout.strip() for family in ("-4", "-6"))):
        raise ValueError("The dedicated ALT guest identity or network isolation changed")


def _check_file(path, proof):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1:
        raise ValueError("Expected a root-owned regular ALT Lab input")
    if info.st_size != proof["size"] or _sha(path) != proof["sha256"]:
        raise ValueError("ALT Lab input differs from the recorded kit")


def _verified_members(trial, directory):
    artifacts = trial["artifacts"]
    for proof in artifacts.values():
        _check_file(directory / proof["filename"], proof)
    key = directory / "endpoint-rpm-release.asc"
    _check_file(key, trial["members"][key.name])
    gpg = directory / "gpg"
    gpg.mkdir(mode=0o700)
    command = ("gpg", "--batch", "--homedir", str(gpg))
    _run(*command, "--import", str(key))
    listing = _run(*command, "--with-colons", "--fingerprint", "--list-keys").stdout.decode("ascii")
    fingerprints = [line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:")]
    if fingerprints != [trial["publisher"]]:
        raise ValueError("Unexpected publisher in the ALT Lab keyring")
    for label in ("manifest", "archive"):
        out = _run(*command, "--status-fd", "1", "--verify", str(directory / artifacts[label + "_signature"]["filename"]),
                   str(directory / artifacts[label]["filename"]), seconds=90).stdout.decode("ascii")
        if not any(line.startswith("[GNUPG:] VALIDSIG " + trial["publisher"] + " ") for line in out.splitlines()):
            raise ValueError("ALT Lab kit signature differs from the pinned publisher")
    names = (*trial["rpm_names"], "endpoint-agent-setup")
    with tarfile.open(directory / artifacts["archive"]["filename"], "r:gz") as archive:
        for name in names:
            proof = trial["members"][name]
            member = archive.getmember(f'{trial["kit_name"]}/{name}')
            if not member.isfile() or member.size != proof["size"]:
                raise ValueError("Unexpected ALT Lab kit member")
            target = directory / name
            with archive.extractfile(member) as source, target.open("xb") as output:
                shutil.copyfileobj(source, output)
            _check_file(target, proof)
    return tuple(directory / name for name in names)


def _prepare_ca(expected):
    directory = Path("/etc/endpoint-agent")
    if expected is None:
        if os.path.lexists(directory) and (directory.is_symlink() or any(directory.iterdir())):
            raise ValueError("Unexpected ALT configuration before factory install")
        return
    ca = directory / "ca.crt"
    if (directory.is_symlink() or {path.name for path in directory.iterdir()} != {ca.name}
            or directory.stat().st_uid != 0 or directory.stat().st_gid != 0
            or stat.S_IMODE(directory.stat().st_mode) not in (0o700, 0o755)
            or ca.is_symlink() or not ca.is_file() or ca.stat().st_uid != 0 or ca.stat().st_gid != 0
            or stat.S_IMODE(ca.stat().st_mode) != 0o600 or _sha(ca) != expected):
        raise ValueError("Public ALT factory CA changed before installation")
    directory.chmod(0o755)


def install(trial):
    os.umask(0o077)
    _check_guest(trial["guest_uuid"])
    directory = Path(trial["directory"])
    for path in ("/var/lib/endpoint-agent-installation/state.json", "/opt/endpoint-agent/current.json",
                 "/etc/endpoint-agent/config.yaml", "/etc/credstore/endpoint-enrollment-claim",
                 "/var/lib/endpoint-agent/device-credential", "/var/lib/endpoint-agent/enrollment-identity.json"):
        if os.path.lexists(path):
            raise ValueError("Existing ALT lifecycle state requires separate review")
    for package in ("endpoint-agent", "endpoint-agent-user-sensor"):
        if _run("rpm", "-q", package, check=False).returncode != 1:
            raise ValueError("Expected an empty native ALT package inventory")
    started = monotonic_ns()
    core, sensor, setup = _verified_members(trial, directory)
    kit_verification = monotonic_ns() - started
    started = monotonic_ns()
    _run("rpm", "-U", "--test", str(core), str(sensor), seconds=90)
    rpm_preflight = monotonic_ns() - started
    print("stock_rpm_pair_test=0", flush=True)
    _check_guest(trial["guest_uuid"])
    _prepare_ca(trial["ca_sha256"])
    setup.chmod(0o700)
    with (directory / "native-dispatched").open("x") as marker:
        marker.write(trial["kit_sha256"] + "\n")
        marker.flush()
        os.fsync(marker.fileno())
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    env = {**ENV, "ENDPOINT_AGENT_DEPLOYMENT_ENVIRONMENT": "staging", "CANARY_ENVIRONMENT": "staging",
           "CANARY_APPROVED": "true", "ENDPOINT_AGENT_ORIGIN": "https://endpoint-staging.sosnadmin.local"}
    started = monotonic_ns()
    outcome = _run(str(setup), "install", "--core-rpm", str(core), "--user-sensor-rpm", str(sensor),
                   "--public-key", str(directory / "endpoint-rpm-release.asc"), env=env, check=False, seconds=180)
    setup_install = monotonic_ns() - started
    print(f"setup_install_exit={outcome.returncode}", flush=True)
    if outcome.returncode != 21:
        raise ValueError("ALT Setup did not return the pre-enrollment result")
    timing = {"kit_verification": kit_verification, "rpm_preflight": rpm_preflight, "setup_install": setup_install}
    print("offline_timing_ns=" + json.dumps(timing), flush=True)
