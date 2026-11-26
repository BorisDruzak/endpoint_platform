"""Run the exact signed ALT offline factory trial on one dedicated Proxmox guest."""

from argparse import ArgumentParser
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from uuid import UUID


ROOT = Path(__file__).resolve().parents[2]
if not __package__:
    sys.path.insert(0, str(ROOT))

from endpoint_contracts.runtime_payload import read_json
from tools.release.agent_alt_offline import (
    MAX_RECEIPT, SOFTWARE_BASELINE, _read_qga, check_factory_baseline, check_installation, recorded_source, verify,
)
from tools.release.agent_candidate_artifacts import SHA256, _fingerprint, alt_rpm_names, verify_recorded_candidate
from tools.release.linux_native_verifier import KEY_SHA256, PUBLISHER


CAPSULE = "/var/tmp/endpoint-alt-factory-offline"
PUBLIC_KEY = ROOT / "packaging/alt/pilot/endpoint-rpm-release.asc"
SOURCE = Path(__file__).resolve().parent
CONFIG_KEYS = set("agent bios boot cores cpu description machine memory meta name numa onboot "
                  "ostype parent scsi0 scsihw smbios1 snaptime sockets tags vga vmgenid".split())
TIMER_STATUS = """
import subprocess
for name, properties in (
    ('timer', 'Id,LastTriggerUSecMonotonic,Result'),
    ('service', 'Id,ExecMainStartTimestampMonotonic,ExecMainStatus,Result'),
):
    subprocess.run(['systemctl', 'show', 'endpoint-agent-setup-retry.' + name, '-p', properties], check=True)
    print(flush=True)
"""

# Proxmox's local guest-agent transport. The caller supplies trusted paths and
# checks the VM configuration again before every file transfer.
UPLOAD = r"""
use strict;
use warnings;
use MIME::Base64 qw(encode_base64);
use PVE::QemuServer::Agent qw(agent_cmd);
my ($vmid, $local, $target) = @ARGV;
open my $input, '<:raw', $local or die 'Unable to read sealed input';
my $handle = agent_cmd($vmid, 'file-open', {path => $target, mode => 'wb'}, 'guest open failed');
my $ok = eval {
    while (1) {
        my $n = read($input, my $block, 393216);
        die 'input read failed' unless defined $n;
        last unless $n;
        my $result = agent_cmd($vmid, 'file-write', {handle => $handle, 'buf-b64' => encode_base64($block, '')}, 'guest write failed');
        die 'incomplete guest write' unless $result->{count} == $n;
    }
    1;
};
my $error = $@;
agent_cmd($vmid, 'file-close', {handle => $handle}, 'guest close failed');
die $error unless $ok;
"""


def _verify_config(raw, args):
    config = {}
    for line in raw.splitlines():
        key, separator, value = line.partition(": ")
        if not separator or key in config or key not in CONFIG_KEYS:
            raise ValueError("Unexpected device or state in the dedicated ALT VM configuration")
        config[key] = value
    disk = re.compile(rf"[A-Za-z0-9_-]+:vm-{args.vmid}-disk-[0-9]+(?:,[^:\n]+)?")
    if (config.get("name") != args.expected_name or config.get("smbios1") != "uuid=" + args.guest_uuid
            or config.get("agent") not in ("1", "enabled=1") or config.get("onboot", "0") != "0"
            or config.get("boot") != "order=scsi0" or not disk.fullmatch(config.get("scsi0", ""))):
        raise ValueError("The ALT VM identity, boot disk or offline configuration differs")
    return config


def _run(*args, data=None, seconds=60):
    return subprocess.run(args, input=data, capture_output=True, check=True, timeout=seconds).stdout


def _json(raw):
    return read_json(raw, MAX_RECEIPT)


class Proxmox:
    def __init__(self, args):
        self.args = args
        self.vmid = str(args.vmid)

    def command(self, *args, seconds=60):
        return _run("/usr/sbin/qm", *args, seconds=seconds)

    def inspect(self, *, stopped=False):
        current = _verify_config(self.command("config", self.vmid).decode("utf-8"), self.args)
        snap = self.command("config", self.vmid, "--snapshot", self.args.snapshot)
        previous = _verify_config(snap.decode("utf-8"), self.args)
        if (current.get("parent") != self.args.snapshot or current["scsi0"] != previous["scsi0"]
                or hashlib.sha256(snap).hexdigest() != self.args.snapshot_sha256):
            raise ValueError("The ALT VM does not match its reviewed cold snapshot")
        if stopped and self.command("status", self.vmid).strip() != b"status: stopped":
            raise ValueError("The dedicated ALT VM must start the trial stopped")
        return {"vmid": self.args.vmid, "guest_uuid": self.args.guest_uuid,
                "snapshot": self.args.snapshot, "snapshot_sha256": self.args.snapshot_sha256}

    def start(self):
        self.inspect(stopped=True)
        self.command("start", self.vmid, seconds=90)
        for _ in range(36):
            try:
                self.command("guest", "cmd", self.vmid, "ping", seconds=8)
                return
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                time.sleep(3)
        raise TimeoutError("The ALT guest agent did not become ready")

    def submit(self, code):
        self.inspect()
        guard = f"""
from pathlib import Path
if (Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower() != {self.args.guest_uuid!r}
        or sorted(p.name for p in Path('/sys/class/net').iterdir()) != ['lo']):
    raise SystemExit('Unexpected or connected ALT guest')
"""
        return _run("/usr/sbin/qm", "guest", "exec", self.vmid, "--pass-stdin", "1", "--synchronous", "0",
                    "--", "/usr/bin/python3", "-I", "-B", "-", data=(guard + code).encode(), seconds=20)

    def wait(self, pid, *, seconds):
        until = time.monotonic() + seconds
        while time.monotonic() < until:
            try:
                raw = self.command("guest", "exec-status", self.vmid, str(pid), seconds=8)
                if _json(raw)["exited"]:
                    return raw
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                pass
            time.sleep(2)
        raise TimeoutError(f"Guest process {pid} has no confirmed outcome")

    def guest(self, code, *, seconds=40):
        return self.wait(_pid(self.submit(code)), seconds=seconds)

    def put(self, path):
        self.inspect()
        _run("/usr/bin/perl", "-e", UPLOAD, self.vmid, str(path), CAPSULE + "/" + path.name, seconds=180)

    def stop(self):
        self.inspect()
        self.command("shutdown", self.vmid, "--timeout", "45", seconds=60)
        self.inspect(stopped=True)

    def restore(self):
        self.inspect(stopped=True)
        self.command("rollback", self.vmid, self.args.snapshot, "--start", "0", seconds=120)
        self.inspect(stopped=True)


def _store(path, data):
    with path.open("xb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    if sys.platform == "linux":
        fd = os.open(path.parent, os.O_DIRECTORY | os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def _record(directory, name, value):
    _store(directory / (name + ".json"), (json.dumps(value, sort_keys=True, indent=2) + "\n").encode())


def _save(directory, name, raw):
    _store(directory / (name + ".json"), raw)
    return _read_qga(directory, name)[0]


def _pid(raw):
    pid = _json(raw)["pid"]
    if type(pid) is not int or pid <= 0:
        raise ValueError("QEMU did not return a guest process handle")
    return pid


def _install(machine, output, code):
    _record(output, "install-dispatched", {"state": "dispatching"})
    handle = machine.submit(code)
    _store(output / "install-handle.json", handle)
    _save(output, "install", machine.wait(_pid(handle), seconds=240))


def _observe(machine, output, name, source):
    return _json(_save(output, name, machine.guest(source)).encode())


def _wait_for_reboot(machine, boot_id):
    code = "import hashlib\nprint(hashlib.sha256(Path('/proc/sys/kernel/random/boot_id').read_bytes()).hexdigest())"
    until = time.monotonic() + 150
    while time.monotonic() < until:
        try:
            row = _json(machine.guest(code, seconds=10))
            observed = row.get("out-data", "").strip()
            if row.get("exitcode") == 0 and SHA256.fullmatch(observed) and observed != boot_id:
                return
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, TimeoutError):
            pass
        time.sleep(4)
    raise TimeoutError("The ALT guest did not return with a new boot ID")


def _wait_for_retry(machine, output):
    until = time.monotonic() + 150
    while time.monotonic() < until:
        raw = machine.guest(TIMER_STATUS)
        row = _json(raw)
        if row.get("exitcode") != 0:
            _save(output, "retry-timer-error", raw)
        if "ExecMainStatus=21" in row.get("out-data", "").splitlines():
            _save(output, "retry-timer-status", raw)
            return
        time.sleep(6)
    raise TimeoutError("No confirmed automatic retry from the ALT guest")


def execute(args, candidate, machine, paths):
    output = args.output_dir
    before_source = (SOURCE / "observe_alt_factory_offline.py").read_text(encoding="utf-8")
    install_source = (SOURCE / "install_alt_factory_offline.py").read_text(encoding="utf-8")
    output.mkdir(mode=0o700)
    _record(output, "trial", {**machine.inspect(stopped=True), "request_id": candidate["request_id"],
                             "kit_sha256": candidate["artifacts"]["archive"]["sha256"]})
    machine.start()
    before = _observe(machine, output, "before", before_source)
    check_factory_baseline(before)
    _save(output, "stage", machine.guest(f"Path({CAPSULE!r}).mkdir(mode=0o700)\nprint('staged')"))
    for path in paths:
        machine.put(path)
    trial = {
        "guest_uuid": args.guest_uuid, "directory": CAPSULE, "ca_sha256": before["ca_sha256"], "publisher": PUBLISHER,
        "kit_name": f'endpoint-alt-pilot-{candidate["version"]}-1', "artifacts": candidate["artifacts"],
        "members": candidate["members"], "rpm_names": alt_rpm_names(candidate["members"], candidate["version"]),
        "kit_sha256": candidate["artifacts"]["archive"]["sha256"],
    }
    _install(machine, output, install_source + f"\ninstall({trial!r})\n")
    installed = _observe(machine, output, "after-install", before_source)
    check_installation(installed, recorded_source(candidate))
    if (installed["boot_id_digest"] != before["boot_id_digest"]
            or any(installed[key] != before[key] for key in SOFTWARE_BASELINE)):
        raise ValueError("The ALT source baseline changed before the planned reboot")
    _record(output, "reboot-dispatched", {"state": "dispatching"})
    _store(output / "reboot-handle.json", machine.submit(
        "import subprocess\nsubprocess.run(['systemctl', 'reboot', '--no-block'], check=True)"))
    _wait_for_reboot(machine, before["boot_id_digest"])
    _observe(machine, output, "after-reboot", before_source)
    _wait_for_retry(machine, output)
    _observe(machine, output, "after-timer", before_source)
    result = verify(candidate, output)
    _record(output, "offline-result", result)
    machine.stop()
    machine.restore()
    machine.start()
    restored = _observe(machine, output, "restored", before_source)
    check_factory_baseline(restored)
    if any(restored[key] != before[key] for key in SOFTWARE_BASELINE):
        raise ValueError("Restored ALT baseline differs from the trial baseline")
    machine.stop()
    result = {**result, "lab_snapshot_restored": True, "lab_guest_stopped": True}
    _record(output, "result", result)
    return result


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--vmid", type=int, required=True)
    parser.add_argument("--expected-name", required=True)
    parser.add_argument("--guest-uuid", type=UUID, required=True)
    parser.add_argument("--snapshot", required=True)
    parser.add_argument("--snapshot-sha256", required=True)
    parser.add_argument("--reservation-file", type=Path, required=True)
    parser.add_argument("--artifacts-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    try:
        if sys.platform != "linux" or os.geteuid() != 0 or not Path("/etc/pve/qemu-server").is_dir():
            raise ValueError("Run on the approved local Proxmox operator host")
        if (not 100 <= args.vmid < 10**9 or not re.fullmatch(r"endpoint-alt-[a-z0-9-]+", args.expected_name)
                or not args.expected_name.endswith(str(args.vmid))
                or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,62}", args.snapshot)
                or not SHA256.fullmatch(args.snapshot_sha256)):
            raise ValueError("Provide the exact dedicated ALT VM and cold snapshot identities")
        args.guest_uuid = str(args.guest_uuid)
        with args.reservation_file.open("rb") as stream:
            reservation = _json(stream.read(MAX_RECEIPT + 1))
        candidate = verify_recorded_candidate(reservation, "alt", args.artifacts_dir)
        if (candidate["publisher_fingerprint"] != PUBLISHER
                or _fingerprint(PUBLIC_KEY) != {"filename": PUBLIC_KEY.name, **candidate["members"][PUBLIC_KEY.name]}
                or candidate["members"][PUBLIC_KEY.name]["sha256"] != KEY_SHA256):
            raise ValueError("ALT Lab kit publisher differs from the pinned key")
        files = [args.artifacts_dir / row["filename"] for row in candidate["artifacts"].values()] + [PUBLIC_KEY]
        machine = Proxmox(args)
        target = machine.inspect(stopped=True)
        if args.execute:
            import fcntl

            with Path(f"/run/lock/endpoint-alt-factory-{args.vmid}.lock").open("ab") as lock:
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                target = execute(args, candidate, machine, files)
        else:
            target.update(state="preview", kit_sha256=candidate["artifacts"]["archive"]["sha256"])
        print(json.dumps(target, sort_keys=True, indent=2))
    except (OSError, KeyError, TypeError, ValueError, subprocess.SubprocessError) as exc:
        if isinstance(exc, subprocess.SubprocessError):
            parser.exit(1, f"ALT offline runner failed during a host or guest call ({type(exc).__name__}). Preserve its receipts.\n")
        parser.exit(1, f"ALT offline runner failed: {exc}\n")


if __name__ == "__main__":
    main()
