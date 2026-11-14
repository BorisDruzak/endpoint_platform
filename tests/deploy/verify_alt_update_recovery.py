"""Run the ALT recovery hook against isolated units on an ALT systemd host.

Copy this script and the two source assets to the dedicated Linux test host.
Run as root with the helper and update-unit paths as positional arguments.
The harness uses temporary Core and updater units and a synthetic selector.
"""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

if os.name != "posix" or os.geteuid() != 0 or len(sys.argv) != 3:
    raise SystemExit("usage: python3 verify_alt_update_recovery.py HELPER UPDATE_UNIT")
helper_source = Path(sys.argv[1]).read_text(encoding="utf-8")
unit_source = Path(sys.argv[2]).read_text(encoding="utf-8")

root = Path(tempfile.mkdtemp(prefix="endpoint-stab04-", dir="/run"))
suffix = root.name.removeprefix("endpoint-stab04-").lower().replace("_", "-")
core = f"endpoint-stab04-{suffix}-core.service"
update = f"endpoint-stab04-{suffix}-update.service"
state_name = f"endpoint-stab04-{suffix}"
state = Path("/var/lib") / state_name
unit_root = Path("/run/systemd/system")
helper = root / "helper"
launcher = root / "launcher"
data = root / "data"
(data / "updates").mkdir(parents=True)
selected = root / "current.json"
phase = root / "phase"
mode = root / "mode"

def ctl(*args, check=True):
    return subprocess.run(["systemctl", *args], capture_output=True, text=True, check=check, timeout=25)

def wait(predicate, explanation):
    for _ in range(180):
        if predicate():
            return
        time.sleep(0.05)
    raise AssertionError(explanation)

helper.write_text(helper_source.replace("/var/lib/endpoint-agent-update/core-stop", str(state / "core-stop"))
     .replace("/var/lib/endpoint-agent", str(data)).replace("/opt/endpoint-agent/launcher", str(launcher))
     .replace("/opt/endpoint-agent", str(root)).replace("endpoint-agent.service", core))
helper.chmod(0o700)
launcher.write_text(f'''#!/usr/bin/python3
from pathlib import Path
import os, time
root = Path({str(root)!r})
mode = (root / "mode").read_text()
if mode == "after-selector":
    (root / "new-selector").write_text("candidate")
    os.replace(root / "new-selector", root / "current.json")
(root / "phase").write_text("entered")
if mode != "success":
    time.sleep(45)
''')
launcher.chmod(0o700)
(unit_root / core).write_text("[Unit]\nStartLimitIntervalSec=0\n[Service]\nType=exec\nExecStart=/usr/bin/sleep infinity\n[Install]\nWantedBy=multi-user.target\n")
(unit_root / update).write_text(unit_source.replace("StateDirectory=endpoint-agent-update", f"StateDirectory={state_name}")
     .replace("/usr/lib/endpoint-agent/apply-pending-alt-update", str(helper))
     .replace("/var/lib/endpoint-agent", str(data)).replace("/opt/endpoint-agent", str(root))
     .replace("TimeoutStartSec=180s", "TimeoutStartSec=2s").replace("TimeoutStopSec=60s", "TimeoutStopSec=10s")
     .replace("StartLimitBurst=3", "StartLimitBurst=20"))

def active():
    return ctl("is-active", "--quiet", core, check=False).returncode == 0

try:
    subprocess.run(["systemd-analyze", "verify", str(unit_root / update), str(unit_root / core)], check=True, timeout=20)
    ctl("daemon-reload")
    ctl("enable", "--runtime", "--now", core)
    for case, action, expected in [
        ("success", "exit", "old"),
        ("before-selector", "kill", "old"),
        ("after-selector", "kill", "candidate"),
        ("before-selector", "timeout", "old"),
        ("after-selector", "timeout", "candidate"),
    ]:
        selected.write_text("old")
        mode.write_text(case)
        phase.unlink(missing_ok=True)
        ctl("reset-failed", update, check=False)
        ctl("start", "--no-block", update)
        wait(phase.exists, "worker did not reach test phase")
        if action == "kill":
            ctl("kill", "--kill-whom=main", "--signal=KILL", update)
        wait(lambda: active() and not (state / "core-stop").exists(), "Core was not restored")
        assert selected.read_text() == expected
        if action == "exit":
            assert ctl("show", "-p", "Result", "--value", update).stdout.strip() == "success"
        else:
            assert ctl("show", "-p", "Result", "--value", update).stdout.strip() == ("signal" if action == "kill" else "timeout")
        print(case, action, "passed")

    # An enabled but manually stopped Core is never acquired.
    ctl("stop", core)
    phase.unlink(missing_ok=True)
    ctl("start", update)
    assert not active() and not phase.exists() and not (state / "core-stop").exists()
    print("manual-stop preserved")

    # An administrator disabling Core while the updater owns its stop wins.
    ctl("start", core)
    mode.write_text("before-selector")
    ctl("start", "--no-block", update)
    wait(phase.exists, "worker did not enter")
    ctl("disable", "--runtime", core)
    ctl("kill", "--kill-whom=main", "--signal=KILL", update)
    wait(lambda: not (state / "core-stop").exists(), "disabled ownership was not cleared")
    assert not active()
    print("disable during update preserved")
    (state / "core-stop").write_text("previous-boot")
    ctl("start", update)
    assert not active() and not (state / "core-stop").exists()
    print("stale boot ownership discarded")
except BaseException:
    print(ctl('status', update, core, '--no-pager', check=False).stdout)
    print(subprocess.run(['journalctl','-u',update,'-n','25','--no-pager'],capture_output=True,text=True).stdout)
    raise
finally:
    ctl("stop", update, core, check=False)
    ctl("disable", "--runtime", core, check=False)
    ctl("reset-failed", update, core, check=False)
    (unit_root / update).unlink(missing_ok=True)
    (unit_root / core).unlink(missing_ok=True)
    ctl("daemon-reload")
    shutil.rmtree(state, ignore_errors=True)
    shutil.rmtree(root)
