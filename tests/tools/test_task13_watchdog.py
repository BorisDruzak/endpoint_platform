"""Owned synthetic Windows processes only; no VM, SSH, MSI or Agent operations."""
from __future__ import annotations

import base64
import ctypes
from datetime import datetime
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time
import uuid

import pytest

pytestmark = [
    pytest.mark.no_db,
    pytest.mark.skipif(sys.platform != "win32", reason="Windows native handles"),
    pytest.mark.skipif(
        sys.platform == "win32" and not ctypes.windll.shell32.IsUserAnAdmin(),
        reason="protected SYSTEM/Administrators diagnostic root requires elevation",
    ),
]
SCRIPT = Path(__file__).resolve().parents[2] / "tools/canary/Watch-Task13DiagnosticProcess.ps1"
POWERSHELL = shutil.which("powershell.exe")


def wait_file(path: Path, process: subprocess.Popen, seconds: float = 15) -> None:
    deadline = time.monotonic() + seconds
    while not path.exists():
        if process.poll() is not None:
            _, error = process.communicate(timeout=2)
            raise AssertionError("process exited before readiness: " + error.decode(errors="replace"))
        assert time.monotonic() < deadline, "readiness deadline"
        time.sleep(0.02)


def synthetic(
    tmp_path: Path, mode: str, *, stall_capture: bool = False, fail_capture: bool = False,
) -> dict:
    assert POWERSHELL
    # Fresh test root, protected exactly like the dedicated VM diagnostic root.
    root = str(tmp_path).replace("'", "''")
    protect = f"""
$a=[Security.AccessControl.DirectorySecurity]::new()
$a.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
[IO.Directory]::SetAccessControl('{root}',$a)
"""
    subprocess.run(
        [POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", protect],
        check=True, capture_output=True, timeout=10,
    )
    if fail_capture:
        (tmp_path / "capture-state.json").write_text("{}")
    run = str(uuid.uuid4())
    watchdog_args = [
        POWERSHELL, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
        "-File", str(SCRIPT), "-Root", str(tmp_path), "-Run", run, "-Limit", "3",
    ]
    if stall_capture:
        watchdog_args.append("-SyntheticCaptureStall")
    watchdog = subprocess.Popen(watchdog_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    target = None
    try:
        wait_file(tmp_path / "watchdog-ready.json", watchdog)
        root = str(tmp_path).replace("'", "''")
        target_run = "wrong" if mode == "wrong_run" else run
        birth_suffix = "+1" if mode == "wrong_birth" else ""
        body = rf"""
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$me=[Diagnostics.Process]::GetCurrentProcess()
$identity=@{{root='{root}';run='{target_run}';pid=$PID;birth=($me.StartTime.ToUniversalTime().ToFileTimeUtc(){birth_suffix})}}|ConvertTo-Json -Compress
[IO.File]::WriteAllText('{root}\identity.tmp',$identity)
[IO.File]::Move('{root}\identity.tmp','{root}\identity.json')
while(-not(Test-Path -LiteralPath '{root}\watchdog-armed.json')){{Start-Sleep -Milliseconds 20}}
"""
        if mode == "empty":
            body += f"[IO.File]::WriteAllText('{root}\\stages.jsonl','');"
        elif mode == "oversized":
            body += f"$f=[IO.FileStream]::new('{root}\\stages.jsonl',[IO.FileMode]::CreateNew);$f.SetLength(33554433);$f.Dispose();"
        elif mode != "missing":
            body += "[IO.File]::WriteAllText('" + root + "\\stages.jsonl','{\"phase\":\"ENTER\",\"stage\":\"SYNTHETIC_WAIT\"}'+[Environment]::NewLine);"
        if mode == "normal":
            body += "[IO.File]::AppendAllText('" + root + "\\stages.jsonl','{\"phase\":\"RETURN\",\"stage\":\"SYNTHETIC_WAIT\"}'+[Environment]::NewLine)"
        elif mode == "stdin":
            body += "[char[]]$b=New-Object char[] 1;[void][Console]::In.Read($b,0,1)"
        else:
            body += "[Threading.Thread]::Sleep(30000)"
        encoded = base64.b64encode(body.encode("utf-16le")).decode()
        target = subprocess.Popen(
            [POWERSHELL, "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        # Keep stdin open; watchdog must finish without local cancellation.
        watchdog_stdout, watchdog_stderr = watchdog.communicate(timeout=18)
        if mode.startswith("wrong_"):
            assert watchdog.returncode == 2 and target.poll() is None
            assert not (tmp_path / "watchdog-armed.json").exists()
            assert (tmp_path / "watchdog-error.json").exists()
            return {"rejected": True}
        output, error = target.communicate(timeout=3)
        assert watchdog.returncode == 0 and not watchdog_stdout and not watchdog_stderr
        assert not output and not error
        receipt = json.loads((tmp_path / "exit-confirmed.json").read_text())
        identity = json.loads((tmp_path / "identity.json").read_text())
        assert receipt["confirmed"] and receipt["wait_result"] == 0
        assert receipt["pid"] == identity["pid"] and receipt["birth"] == identity["birth"]
        if mode == "normal":
            assert not receipt["terminated"] and receipt["exit_code"] == 0
        else:
            assert receipt["terminated"] and receipt["exit_code"] == 124
            kill = datetime.fromisoformat(receipt["termination_utc"].replace("Z", "+00:00"))
            birth = (identity["birth"] - 116444736000000000) / 10_000_000
            receipt["observed_lifetime"] = kill.timestamp() - birth
            if stall_capture or fail_capture or mode in {"missing", "empty", "oversized"}:
                assert not receipt["capture_complete_before_exit"]
                if fail_capture or mode in {"missing", "empty", "oversized"}:
                    assert receipt["capture_error"] == "IOException"
            else:
                assert receipt["capture_complete_before_exit"]
                capture = json.loads((tmp_path / "capture-state.json").read_text())
                assert capture["capture_complete"] and capture["exit_code"] == 259
                assert json.loads(capture["last_stage"])["stage"] == "SYNTHETIC_WAIT"
                capture_finish = (receipt["capture_finished_utc_ticks"] - 621355968000000000) / 10_000_000
                assert capture_finish < kill.timestamp()
        return receipt
    finally:
        # Only direct, owned local synthetic children; never a remote PID.
        for process in (target, watchdog):
            if process is not None and process.poll() is None:
                process.kill()
                process.wait(timeout=5)


def test_hard_ceiling_leaves_time_for_scheduler(tmp_path: Path) -> None:
    assert synthetic(tmp_path, "sleep")["observed_lifetime"] <= 3


def test_capture_stall_cannot_delay_native_kill(tmp_path: Path) -> None:
    assert synthetic(tmp_path, "sleep", stall_capture=True)["observed_lifetime"] <= 3


def test_capture_write_failure_cannot_claim_complete_or_delay_kill(tmp_path: Path) -> None:
    assert synthetic(tmp_path, "sleep", fail_capture=True)["observed_lifetime"] <= 3


@pytest.mark.parametrize("mode", ["missing", "empty", "oversized"])
def test_bad_journal_remains_incomplete_and_cannot_delay_kill(tmp_path: Path, mode: str) -> None:
    assert synthetic(tmp_path, mode)["observed_lifetime"] <= 3


@pytest.mark.parametrize("mode", ["stdin", "normal", "wrong_run", "wrong_birth"])
def test_native_control_and_identity(tmp_path: Path, mode: str) -> None:
    synthetic(tmp_path, mode)
