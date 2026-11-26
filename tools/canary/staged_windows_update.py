"""Bounded, secret-free acceptance evidence for dedicated Windows update tests.

Evidence verification grants no installation authority. ``run`` is a separate,
explicit local Windows guest action; remote transport and credentials remain
outside this module. An installer exit code is never a health verdict.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import socket
import subprocess
import tempfile
from uuid import UUID


class EvidenceError(ValueError):
    """A bounded public observation is invalid or incompatible."""


_BASELINES = {"legacy", "modern", "modern-with-ota"}
_SCENARIOS = {
    "success-cold", "success-warm", "early-crash", "no-proof", "owner-loss",
    "reset-promotion", "reboot-required", "stale-proof", "competing-ota",
    "disk-full", "acl", "hash", "reparse", "conflicting-destination",
}
_CHECKS = {
    "native_registration", "shared_bytes", "full_runtime_tree",
    "private_preservation", "fresh_server_wss", "policy_proof",
    "continuous_online_preparation", "same_ntfs_file_ids", "companions",
}
_FIELDS = {
    "schema_version", "scenario", "baseline", "baseline_fingerprint",
    "source_revision", "artifact_sha256", "operation_id", "terminal",
    "msi_exit", "foundation_before", "core_before", "foundation_after",
    "core_after", "candidate_version", "checks", "durations",
    "payload_capture_bytes", "payload_restore_bytes",
}


def _exact(value, fields):
    if not isinstance(value, dict) or set(value) != fields:
        raise EvidenceError("evidence schema is invalid")


def _hex(value, length):
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{%d}" % length, value) is None:
        raise EvidenceError("identity is invalid")


def load_evidence(path: Path):
    with path.open("rb") as stream:
        raw = stream.read(1024 * 1024 + 1)
    if not raw or len(raw) > 1024 * 1024:
        raise EvidenceError("evidence size is invalid")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise EvidenceError("duplicate evidence key")
            result[key] = value
        return result

    return json.loads(raw.decode("utf-8-sig"), object_pairs_hook=pairs)


def evaluate_scenario(value: dict) -> dict:
    _exact(value, _FIELDS)
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise EvidenceError("evidence version is invalid")
    if value["baseline"] not in _BASELINES or value["scenario"] not in _SCENARIOS:
        raise EvidenceError("scenario is invalid")
    for key, length in (("baseline_fingerprint", 64), ("source_revision", 40), ("artifact_sha256", 64)):
        _hex(value[key], length)
    if str(UUID(value["operation_id"])) != value["operation_id"]:
        raise EvidenceError("operation identity is invalid")
    for key in ("foundation_before", "core_before", "foundation_after", "core_after", "candidate_version"):
        if not isinstance(value[key], str) or re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", value[key]) is None:
            raise EvidenceError("version identity is invalid")
    if value["terminal"] not in {"preparing", "prepared", "switching", "native-settled", "trial", "accepted", "rolling-back", "rolled-back", "preparation-cancelled", "recovery-required"}:
        raise EvidenceError("terminal phase is invalid")
    if value["msi_exit"] is not None and type(value["msi_exit"]) is not int:
        raise EvidenceError("native exit is invalid")
    _exact(value["checks"], _CHECKS)
    if any(type(item) is not bool for item in value["checks"].values()):
        raise EvidenceError("check must be a boolean")
    _exact(value["durations"], {"accepted_seconds", "stop_to_new_wss_seconds"})
    for item in value["durations"].values():
        if item is not None and (type(item) not in (int, float) or not math.isfinite(item) or not 0 <= item <= 86400):
            raise EvidenceError("duration is invalid")
    for key in ("payload_capture_bytes", "payload_restore_bytes"):
        if value[key] is not None and (type(value[key]) is not int or not 0 <= value[key] <= 2**50):
            raise EvidenceError("copy count is invalid")
    unproven = [key for key, result in value["checks"].items() if not result]
    success = value["scenario"].startswith("success-")
    if success:
        if value["terminal"] != "accepted":
            unproven.append("accepted")
        if value["foundation_after"] != value["candidate_version"] or value["core_after"] != value["candidate_version"]:
            unproven.append("candidate_pair")
        if not value["payload_capture_bytes"]:
            unproven.append("single_capture")
        if value["payload_restore_bytes"] != 0:
            unproven.append("payload_restore_bytes")
        for key, limit in (("accepted_seconds", 600), ("stop_to_new_wss_seconds", 120)):
            duration = value["durations"][key]
            if duration is None or duration > limit:
                unproven.append(key)
    else:
        if value["terminal"] not in {"rolled-back", "preparation-cancelled"}:
            unproven.append("rollback_terminal")
        if value["foundation_after"] != value["foundation_before"] or value["core_after"] != value["core_before"]:
            unproven.append("original_pair")
    return {"scenario": value["scenario"], "baseline": value["baseline"], "verdict": "incomplete" if unproven else "pass", "unproven": sorted(unproven)}


def compare_benchmarks(cold: dict, warm: dict) -> dict:
    for value in (cold, warm):
        evaluate_scenario(value)
    if cold["baseline"] != warm["baseline"] or cold["baseline_fingerprint"] != warm["baseline_fingerprint"]:
        raise EvidenceError("benchmark baseline differs")
    if any(cold[key] != warm[key] for key in ("source_revision", "artifact_sha256", "candidate_version")):
        raise EvidenceError("benchmark candidate differs")
    if cold["scenario"] != "success-cold" or warm["scenario"] != "success-warm":
        raise EvidenceError("benchmark samples are invalid")
    return {"comparable": True, "cold": cold["durations"], "warm": warm["durations"]}


def verify_matrix(observations: list) -> dict:
    if not isinstance(observations, list) or len(observations) > 100:
        raise EvidenceError("matrix size is invalid")
    results, seen, baselines = [], {}, {}
    candidate = None
    for value in observations:
        result = evaluate_scenario(value)
        key = (value["baseline"], value["scenario"])
        if key in seen:
            raise EvidenceError("duplicate scenario")
        identity = tuple(value[field] for field in ("candidate_version", "source_revision", "artifact_sha256"))
        if candidate is not None and identity != candidate:
            raise EvidenceError("matrix candidate differs")
        candidate = identity
        installed = tuple(value[field] for field in ("baseline_fingerprint", "foundation_before", "core_before"))
        if value["baseline"] in baselines and baselines[value["baseline"]] != installed:
            raise EvidenceError("matrix baseline differs")
        baselines[value["baseline"]] = installed
        seen[key] = value
        results.append(result)
    required = {(baseline, scenario) for baseline in _BASELINES for scenario in _SCENARIOS}
    missing = sorted(":".join(key) for key in required - set(seen))
    for baseline in _BASELINES:
        if all((baseline, name) in seen for name in ("success-cold", "success-warm")):
            compare_benchmarks(seen[baseline, "success-cold"], seen[baseline, "success-warm"])
    return {"schema_version": 1, "verdict": "pass" if not missing and all(row["verdict"] == "pass" for row in results) else "incomplete", "missing": missing, "results": results}


def baseline_fingerprint(preflight: dict) -> str:
    """Compare verified installed identities without enrollment bytes/digests."""
    if (preflight.get('eligibility') != 'READY_FOR_SETUP_UPGRADE'
            or preflight.get('foundation', {}).get('native_verified') is not True
            or preflight.get('core', {}).get('verified') is not True):
        raise EvidenceError('verified baseline is required')
    result = {}
    for role in ('foundation', 'core'):
        value = preflight[role]
        _hex(value.get('source_revision'), 40)
        _hex(value.get('package_sha256'), 64)
        version = value.get('version')
        if not isinstance(version, str) or re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', version) is None:
            raise EvidenceError('baseline version is invalid')
        keys = ('version', 'source_revision', 'package_sha256')
        result[role] = {key: value[key] for key in keys}
    product = preflight['foundation'].get('product_code')
    if not isinstance(product, str) or re.fullmatch(r'\{[0-9A-Fa-f-]{36}\}', product) is None:
        raise EvidenceError('baseline product is invalid')
    result['foundation']['product_code'] = product.upper()
    return hashlib.sha256(json.dumps(result, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def run_on_dedicated_guest(args) -> dict:
    if not args.execute_dedicated_guest or os.name != "nt":
        raise EvidenceError("explicit dedicated Windows guest execution required")
    return _dedicated_guest(args, execute=True)


def preview_dedicated_guest(args) -> dict:
    if os.name != "nt":
        raise EvidenceError("dedicated Windows guest preview requires Windows")
    return _dedicated_guest(args, execute=False)


def _guest_admission(path):
    admission = load_evidence(path)
    _exact(admission, {"schema_version", "computer", "hardware_uuid", "edition", "build", "candidate_version",
                       "baseline_fingerprint", "artifact_sha256", "source_revision", "signer_thumbprint"})
    if (type(admission["schema_version"]) is not int or admission["schema_version"] != 2
            or not isinstance(admission["computer"], str)
            or not re.fullmatch(r"[a-zA-Z0-9-]{1,63}", admission["computer"])
            or socket.gethostname().casefold() != admission["computer"].casefold()):
        raise EvidenceError("dedicated guest requires an exact profile and schema 2 admission")
    try:
        hardware_id = UUID(admission["hardware_uuid"])
    except (ValueError, TypeError, AttributeError) as error:
        raise EvidenceError("dedicated guest hardware UUID is invalid") from error
    if str(hardware_id) != admission["hardware_uuid"] or hardware_id.int in (0, 2**128 - 1):
        raise EvidenceError("dedicated guest hardware UUID is invalid")
    for key, pattern in (("edition", r"[A-Za-z0-9]{1,40}"), ("build", r"[0-9]{1,10}\.[0-9]{1,10}"),
                         ("candidate_version", r"(0|[1-9][0-9]*)(\.(0|[1-9][0-9]*)){2}")):
        if not isinstance(admission[key], str) or not re.fullmatch(pattern, admission[key]):
            raise EvidenceError("dedicated guest or candidate profile is invalid")
    for key, length in (("baseline_fingerprint", 64), ("artifact_sha256", 64), ("source_revision", 40)):
        _hex(admission[key], length)
    _hex(admission["signer_thumbprint"], 40)
    return admission


# Inputs remain arguments, never interpolated executable PowerShell text.
_WINDOWS_LAB_SCRIPT = r'''param($Candidate,$Digest,$Signer,$Computer,$HardwareUuid,$Edition,$Build,[switch]$CheckOnly)
$ErrorActionPreference='Stop'
if(-not([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'elevation required'}
if($env:COMPUTERNAME -ine $Computer -or (Get-CimInstance Win32_ComputerSystemProduct).UUID -ine $HardwareUuid){throw 'dedicated guest hardware identity differs'}
$windows=Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
if($windows.EditionID -cne $Edition -or "$($windows.CurrentBuild).$($windows.UBR)" -cne $Build){throw 'dedicated guest Windows profile differs'}
$file=Get-Item -LiteralPath $Candidate -Force
if($file -isnot [IO.FileInfo]){throw 'candidate is not a regular file'}
for($entry=$file; $null -ne $entry; ){
 if($entry.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'candidate path uses a reparse point'}
 if($entry -is [IO.FileInfo]){$entry=$entry.Directory}else{$entry=$entry.Parent}
}
$pin=[IO.File]::Open($Candidate,'Open','Read','Read')
try {
 if((Get-FileHash -LiteralPath $Candidate -Algorithm SHA256).Hash -ine $Digest){throw 'candidate changed'}
 $signature=Get-AuthenticodeSignature -LiteralPath $Candidate
 if($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -ine $Signer -or $null -eq $signature.TimeStamperCertificate){throw 'signature gate'}
 if($CheckOnly){
  $out=Join-Path $PSScriptRoot 'preflight.stdout'
  $err=Join-Path $PSScriptRoot 'preflight.stderr'
  $probe=Start-Process -FilePath $Candidate -ArgumentList @('--preflight','--quiet') -PassThru -Wait -WindowStyle Hidden -RedirectStandardOutput $out -RedirectStandardError $err
  $probe.Refresh()
  if($probe.ExitCode -ne 0 -or (Get-Item -LiteralPath $err).Length -ne 0){throw 'native preflight process failed'}
  $size=(Get-Item -LiteralPath $out).Length
  if($size -lt 1 -or $size -gt 32768){throw 'native preflight result size is invalid'}
  [IO.File]::ReadAllText($out)
  exit 0
 }
 # MSI costing during preflight can leave the Windows Installer service running.
 # Recheck until all native owners exit naturally, without stopping a process.
 $idleWait=[Diagnostics.Stopwatch]::StartNew()
 while($true){
  $owners=@(Get-CimInstance Win32_Process|Where-Object {$_.Name -match '^(msiexec|EndpointAgentSetup.*|endpoint-installer-host)\.exe$'})
  if(-not $owners.Count){break}
  $msiService=Get-CimInstance Win32_Service -Filter "Name='msiserver'"
  if($owners.Count -ne 1 -or $owners[0].Name -ine 'msiexec.exe' -or $owners[0].ProcessId -ne $msiService.ProcessId){throw 'foreign native owner'}
  if($idleWait.Elapsed.TotalMinutes -ge 12){throw 'Windows Installer service did not become quiet'}
  Start-Sleep -Seconds 2
 }
 $process=Start-Process -FilePath $Candidate -ArgumentList '--quiet' -PassThru -WindowStyle Hidden
 $process.WaitForExit();$process.Refresh()
 [pscustomobject]@{native_exit=$process.ExitCode;health_verdict='unproven'}|ConvertTo-Json -Compress
}finally{$pin.Dispose()}
'''


def _dedicated_guest(args, *, execute):
    admission = _guest_admission(args.admission)
    candidate = args.candidate.absolute()
    if candidate.suffix.lower() != ".exe" or ".." in candidate.parts:
        raise EvidenceError("candidate path is invalid")
    arguments = ("artifact_sha256", "signer_thumbprint", "computer", "hardware_uuid", "edition", "build")
    with tempfile.TemporaryDirectory(prefix="endpoint-staged-guest-") as directory:
        script_path = Path(directory) / "run.ps1"
        script_path.write_text(_WINDOWS_LAB_SCRIPT, encoding="utf-8-sig")
        command = ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File",
                   str(script_path), str(candidate), *(admission[key] for key in arguments)]
        try:
            observed = subprocess.run([*command, '-CheckOnly'], capture_output=True, text=True, check=True, timeout=180)
        except subprocess.TimeoutExpired:
            raise EvidenceError("native preflight did not return within the observation window") from None
        except subprocess.CalledProcessError as error:
            stderr = error.stderr or ""
            reasons = ("dedicated guest hardware identity differs", "dedicated guest Windows profile differs",
                       "native preflight process failed", "native preflight result size is invalid",
                       "signature gate", "candidate changed", "candidate path uses a reparse point")
            reason = next((reason for reason in reasons if reason in stderr), "PowerShell gate failed")
            raise EvidenceError(f"native preflight refused: {reason}") from None
        if not observed.stdout or len(observed.stdout) > 32768:
            raise EvidenceError("native preflight result size is invalid")
        preflight = json.loads(observed.stdout)
        if (preflight.get("eligibility") != "READY_FOR_SETUP_UPGRADE"
                or preflight.get("target_version") != admission["candidate_version"]
                or preflight.get("pending", {}).get("active_or_degraded") is not False):
            raise EvidenceError("native preflight refused the candidate or installed state")
        if baseline_fingerprint(preflight) != admission["baseline_fingerprint"]:
            raise EvidenceError("native preflight baseline differs from admission")
        if not execute:
            return {"schema_version": 2, "scope": "guest_admission", "state": "ready", **{
                key: admission[key] for key in ("hardware_uuid", "edition", "build", "candidate_version",
                                                "artifact_sha256", "source_revision", "baseline_fingerprint")
            }}
        try:
            result = subprocess.run(command, capture_output=True, text=True, check=True)
        except subprocess.CalledProcessError as error:
            reasons = ("foreign native owner", "Windows Installer service did not become quiet")
            reason = next((item for item in reasons if item in (error.stderr or "")), None)
            if reason is None:
                raise EvidenceError("native execution returned no result; inspect the dedicated guest") from None
            raise EvidenceError(f"native execution refused: {reason}") from None
    return json.loads(result.stdout)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("preflight", "capture", "observe", "verify"):
        commands.add_parser(command).add_argument("evidence", type=Path)
    run = commands.add_parser("run")
    run.add_argument("--execute-dedicated-guest", action="store_true")
    preview = commands.add_parser("preview", help="verify dedicated guest and exact Setup preflight")
    for operation in (preview, run):
        operation.add_argument("--admission", type=Path, required=True)
        operation.add_argument("--candidate", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "run":
            result = run_on_dedicated_guest(args)
        elif args.command == "preview":
            result = preview_dedicated_guest(args)
        else:
            value = load_evidence(args.evidence)
            result = verify_matrix(value) if args.command == "verify" else evaluate_scenario(value)
    except EvidenceError as error:
        parser.exit(2, f"{error}\n")
    print(json.dumps(result, sort_keys=True))
    return 0 if args.command == "preview" or result.get("verdict") == "pass" else 2


if __name__ == "__main__":
    raise SystemExit(main())
