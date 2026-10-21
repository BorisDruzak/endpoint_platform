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
    results, seen = [], {}
    for value in observations:
        result = evaluate_scenario(value)
        key = (value["baseline"], value["scenario"])
        if key in seen:
            raise EvidenceError("duplicate scenario")
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
    admission = load_evidence(args.admission)
    _exact(admission, {"schema_version", "computer", "baseline_fingerprint", "artifact_sha256", "source_revision", "signer_thumbprint"})
    if admission["schema_version"] != 1 or socket.gethostname().casefold() != admission["computer"].casefold():
        raise EvidenceError("dedicated guest identity differs")
    for key, length in (("baseline_fingerprint", 64), ("artifact_sha256", 64), ("source_revision", 40)):
        _hex(admission[key], length)
    _hex(admission["signer_thumbprint"], 40)
    candidate = args.candidate.resolve(strict=True)
    if candidate.suffix.lower() != ".exe" or candidate.is_symlink():
        raise EvidenceError("candidate path is invalid")
    with candidate.open("rb") as stream:
        if hashlib.file_digest(stream, "sha256").hexdigest() != admission["artifact_sha256"]:
            raise EvidenceError("candidate hash differs")
    # Inputs remain arguments, never interpolated executable PowerShell text.
    script = r'''param($Candidate,$Digest,$Signer,[switch]$CheckOnly)
$ErrorActionPreference='Stop'
if(-not([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'elevation required'}
$pin=[IO.File]::Open($Candidate,'Open','Read','Read')
try {
 if((Get-FileHash -LiteralPath $Candidate -Algorithm SHA256).Hash -ine $Digest){throw 'candidate changed'}
 $signature=Get-AuthenticodeSignature -LiteralPath $Candidate
 if($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -ine $Signer -or $null -eq $signature.TimeStamperCertificate){throw 'signature gate'}
 $owners=@(Get-CimInstance Win32_Process|Where-Object {$_.Name -match '^(msiexec|EndpointAgentSetup.*|endpoint-installer-host)\.exe$'})
 if($owners.Count){throw 'foreign native owner'}
 if($CheckOnly){'{}';exit 0}
 $process=Start-Process -FilePath $Candidate -ArgumentList '--quiet' -PassThru -WindowStyle Hidden
 $process.WaitForExit();$process.Refresh()
 [pscustomobject]@{native_exit=$process.ExitCode;health_verdict='unproven'}|ConvertTo-Json -Compress
}finally{$pin.Dispose()}
'''
    with tempfile.TemporaryDirectory(prefix="endpoint-staged-guest-") as directory:
        script_path = Path(directory) / "run.ps1"
        script_path.write_text(script, encoding="utf-8-sig")
        command = ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(script_path), str(candidate), admission["artifact_sha256"], admission["signer_thumbprint"]]
        subprocess.run([*command, '-CheckOnly'], capture_output=True, text=True, check=True)
        observed = subprocess.run([str(candidate), '--preflight', '--quiet'], capture_output=True, text=True, check=True, timeout=180)
        if baseline_fingerprint(json.loads(observed.stdout)) != admission['baseline_fingerprint']:
            raise EvidenceError('installed baseline differs from admission')
        result = subprocess.run(command, capture_output=True, text=True, check=True)
    return json.loads(result.stdout)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("preflight", "capture", "observe", "verify"):
        commands.add_parser(command).add_argument("evidence", type=Path)
    run = commands.add_parser("run")
    run.add_argument("--execute-dedicated-guest", action="store_true")
    run.add_argument("--admission", type=Path, required=True)
    run.add_argument("--candidate", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.command == "run":
        result = run_on_dedicated_guest(args)
    else:
        value = load_evidence(args.evidence)
        result = verify_matrix(value) if args.command == "verify" else evaluate_scenario(value)
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("verdict") == "pass" else 2


if __name__ == "__main__":
    raise SystemExit(main())
