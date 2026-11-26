"""Verify a Windows Full Setup builder receipt against the signed outputs."""

from argparse import Namespace
import hashlib
import os
from pathlib import Path
import re
import subprocess

from endpoint_contracts.runtime_payload import read_json
from tools.release.agent_candidate_artifacts import MAX_METADATA, _fingerprint, inspect_candidate


ARTIFACT_KEYS = ("msi", "msi_manifest", "setup", "manifest")
THUMBPRINT = re.compile(r"[0-9A-F]{40}")

_VERIFY_AUTHENTICODE = r"""
$ErrorActionPreference = 'Stop'
foreach ($path in @($env:ENDPOINT_BUILD_SETUP_EXE, $env:ENDPOINT_BUILD_SETUP_MSI)) {
    # Keep the same file pinned while Windows verifies it and we hash it.
    $file = [IO.File]::Open($path, 'Open', 'Read', 'Read')
    try {
        $signature = Get-AuthenticodeSignature -LiteralPath $path
        if ($signature.Status -ne 'Valid' -or $signature.SignatureType -ne 'Authenticode' -or
            $null -eq $signature.TimeStamperCertificate -or
            $signature.SignerCertificate.Thumbprint -cne $env:ENDPOINT_BUILD_SIGNER_THUMBPRINT -or
            $signature.SignerCertificate.Subject -cne $env:ENDPOINT_BUILD_SIGNER_SUBJECT) {
            throw 'Unexpected or invalid timestamped Authenticode signature'
        }
        (Get-FileHash -InputStream $file -Algorithm SHA256).Hash.ToLowerInvariant()
    } finally {
        $file.Dispose()
    }
}
"""


def _signed_digests(exe: Path, msi: Path, publisher: str, thumbprint: str) -> list[str]:
    result = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", _VERIFY_AUTHENTICODE],
        env={**os.environ, "ENDPOINT_BUILD_SETUP_EXE": str(exe.absolute()),
             "ENDPOINT_BUILD_SETUP_MSI": str(msi.absolute()), "ENDPOINT_BUILD_SIGNER_SUBJECT": publisher,
             "ENDPOINT_BUILD_SIGNER_THUMBPRINT": thumbprint},
        capture_output=True, stdin=subprocess.DEVNULL, timeout=120, check=False,
    )
    if result.returncode:
        raise ValueError("Windows EXE and MSI require valid timestamped Authenticode from the expected signer")
    return result.stdout.decode("ascii").splitlines()


def inspect_signed_windows_build(receipt_path: Path, binding: dict, publisher: str, thumbprint: str) -> dict:
    from tools.release.agent_qualification import _build_host

    if not _build_host("windows"):
        raise ValueError("Record the signed Windows build on its Windows x64 build worker")
    thumbprint = thumbprint.upper()
    if not THUMBPRINT.fullmatch(thumbprint):
        raise ValueError("Expected a Windows publisher certificate thumbprint")
    with receipt_path.open("rb") as stream:
        raw = stream.read(MAX_METADATA + 1)
    try:
        receipt = read_json(raw, MAX_METADATA)
    except ValueError as error:
        raise ValueError("Invalid Windows qualification build receipt") from error
    expected = {"schema_version": 1, "state": "built", "platform": "windows",
                "artifact": "windows_full_setup", "builder": "packaging/windows/build-setup.ps1", **binding}
    if type(receipt.get("schema_version")) is not int or any(receipt.get(key) != value for key, value in expected.items()):
        raise ValueError("Windows build receipt differs from the bound Full Setup build")
    release = receipt_path.parent / "releases"
    sidecar = release / f'EndpointAgentSetup-{binding["version"]}-x64.release.json'
    candidate = inspect_candidate(Namespace(platform="windows", manifest=sidecar, expected_publisher=publisher,
                                            archive_signature=None, manifest_signature=None), binding)
    artifacts = candidate["artifacts"]
    outputs = [{**artifacts[key], "path": "releases/" + artifacts[key]["filename"]} for key in ARTIFACT_KEYS]
    if receipt.get("outputs") != outputs or any(type(row["size"]) is not int for row in receipt["outputs"]):
        raise ValueError("Windows EXE, MSI or sidecars differ from the build receipt")
    signed = _signed_digests(release / artifacts["setup"]["filename"], release / artifacts["msi"]["filename"],
                             publisher, thumbprint)
    if signed != [artifacts[key]["sha256"] for key in ("setup", "msi")]:
        raise ValueError("Verified Windows Authenticode bytes differ from the build receipt")
    digest = hashlib.sha256(raw).hexdigest()
    if _fingerprint(receipt_path, MAX_METADATA)["sha256"] != digest:
        raise ValueError("Windows build receipt changed during verification")
    return {**candidate, "publisher_thumbprint": thumbprint, "build_receipt_sha256": digest}
