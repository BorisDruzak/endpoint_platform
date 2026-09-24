"""Exercise selected-runtime evidence parsing without touching a live Agent."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


COLLECTOR = Path(__file__).resolve().parents[2] / "tools" / "canary" / "Collect-WindowsAgentPreflight.ps1"


def _run_selected_runtime_reader(root: Path) -> subprocess.CompletedProcess[str]:
    script = r"""
$ErrorActionPreference = 'Stop'
$tokens = $null
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($env:CANARY_TEST_COLLECTOR, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw 'Collector syntax is invalid.' }
foreach ($definition in $ast.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
    Invoke-Expression $definition.Extent.Text
}
# The fixture lives in a test-owned temporary directory and cannot have the
# owner/ACL required for an installed Program Files runtime.
function Assert-TrustedRuntimeAcl { param([string]$Path) }
$selector = [pscustomobject]@{ schema_version = 1; version = '3.2.17'; source_revision = ('c' * 40) }
$installer = [pscustomobject]@{ version = '3.2.16'; source_revision = ('a' * 40) }
$result = Read-SelectedRuntimeEvidence -InstallRoot $env:CANARY_TEST_INSTALL_ROOT -SelectorValue $selector -InstallerProvenance $installer
$result | ConvertTo-Json -Compress -Depth 5
"""
    return subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True, text=True, timeout=30, check=False,
        env={**os.environ, "CANARY_TEST_COLLECTOR": str(COLLECTOR), "CANARY_TEST_INSTALL_ROOT": str(root)},
    )


@pytest.mark.skipif(sys.platform != "win32", reason="Windows PowerShell collector")
def test_zip_evidence_accepts_distinct_installer_and_selected_runtime(tmp_path: Path) -> None:
    selected = tmp_path / "versions" / "3.2.17"
    selected.mkdir(parents=True)
    payload = b"verified runtime"
    (selected / "pc_agent.exe").write_bytes(payload)
    (selected / ".endpoint-update.json").write_text(json.dumps({
        "sha256": "d" * 64, "size": 12345, "version": "3.2.17",
    }), encoding="utf-8")
    (selected / "endpoint-update-manifest.json").write_text(json.dumps({
        "schema_version": 1, "version": "3.2.17", "source_revision": "c" * 40,
        "files": [{"path": "pc_agent.exe", "size": len(payload),
                   "sha256": hashlib.sha256(payload).hexdigest()}],
    }), encoding="utf-8")

    result = _run_selected_runtime_reader(tmp_path)

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["origin"] == "zip"

    (selected / "pc_agent.exe").write_bytes(b"tampered runtime")
    tampered = _run_selected_runtime_reader(tmp_path)
    assert tampered.returncode != 0
    assert "manifest" in tampered.stderr.lower()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows PowerShell collector")
def test_zip_evidence_rejects_missing_receipt(tmp_path: Path) -> None:
    selected = tmp_path / "versions" / "3.2.17"
    selected.mkdir(parents=True)
    (selected / "endpoint-update-manifest.json").write_text("{}", encoding="utf-8")

    result = _run_selected_runtime_reader(tmp_path)

    assert result.returncode != 0


@pytest.mark.skipif(sys.platform != "win32", reason="Windows PowerShell collector")
def test_zip_evidence_rejects_non_array_file_inventory(tmp_path: Path) -> None:
    selected = tmp_path / "versions" / "3.2.17"
    selected.mkdir(parents=True)
    payload = b"verified runtime"
    (selected / "pc_agent.exe").write_bytes(payload)
    (selected / ".endpoint-update.json").write_text(json.dumps({
        "sha256": "d" * 64, "size": 12345, "version": "3.2.17",
    }), encoding="utf-8")
    (selected / "endpoint-update-manifest.json").write_text(json.dumps({
        "schema_version": 1, "version": "3.2.17", "source_revision": "c" * 40,
        "files": {"path": "pc_agent.exe", "size": len(payload),
                  "sha256": hashlib.sha256(payload).hexdigest()},
    }), encoding="utf-8")

    result = _run_selected_runtime_reader(tmp_path)

    assert result.returncode != 0
