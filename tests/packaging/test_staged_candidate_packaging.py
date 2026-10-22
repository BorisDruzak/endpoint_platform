"""Signed Setup carries an MSI-bound Core transport and its disk allocation."""
from pathlib import Path
from types import SimpleNamespace

from pc_agent.tests.windows.test_setup_entry import _write_public_payload
from pc_agent.platform.windows import setup_entry

ROOT = Path(__file__).resolve().parents[2]


def test_embedded_archive_is_passed_to_native_owner(tmp_path, monkeypatch):
    _write_public_payload(tmp_path)
    archive = tmp_path / 'EndpointCore.zip'
    archive.write_bytes(b'internal archive fixture')
    seen = []
    monkeypatch.setattr(setup_entry, '_embedded_recovery_operation', lambda _: None)
    monkeypatch.setattr(setup_entry.subprocess, 'run', lambda command, **kw: seen.append(command) or SimpleNamespace(returncode=0))
    setup_entry._install_embedded_msi(tmp_path / 'EndpointAgent.msi')
    assert seen[0][seen[0].index('-CoreArchivePath') + 1] == str(archive)


def test_setup_spec_and_builder_require_internal_archive():
    spec = (ROOT / 'pc_agent/pyinstaller_windows_setup.spec').read_text()
    build = (ROOT / 'packaging/windows/build-setup.ps1').read_text()
    assert '_public_payload("ENDPOINT_SETUP_CORE_ARCHIVE", "EndpointCore.zip")' in spec
    assert '(str(setup_core_archive), "payload")' in spec
    assert 'build-update-zip.ps1' in build
    assert '$env:ENDPOINT_SETUP_CORE_ARCHIVE = $setupCoreArchive' in build


def test_native_owner_pins_archive_and_recovery_uses_same_fixed_cache():
    wrapper = (ROOT / 'packaging/windows/Install-EndpointAgentCanary.ps1').read_text()
    assert '[string]$CoreArchivePath' in wrapper
    assert "'EndpointCore.zip'" in wrapper
    assert '$coreArchivePin.Dispose()' in wrapper


def test_owner_records_launch_and_execution_separately_without_changing_grants():
    wrapper = (ROOT / 'packaging/windows/Install-EndpointAgentCanary.ps1').read_text()
    assert 'launch_seconds=$launchSeconds' in wrapper
    assert 'total_seconds=$phaseTimer.Elapsed.TotalSeconds' in wrapper
    assert 'owner-phase-metrics-' in wrapper
