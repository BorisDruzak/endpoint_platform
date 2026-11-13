import sys
import subprocess

import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from pc_agent.core import device_fingerprint


def test_windows_fingerprint_prefers_stable_hardware_evidence(monkeypatch):

    monkeypatch.delenv("PC_AGENT_ENABLE_WMI_FINGERPRINT", raising=False)
    monkeypatch.setattr(device_fingerprint.platform, "system", lambda: "Windows")
    monkeypatch.setattr(device_fingerprint, "_windows_system_uuid", lambda: "product-uuid")
    monkeypatch.setattr(device_fingerprint, "_windows_system_serial", lambda: "system-serial")
    monkeypatch.setattr(device_fingerprint, "_windows_machine_guid", lambda: "machine-guid")
    monkeypatch.setattr(device_fingerprint, "_windows_boot_volume", lambda: "boot-volume")
    monkeypatch.setattr(device_fingerprint, "_mac_hashes", lambda: ["mac-hash"])

    monkeypatch.setattr(device_fingerprint, "_windows_baseboard", lambda: "baseboard-serial")

    result = device_fingerprint.collect_device_fingerprint()

    assert {"product_uuid", "system_serial", "baseboard"} <= set(result["components"])
    assert "machine_guid" in result["components"]
    assert "boot_volume" in result["components"]
    assert result["mac_hashes"] == ["mac-hash"]


@pytest.fixture
def inventory_windows(monkeypatch):
    monkeypatch.setattr(device_fingerprint.platform, "system", lambda: "Windows")
    native = Path("C:/Windows/System32")
    monkeypatch.setattr("pc_agent.platform.windows.update_paths._native_folder", lambda _: native)
    return str(native / "WindowsPowerShell/v1.0/powershell.exe")


@pytest.mark.parametrize("returncode", [0, 1])
def test_inventory_windows_retries_transient_wmi_error_and_keeps_canonical_values(
    monkeypatch, inventory_windows, returncode,
):
    monkeypatch.setattr(device_fingerprint, "_windows_machine_guid", lambda: "machine-guid")
    monkeypatch.setattr(device_fingerprint, "_windows_boot_volume", lambda: "boot-volume")
    monkeypatch.setattr(device_fingerprint, "_mac_hashes", lambda: ["mac-hash"])
    responses = iter([
        subprocess.CompletedProcess([], returncode, b"", b"Transient PowerShell failure"),
        subprocess.CompletedProcess([], 0, b"product-uuid", b""),
        subprocess.CompletedProcess([], 0, b"", b""),
        subprocess.CompletedProcess([], 0, b"board", b""),
    ])
    def run(command, **kwargs):
        assert command[0] == inventory_windows
        assert "-NonInteractive" in command
        assert "$ErrorActionPreference = 'Stop'" in command[-1]
        assert kwargs["shell"] is False
        return next(responses)

    monkeypatch.setattr(device_fingerprint.subprocess, "run", run)

    result = device_fingerprint.collect_windows_inventory_fingerprint()

    assert result["components"]["product_uuid"] == device_fingerprint._hash("product-uuid")
    assert result["components"]["baseboard"] == device_fingerprint._hash("board")
    assert "system_serial" not in result["components"]
    assert result["mac_hashes"] == ["mac-hash"]


def test_inventory_windows_fails_closed_when_wmi_does_not_finish(monkeypatch, inventory_windows):
    calls = []

    def timeout(command, **kwargs):
        calls.append(kwargs["timeout"])
        raise subprocess.TimeoutExpired(command, kwargs["timeout"])

    monkeypatch.setattr(device_fingerprint.subprocess, "run", timeout)

    with pytest.raises(RuntimeError, match="Inventory WMI evidence unavailable"):
        device_fingerprint.collect_windows_inventory_fingerprint()

    assert len(calls) == 2
