import sys
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
