from __future__ import annotations

from pc_agent.platform.windows.identity import stable_machine_identity


def test_windows_machine_guid_produces_a_stable_non_network_identity() -> None:
    """Replacing a host name or address must not change MachineGuid identity."""
    machine_id, source = stable_machine_identity(
        machine_guid_reader=lambda: "7A889950-6A2A-4FA7-A59D-4F3AD64655A4"
    )

    assert machine_id == "fce11f26-fd68-515c-9f87-0bb1cc84eeb6"
    assert source == "windows_machine_guid"


def test_windows_machine_identity_falls_back_without_using_hostname_or_ip(tmp_path) -> None:
    """No registry value creates a durable random ID, never a host-derived ID."""
    machine_id, source = stable_machine_identity(
        machine_guid_reader=lambda: None,
        fallback_file=tmp_path / "machine_id",
    )

    assert source.startswith("file_uuid:")
    assert machine_id != "workstation-01"
    assert machine_id != "192.0.2.10"
    assert (tmp_path / "machine_id").read_text(encoding="utf-8") == machine_id
