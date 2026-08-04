from __future__ import annotations

import pc_agent.core.machine_identity as machine_identity

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


def test_windows_machine_guid_wins_over_an_ip_environment_override(monkeypatch) -> None:
    """An address-shaped generic override cannot displace the Windows MachineGuid."""
    monkeypatch.setenv("PC_AGENT_MACHINE_ID", "192.0.2.10")
    monkeypatch.setattr(
        machine_identity,
        "_resolve_windows_machine_guid",
        lambda: ("fce11f26-fd68-515c-9f87-0bb1cc84eeb6", "windows_machine_guid"),
    )

    machine_id, source = stable_machine_identity()

    assert machine_id == "fce11f26-fd68-515c-9f87-0bb1cc84eeb6"
    assert source == "windows_machine_guid"


def test_windows_falls_back_when_hostname_environment_override_has_no_machine_guid(monkeypatch, tmp_path) -> None:
    """A host-name generic override cannot create a Windows device identity."""
    fallback_file = tmp_path / "machine_id"
    monkeypatch.setenv("PC_AGENT_MACHINE_ID", "workstation-01")
    monkeypatch.setattr(machine_identity, "_resolve_windows_machine_guid", lambda: None)

    machine_id, source = stable_machine_identity(fallback_file=fallback_file)

    assert source.startswith("file_uuid:")
    assert machine_id != "workstation-01"
    assert fallback_file.read_text(encoding="utf-8") == machine_id
