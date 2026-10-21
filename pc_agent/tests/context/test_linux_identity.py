"""Unqualified directory names cannot merge unrelated domain identities."""
import pytest


def test_os_uid_sid_and_original_upn_establish_domain_identity():
    from pc_agent.platform.linux.identity import resolve_login

    result = resolve_login(2000, "worker", directory_lookup=lambda uid, name: ("S-1-5-21-1-2-3-1001", "worker@first.example"), local_lookup=lambda uid: None)
    other = resolve_login(2001, "worker", directory_lookup=lambda uid, name: ("S-1-5-21-4-5-6-1001", "worker@second.example"), local_lookup=lambda uid: None)
    assert result == "worker@first.example" and other == "worker@second.example"
    assert result != other


@pytest.mark.parametrize("directory", [None, ("not-a-sid", "worker@domain.example"), ("S-1-5-21-1-2-3-1001", "worker")])
def test_unverified_directory_name_remains_unknown(directory):
    from pc_agent.platform.linux.identity import resolve_login

    assert resolve_login(2000, "worker", directory_lookup=lambda *a: directory, local_lookup=lambda uid: None) is None


def test_local_identity_is_bound_to_verified_passwd_uid_and_host():
    from pc_agent.platform.linux.identity import resolve_login

    assert resolve_login(1000, "operator", directory_lookup=lambda *a: None, local_lookup=lambda uid: "operator", hostname="workstation.example") == "workstation.example\\operator"
    assert resolve_login(1000, "operator", directory_lookup=lambda *a: None, local_lookup=lambda uid: "other", hostname="workstation.example") is None
