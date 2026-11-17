import importlib.util
import json
import os
from pathlib import Path

import pytest


def module():
    path = Path("tools/keycloak/prepare_runtime.py")
    spec = importlib.util.spec_from_file_location("prepare_keycloak_runtime", path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def test_runtime_secrets_are_independent_and_realm_clients_remain_disabled(tmp_path):
    bind_password = "DummyTestPasswordOnly1234_@-!abcdefghijk"
    result = module().prepare_files(tmp_path / "pilot", {
        "bind_dn": "CN=svc-keycloak-ldap,CN=Users,DC=sosnadmin,DC=local",
        "bind_password": bind_password,
    })
    env = result["environment"].read_text(encoding="utf-8")
    lines = dict(line.split("=", 1) for line in env.splitlines())
    keys = ["SSO_HELPDESK_CLIENT_SECRET", "SSO_ENDPOINT_CLIENT_SECRET", "SSO_WORKTIME_CLIENT_SECRET", "SSO_BOOTSTRAP_PASSWORD"]
    assert len({lines[k] for k in keys}) == 4
    assert all(len(lines[k]) >= 48 for k in keys)
    realm = json.loads(result["realm"].read_text(encoding="utf-8"))
    assert not any(client["enabled"] for client in realm["clients"])
    assert bind_password not in result["realm"].read_text(encoding="utf-8")
    ldap = realm["components"]["org.keycloak.storage.UserStorageProvider"][0]
    assert ldap["config"]["usersDn"] == ["CN=ssopilot-20261027,OU=TEST,DC=sosnadmin,DC=local"]
    if os.name == "posix":
        assert result["environment"].stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("input", [
    {"bind_dn": "CN=Administrator,CN=Users,DC=sosnadmin,DC=local", "bind_password": "x" * 40},
    {"bind_dn": "CN=svc-keycloak-ldap,CN=Users,DC=sosnadmin,DC=local", "bind_password": "x" * 40 + "\nINJECT=1"},
    {"bind_dn": "CN=svc-keycloak-ldap,CN=Users,DC=sosnadmin,DC=local", "bind_password": "short"},
])
def test_malformed_or_privileged_bind_input_is_rejected_before_writes(tmp_path, input):
    target = tmp_path / "pilot"
    with pytest.raises(ValueError):
        module().prepare_files(target, input)
    assert not target.exists()


def test_runtime_never_overwrites_or_rotates_existing_secret_inputs(tmp_path):
    target = tmp_path / "pilot"
    target.mkdir()
    with pytest.raises(FileExistsError):
        module().prepare_files(target, {
            "bind_dn": "CN=svc-keycloak-ldap,CN=Users,DC=sosnadmin,DC=local",
            "bind_password": "x" * 40,
        })
    assert list(target.iterdir()) == []


def old_prepared_realm():
    runtime = module()
    realm = runtime._renderer().build_realm(runtime.CALLBACKS, runtime.PILOT_DN)
    def add_api_field(collection):
        for provider_type, components in collection.items():
            for component in components:
                component["providerType"] = provider_type
                add_api_field(component.get("subComponents", {}))
    add_api_field(realm["components"])
    return realm


def test_existing_prepared_realm_repair_removes_only_six_api_fields_and_keeps_secrets(tmp_path):
    runtime = module()
    path = tmp_path / "sosnadmin-realm.json"
    original = json.dumps(old_prepared_realm(), indent=2)
    path.write_text(original, encoding="utf-8")
    environment = tmp_path / "provision.env"
    environment.write_text("DUMMY=unchanged-test-only\n", encoding="utf-8")
    result = runtime.repair_prepared_realm(path, apply=False)
    assert result["removed_fields"] == 6
    assert path.read_text(encoding="utf-8") == original
    assert not path.with_suffix(".before-export-shape.json").exists()
    result = runtime.repair_prepared_realm(path, apply=True)
    assert result["removed_fields"] == 6
    assert json.loads(path.read_text(encoding="utf-8")) == runtime._renderer().build_realm(runtime.CALLBACKS, runtime.PILOT_DN)
    assert path.with_suffix(".before-export-shape.json").read_text(encoding="utf-8") == original
    assert environment.read_text(encoding="utf-8") == "DUMMY=unchanged-test-only\n"
    with pytest.raises(FileExistsError):
        runtime.repair_prepared_realm(path, apply=True)


def test_prepared_realm_repair_refuses_enabled_or_changed_clients(tmp_path):
    runtime = module()
    path = tmp_path / "sosnadmin-realm.json"
    realm = old_prepared_realm()
    realm["clients"][0]["enabled"] = True
    original = json.dumps(realm)
    path.write_text(original, encoding="utf-8")
    with pytest.raises(ValueError):
        runtime.repair_prepared_realm(path, apply=True)
    assert path.read_text(encoding="utf-8") == original


def test_prepared_realm_repair_refuses_unknown_component_fields_without_backup(tmp_path):
    runtime = module()
    path = tmp_path / "sosnadmin-realm.json"
    realm = old_prepared_realm()
    realm["components"]["org.keycloak.storage.UserStorageProvider"][0]["parentId"] = "api-only"
    path.write_text(json.dumps(realm), encoding="utf-8")
    with pytest.raises(ValueError):
        runtime.repair_prepared_realm(path, apply=True)
    assert not path.with_suffix(".before-export-shape.json").exists()
