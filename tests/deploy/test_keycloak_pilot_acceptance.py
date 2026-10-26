import importlib.util
import json
from pathlib import Path

import pytest


def module():
    path = Path("tools/keycloak/pilot_acceptance.py")
    spec = importlib.util.spec_from_file_location("keycloak_pilot_acceptance", path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


GUID = "12345678-1234-4234-8234-123456789abc"


class FakeClient:
    def __init__(self, api):
        self.api = api
        self.calls = []
        self.token = "TOKEN_TEST_ONLY"

    def request(self, method, path, *, payload=None, form=None, authenticated=True):
        self.calls.append((method, path, payload, form))
        if path.endswith("/testLDAPConnection"):
            assert payload["connectionUrl"] == "ldaps://AD-MAIN.sosnadmin.local:636"
            assert payload["bindCredential"] == "TEST_BIND_PASSWORD_ONLY"
            assert payload["startTls"] == "false"
            return None
        return self.api[path]


def fixture_api(module):
    prefix = "/admin/realms/sosnadmin"
    api = {
        prefix: {"registrationAllowed": False, "resetPasswordAllowed": False,
                 "browserFlow": "sso-browser", "attributes": {"acr.loa.map": json.dumps({module.MFA_ACR: 2})}},
        prefix + "/components?type=org.keycloak.storage.UserStorageProvider&name=sosnadmin-ad-readonly": [{
            "id": "ldap-id", "providerId": "ldap", "providerType": "org.keycloak.storage.UserStorageProvider", "config": {
                "editMode": ["READ_ONLY"], "connectionUrl": ["ldaps://AD-MAIN.sosnadmin.local:636"],
                "uuidLDAPAttribute": ["objectGUID"], "usersDn": [module.PILOT_DN], "syncRegistrations": ["false"], "searchScope": ["0"]}}],
        prefix + "/users?username=ssopilot-20261027&exact=true&max=2&briefRepresentation=false": [{
            "id": "pilot-id", "username": "ssopilot-20261027", "enabled": True,
            "federationLink": "ldap-id", "attributes": {"LDAP_ID": [GUID]}}],
        prefix + "/authentication/flows/sso-level-2/executions": [
            {"providerId": "conditional-level-of-authentication", "requirement": "REQUIRED", "authenticationConfig": "loa-id"},
            {"providerId": "auth-otp-form", "requirement": "REQUIRED"}],
        prefix + "/authentication/config/loa-id": {"config": {"loa-condition-level": "2", "loa-max-age": "300"}},
    }
    for client_id in module.CLIENTS:
        api[prefix + "/clients?clientId=" + client_id] = [{
            "clientId": client_id, "enabled": False, "publicClient": False,
            "directAccessGrantsEnabled": False, "serviceAccountsEnabled": False,
            "attributes": {"pkce.code.challenge.method": "S256"},
            "protocolMappers": [{"name": "ad-object-guid", "config": {"user.attribute": "LDAP_ID", "claim.name": "ad_object_guid", "id.token.claim": "true"}}],
        }]
    return api


def test_inventory_is_bounded_to_pilot_and_does_not_output_credentials():
    runtime = module()
    client = FakeClient(fixture_api(runtime))
    result = runtime.inspect_pilot(client, {"SSO_LDAP_BIND_DN": runtime.BIND_DN,
        "SSO_LDAP_BIND_PASSWORD": "TEST_BIND_PASSWORD_ONLY"}, GUID)
    assert result["pilot_guid_matches"] is True
    assert result["clients_disabled"] is True
    assert result["mfa_flow_required"] is True
    assert len(client.calls) <= 12
    posts = [call for call in client.calls if call[0] == "POST"]
    assert len(posts) == 2
    assert {call[2]["action"] for call in posts} == {"testConnection", "testAuthentication"}
    assert "PASSWORD" not in json.dumps(result)
    assert "TOKEN" not in json.dumps(result)
    assert not any(method in {"PUT", "DELETE"} for method, *_ in client.calls)


def test_guid_mismatch_refuses_acceptance():
    runtime = module()
    client = FakeClient(fixture_api(runtime))
    with pytest.raises(runtime.AcceptanceError):
        runtime.inspect_pilot(client, {"SSO_LDAP_BIND_DN": runtime.BIND_DN,
            "SSO_LDAP_BIND_PASSWORD": "TEST_BIND_PASSWORD_ONLY"}, "87654321-1234-4234-8234-123456789abc")


def test_enabled_client_or_optional_otp_is_not_accepted():
    runtime = module()
    for mutation in ("client", "otp"):
        api = fixture_api(runtime)
        if mutation == "client":
            api["/admin/realms/sosnadmin/clients?clientId=helpdesk-web"][0]["enabled"] = True
        else:
            api["/admin/realms/sosnadmin/authentication/flows/sso-level-2/executions"][1]["requirement"] = "OPTIONAL"
        with pytest.raises(runtime.AcceptanceError):
            runtime.inspect_pilot(FakeClient(api), {"SSO_LDAP_BIND_DN": runtime.BIND_DN,
                "SSO_LDAP_BIND_PASSWORD": "TEST_BIND_PASSWORD_ONLY"}, GUID)


def test_http_surface_rejects_writes_and_nonlocal_paths_before_io():
    runtime = module()
    client = runtime.LocalAdminClient()
    for method, path in (("PUT", "/admin/realms/sosnadmin"), ("GET", "https://evil.example"),
                         ("POST", "/admin/realms/sosnadmin/logout-all")):
        with pytest.raises(runtime.AcceptanceError):
            client.request(method, path)


def test_scope_repair_updates_only_scope_after_review_and_preserves_secrets(tmp_path):
    runtime = module()
    component_path = "/admin/realms/sosnadmin/components/ldap-id"
    api = fixture_api(runtime)
    component = api["/admin/realms/sosnadmin/components?type=org.keycloak.storage.UserStorageProvider&name=sosnadmin-ad-readonly"][0]
    component["config"]["searchScope"] = ["2"]
    component["config"]["bindCredential"] = ["**********"]
    api[component_path] = component
    class RepairClient(FakeClient):
        def request(self, method, path, **kwargs):
            if method == "PUT":
                self.calls.append((method, path, kwargs["payload"], None))
                # Keycloak's audit StripSecretsUtils requires both metadata
                # fields even though the model config updater can merge keys.
                assert kwargs["payload"] == {
                    "providerType": "org.keycloak.storage.UserStorageProvider",
                    "providerId": "ldap", "config": {"searchScope": ["0"]}}
                api[path]["config"]["searchScope"] = ["0"]
                return None
            return super().request(method, path, **kwargs)
    client = RepairClient(api)
    backup = tmp_path / "scope-before.json"
    plan = runtime.repair_exact_pilot_scope(client, apply=False, backup_path=backup)
    assert plan["status"] == "ExactPilotScopeRepairPlan"
    assert not backup.exists()
    result = runtime.repair_exact_pilot_scope(client, apply=True, backup_path=backup)
    assert result["status"] == "ExactPilotScopeRepaired"
    assert json.loads(backup.read_text())["old_search_scope"] == "2"
    assert api[component_path]["config"]["bindCredential"] == ["**********"]
    assert len([call for call in client.calls if call[0] == "PUT"]) == 1
    assert "Credential" not in backup.read_text()


def test_scope_repair_refuses_scope_or_pilot_dn_drift_and_enabled_client(tmp_path):
    runtime = module()
    for mutation in ("scope", "dn", "client"):
        api = fixture_api(runtime)
        component = api["/admin/realms/sosnadmin/components?type=org.keycloak.storage.UserStorageProvider&name=sosnadmin-ad-readonly"][0]
        component["config"]["searchScope"] = ["2"]
        if mutation == "scope":
            component["config"]["searchScope"] = ["1"]
        elif mutation == "dn":
            component["config"]["usersDn"] = ["OU=TEST,DC=sosnadmin,DC=local"]
        else:
            api["/admin/realms/sosnadmin/clients?clientId=helpdesk-web"][0]["enabled"] = True
        backup = tmp_path / (mutation + ".json")
        with pytest.raises(runtime.AcceptanceError):
            runtime.repair_exact_pilot_scope(FakeClient(api), apply=True, backup_path=backup)
        assert not backup.exists()
