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


def client_enable_api(runtime):
    api = fixture_api(runtime)
    for client_id, callback in runtime.CLIENT_CALLBACKS.items():
        listed = api["/admin/realms/sosnadmin/clients?clientId=" + client_id][0]
        listed["id"] = "id-" + client_id
        detail = json.loads(json.dumps(listed))
        detail.update(protocol="openid-connect", redirectUris=[callback], webOrigins=[],
                      standardFlowEnabled=True, implicitFlowEnabled=False,
                      clientAuthenticatorType="client-secret")
        level = "1" if client_id == "worktime-employee" else "2"
        detail["attributes"].update({"minimum.acr.value": level,
                                    "default.acr.values": "urn:sosnadmin:loa:" + level})
        # Detail-only fields model the actual API shape instead of reusing
        # the collection object, and must not be sent back in enable payloads.
        detail["access"] = {"view": True}
        detail["secret"] = "DUMMY_MEMORY_ONLY_CLIENT_SECRET"
        api["/admin/realms/sosnadmin/clients/id-" + client_id] = detail
    return api


def test_enabling_fixed_clients_is_explicit_and_preserves_detail_secrets(tmp_path):
    runtime = module()
    api = client_enable_api(runtime)
    class Enabler(FakeClient):
        def request(self, method, path, **kwargs):
            if method == "PUT":
                body = kwargs["payload"]
                assert set(body) == {"id", "clientId", "protocol", "enabled", "webOrigins"}
                assert body["enabled"] is True
                assert body["webOrigins"] == []
                assert path == "/admin/realms/sosnadmin/clients/" + body["id"]
                self.calls.append((method, path, body, None))
                api[path]["enabled"] = True
                # Actual26.8.1 derives origin from redirectUris if webOrigins
                # was omitted. An explicit empty list preserves the BFF setup.
                api[path]["webOrigins"] = body.get("webOrigins", [api[path]["redirectUris"][0].rsplit("/api/", 1)[0]])
                return None
            return super().request(method, path, **kwargs)
    client = Enabler(api)
    environment = {"SSO_LDAP_BIND_DN": runtime.BIND_DN, "SSO_LDAP_BIND_PASSWORD": "TEST_BIND_PASSWORD_ONLY"}
    backup = tmp_path / "client-enable-before.json"
    result = runtime.enable_pilot_clients(client, environment, GUID, apply=False, backup_path=backup)
    assert result["status"] == "PilotClientEnablePlan"
    assert not backup.exists()
    assert not any(call[0] == "PUT" for call in client.calls)
    client.calls.clear()
    result = runtime.enable_pilot_clients(client, environment, GUID, apply=True, backup_path=backup)
    assert result["status"] == "PilotClientsEnabledApplicationsUnchanged"
    assert len([call for call in client.calls if call[0] == "PUT"]) == 3
    assert "secret" not in backup.read_text().lower()
    assert all(api["/admin/realms/sosnadmin/clients/id-" + client_id]["secret"] == "DUMMY_MEMORY_ONLY_CLIENT_SECRET" for client_id in runtime.CLIENTS)


def test_client_enable_refuses_wrong_callback_before_any_write(tmp_path):
    runtime = module()
    api = client_enable_api(runtime)
    api["/admin/realms/sosnadmin/clients/id-helpdesk-web"]["redirectUris"] = ["https://helpdesk.sosnadmin.local/*"]
    client = FakeClient(api)
    with pytest.raises(runtime.AcceptanceError):
        runtime.enable_pilot_clients(client, {"SSO_LDAP_BIND_DN": runtime.BIND_DN,
            "SSO_LDAP_BIND_PASSWORD": "TEST_BIND_PASSWORD_ONLY"}, GUID, apply=True, backup_path=tmp_path / "before.json")
    assert not any(call[0] == "PUT" for call in client.calls)


def test_helpdesk_only_normalization_restore_preserves_other_fields_and_receipt(tmp_path):
    runtime = module()
    api = client_enable_api(runtime)
    for client_id in runtime.CLIENTS:
        api["/admin/realms/sosnadmin/clients/id-" + client_id]["webOrigins"] = []
    helpdesk = api["/admin/realms/sosnadmin/clients/id-helpdesk-web"]
    helpdesk["enabled"] = True
    helpdesk["webOrigins"] = ["https://helpdesk.sosnadmin.local"]
    receipt = tmp_path / "original.json"
    original = {"pilot_ad_guid": GUID, "clients": [{"id": "id-" + name, "clientId": name,
                "enabled": False, "redirectUris": [runtime.CLIENT_CALLBACKS[name]]} for name in runtime.CLIENTS]}
    receipt.write_text(json.dumps(original))
    before_receipt = receipt.read_bytes()
    class Restorer(FakeClient):
        def request(self, method, path, **kwargs):
            if method == "PUT":
                assert path.endswith("/id-helpdesk-web")
                assert kwargs["payload"] == {"id": "id-helpdesk-web", "clientId": "helpdesk-web",
                    "protocol": "openid-connect", "enabled": False, "webOrigins": []}
                self.calls.append((method, path, kwargs["payload"], None))
                helpdesk["enabled"] = False
                helpdesk["webOrigins"] = []
                return None
            if "?clientId=" in path:
                name = path.rsplit("=", 1)[1]
                self.calls.append((method, path, None, None))
                return [api["/admin/realms/sosnadmin/clients/id-" + name]]
            return super().request(method, path, **kwargs)
    client = Restorer(api)
    backup = tmp_path / "recovery.json"
    plan = runtime.restore_helpdesk_normalization(client, GUID, receipt_path=receipt, backup_path=backup)
    assert plan["status"] == "HelpdeskNormalizationRestorePlan"
    assert not backup.exists()
    result = runtime.restore_helpdesk_normalization(client, GUID, apply=True, receipt_path=receipt, backup_path=backup)
    assert result["status"] == "HelpdeskNormalizationRestoredAllClientsDisabled"
    assert len([call for call in client.calls if call[0] == "PUT"]) == 1
    assert receipt.read_bytes() == before_receipt
    assert all(api["/admin/realms/sosnadmin/clients/id-" + name]["enabled"] is False for name in runtime.CLIENTS)
    assert helpdesk["secret"] == "DUMMY_MEMORY_ONLY_CLIENT_SECRET"


def enabled_audience_api(runtime):
    api = client_enable_api(runtime)
    for client_id in runtime.CLIENTS:
        listed = api[runtime.PREFIX + "/clients?clientId=" + client_id][0]
        detail = api[runtime.PREFIX + "/clients/id-" + client_id]
        listed["enabled"] = detail["enabled"] = True
        api[runtime.PREFIX + "/clients/id-" + client_id + "/protocol-mappers/models"] = json.loads(json.dumps(detail["protocolMappers"]))
    return api


def test_own_audience_addition_is_planned_additive_and_idempotent(tmp_path):
    runtime = module()
    api = enabled_audience_api(runtime)
    class AudienceClient(FakeClient):
        def request(self, method, path, **kwargs):
            if method == "POST" and path.endswith("/protocol-mappers/models"):
                body = kwargs["payload"]
                client_id = path.split("/clients/id-", 1)[1].split("/", 1)[0]
                assert body == runtime.self_audience_mapper(client_id)
                assert "secret" not in json.dumps(body)
                self.calls.append((method, path, body, None))
                created = dict(body, id="generated-audience-" + client_id)
                created["config"] = dict(created["config"], **{"userinfo.token.claim": "false"})
                api[path].append(created)
                api[path.removesuffix("/protocol-mappers/models")]["protocolMappers"].append(created)
                return None
            return super().request(method, path, **kwargs)
    client = AudienceClient(api)
    env = {"SSO_LDAP_BIND_DN": runtime.BIND_DN, "SSO_LDAP_BIND_PASSWORD": "TEST_BIND_PASSWORD_ONLY"}
    receipt = tmp_path / "audience-before.json"
    result = runtime.add_self_audiences(client, env, GUID, receipt_path=receipt)
    assert result["status"] == "SelfAudienceMapperPlan"
    assert result["missing_mappers"] == 3
    assert not receipt.exists()
    result = runtime.add_self_audiences(client, env, GUID, apply=True, receipt_path=receipt)
    assert result["status"] == "SelfAudienceMappersVerified"
    assert result["created_mappers"] == 3
    assert len([x for x in client.calls if x[0] == "POST" and x[1].endswith("/protocol-mappers/models")]) == 3
    assert all(api[runtime.PREFIX + "/clients/id-" + name]["secret"] == "DUMMY_MEMORY_ONLY_CLIENT_SECRET" for name in runtime.CLIENTS)
    before = receipt.read_bytes()
    count = len(client.calls)
    result = runtime.add_self_audiences(client, env, GUID, apply=True, receipt_path=receipt)
    assert result["created_mappers"] == 0
    assert not any(x[0] == "POST" and x[1].endswith("/protocol-mappers/models") for x in client.calls[count:])
    assert receipt.read_bytes() == before


def test_own_audience_rejects_conflicting_or_cross_client_mapping_before_write(tmp_path):
    runtime = module()
    api = enabled_audience_api(runtime)
    wrong = runtime.self_audience_mapper("endpoint-admin")
    api[runtime.PREFIX + "/clients/id-helpdesk-web/protocol-mappers/models"].append(wrong)
    client = FakeClient(api)
    with pytest.raises(runtime.AcceptanceError):
        runtime.add_self_audiences(client, {"SSO_LDAP_BIND_DN": runtime.BIND_DN,
            "SSO_LDAP_BIND_PASSWORD": "TEST_BIND_PASSWORD_ONLY"}, GUID, apply=True,
            receipt_path=tmp_path / "refused.json")
    assert not (tmp_path / "refused.json").exists()
    assert not any(x[0] == "POST" and x[1].endswith("/protocol-mappers/models") for x in client.calls)


def test_audience_resume_preserves_exact_legacy_receipt_and_default_false_shape(tmp_path):
    runtime = module()
    api = enabled_audience_api(runtime)
    name = "helpdesk-web"
    mapper_path = runtime.PREFIX + "/clients/id-" + name + "/protocol-mappers/models"
    first = dict(runtime.self_audience_mapper(name), id="existing-first-audience")
    api[mapper_path].append(json.loads(json.dumps(first)))
    detail_mapper = json.loads(json.dumps(first))
    del detail_mapper["config"]["userinfo.token.claim"]
    api[runtime.PREFIX + "/clients/id-" + name]["protocolMappers"].append(detail_mapper)
    receipt_path = tmp_path / "legacy-receipt.json"
    receipt = {"pilot_ad_guid": GUID, "clients": [
        {"id": "id-" + name, "clientId": name, "mapper": runtime.self_audience_mapper(name)} for name in runtime.CLIENTS]}
    for entry in receipt["clients"]:
        del entry["mapper"]["config"]["userinfo.token.claim"]
    receipt_path.write_text(json.dumps(receipt))
    original = receipt_path.read_bytes()
    class ResumeClient(FakeClient):
        def request(self, method, path, **kwargs):
            if method == "POST" and path.endswith("/protocol-mappers/models"):
                assert "id-helpdesk-web/" not in path
                self.calls.append((method, path, kwargs["payload"], None))
                created = dict(kwargs["payload"], id="new-" + str(len(self.calls)))
                api[path].append(created)
                api[path.removesuffix("/protocol-mappers/models")]["protocolMappers"].append(created)
                return None
            return super().request(method, path, **kwargs)
    client = ResumeClient(api)
    env = {"SSO_LDAP_BIND_DN": runtime.BIND_DN, "SSO_LDAP_BIND_PASSWORD": "TEST_BIND_PASSWORD_ONLY"}
    result = runtime.add_self_audiences(client, env, GUID, apply=True, receipt_path=receipt_path)
    assert result["created_mappers"] == 2
    assert receipt_path.read_bytes() == original


def test_audience_normalization_accepts_only_absent_false_userinfo_default():
    runtime = module()
    expected = runtime.self_audience_mapper("helpdesk-web")
    legacy = json.loads(json.dumps(expected))
    del legacy["config"]["userinfo.token.claim"]
    assert runtime.canonical_mapper(legacy) == expected
    guid = {"name": "ad-object-guid", "protocol": "openid-connect", "config": {}}
    for key, value in (("userinfo.token.claim", "true"), ("included.custom.audience", "other-client")):
        conflicting = json.loads(json.dumps(expected))
        conflicting["config"][key] = value
        with pytest.raises(runtime.AcceptanceError):
            runtime.checked_audience_mappers([guid, conflicting], "helpdesk-web")


def basic_scope_api(runtime):
    api = enabled_audience_api(runtime)
    basic = {"id": "basic-id", "name": "basic", "protocol": "openid-connect",
             "attributes": {"include.in.token.scope": "false", "display.on.consent.screen": "false"},
             "protocolMappers": runtime.basic_scope_mappers()}
    api[runtime.PREFIX + "/client-scopes"] = [basic]
    api[runtime.PREFIX + "/client-scopes/basic-id/scope-mappings"] = {}
    for name in runtime.CLIENTS:
        path = runtime.PREFIX + "/clients/id-" + name
        detail = api[path]
        detail["protocolMappers"].append(runtime.self_audience_mapper(name))
        detail["defaultClientScopes"] = ["profile", "email", "acr"]
        detail["optionalClientScopes"] = []
        api[path + "/default-client-scopes"] = [{"id": "scope-" + x, "name": x}
                                                for x in detail["defaultClientScopes"]]
    return api


def test_basic_binding_uses_bodyless_additive_api_preserves_secrets_and_is_idempotent(tmp_path):
    runtime = module()
    api = basic_scope_api(runtime)
    class Binder(FakeClient):
        def request(self, method, path, **kwargs):
            if method == "PUT":
                assert path.endswith("/default-client-scopes/basic-id")
                assert kwargs == {}  # No client representation or secret submitted.
                self.calls.append((method, path, None, None))
                base = path.removesuffix("/default-client-scopes/basic-id")
                api[base]["defaultClientScopes"].append("basic")
                api[base + "/default-client-scopes"].append({"id": "basic-id", "name": "basic"})
                return None
            return super().request(method, path, **kwargs)
    client = Binder(api)
    env = {"SSO_LDAP_BIND_DN": runtime.BIND_DN, "SSO_LDAP_BIND_PASSWORD": "TEST_BIND_PASSWORD_ONLY"}
    receipt = tmp_path / "basic.json"
    assert runtime.add_basic_scope(client, env, GUID, receipt_path=receipt)["missing_bindings"] == 3
    assert not receipt.exists()
    assert runtime.add_basic_scope(client, env, GUID, apply=True, receipt_path=receipt)["added_bindings"] == 3
    saved = receipt.read_bytes()
    assert runtime.add_basic_scope(client, env, GUID, apply=True, receipt_path=receipt)["added_bindings"] == 0
    assert len([x for x in client.calls if x[0] == "PUT"]) == 3
    assert receipt.read_bytes() == saved
    assert all(api[runtime.PREFIX + "/clients/id-" + n]["secret"] == "DUMMY_MEMORY_ONLY_CLIENT_SECRET"
               for n in runtime.CLIENTS)


@pytest.mark.parametrize("drift", ["mapper", "roles", "foreign-scope", "receipt"])
def test_basic_binding_rejects_nonbuiltin_scope_and_client_drift_before_write(tmp_path, drift):
    runtime = module()
    api = basic_scope_api(runtime)
    receipt = tmp_path / "basic.json"
    if drift == "mapper":
        api[runtime.PREFIX + "/client-scopes"][0]["protocolMappers"][0]["config"]["claim.value"] = "forged-subject"
    elif drift == "roles":
        api[runtime.PREFIX + "/client-scopes/basic-id/scope-mappings"] = {"realmMappings": [{"name": "admin"}]}
    elif drift == "foreign-scope":
        api[runtime.PREFIX + "/clients/id-helpdesk-web"]["defaultClientScopes"].append("roles")
    else:
        receipt.write_text('{"clients": []}')
    client = FakeClient(api)
    with pytest.raises(runtime.AcceptanceError):
        runtime.add_basic_scope(client, {"SSO_LDAP_BIND_DN": runtime.BIND_DN,
            "SSO_LDAP_BIND_PASSWORD": "TEST_BIND_PASSWORD_ONLY"}, GUID, apply=True, receipt_path=receipt)
    assert not any(x[0] == "PUT" for x in client.calls)
