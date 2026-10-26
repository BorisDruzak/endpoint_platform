from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


def load_module():
    path = Path("tools/keycloak/render_realm.py")
    spec = importlib.util.spec_from_file_location("render_keycloak_realm", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def pilot():
    return {
        "helpdesk-web": "https://helpdesk.sosnadmin.local/auth/oidc/callback",
        "endpoint-admin": "https://endpoint.sosnadmin.local/admin/auth/oidc/callback",
        "worktime-employee": "https://endpoint.sosnadmin.local/worktime/auth/oidc/callback",
    }


def test_generated_realm_has_no_secrets_and_federation_is_secure_readonly():
    realm = load_module().build_realm(pilot(), "OU=Pilot,DC=sosnadmin,DC=local")
    ldap = realm["components"]["org.keycloak.storage.UserStorageProvider"][0]
    assert ldap["config"]["editMode"] == ["READ_ONLY"]
    assert ldap["config"]["uuidLDAPAttribute"] == ["objectGUID"]
    assert ldap["config"]["connectionUrl"] == ["ldaps://AD-MAIN.sosnadmin.local:636"]
    assert ldap["config"]["syncRegistrations"] == ["false"]
    assert ldap["config"]["bindCredential"] == ["${SSO_LDAP_BIND_PASSWORD}"]
    assert realm["registrationAllowed"] is False
    assert realm["resetPasswordAllowed"] is False
    assert realm["accessTokenLifespan"] <= 300
    assert realm["revokeRefreshToken"] is True
    assert "users" not in realm


@pytest.mark.parametrize("bad", ["http://endpoint.sosnadmin.local/cb", "https://endpoint.sosnadmin.local/*", "https://evil.example/cb", "https://user:pw@endpoint.sosnadmin.local/cb", "https://endpoint.sosnadmin.local/cb?x=1"])
def test_redirects_reject_insecure_wildcard_foreign_and_credential_urls(bad):
    redirects = pilot()
    redirects["endpoint-admin"] = bad
    with pytest.raises(ValueError):
        load_module().build_realm(redirects, "OU=Pilot,DC=sosnadmin,DC=local")


def test_clients_are_independent_confidential_pkce_and_no_password_grant():
    realm = load_module().build_realm(pilot(), "OU=Pilot,DC=sosnadmin,DC=local")
    assert {c["clientId"] for c in realm["clients"]} == set(pilot())
    for client in realm["clients"]:
        assert client["redirectUris"] == [pilot()[client["clientId"]]]
        assert client["publicClient"] is False
        assert client["directAccessGrantsEnabled"] is False
        assert client["serviceAccountsEnabled"] is False
        assert client["attributes"]["pkce.code.challenge.method"] == "S256"
        guid = next(m for m in client["protocolMappers"] if m["name"] == "ad-object-guid")
        assert guid["config"]["user.attribute"] == "LDAP_ID"
        assert guid["config"]["claim.name"] == "ad_object_guid"
        assert not any(m["protocolMapper"] == "oidc-hardcoded-claim-mapper" for m in client["protocolMappers"])


def test_mfa_acr_is_earned_from_required_otp_and_loas():
    realm = load_module().build_realm(pilot(), "OU=Pilot,DC=sosnadmin,DC=local")
    mfa = next(f for f in realm["authenticationFlows"] if f["alias"] == "sso-level-2")
    assert any(e.get("authenticator") == "auth-otp-form" and e["requirement"] == "REQUIRED" for e in mfa["authenticationExecutions"])
    assert realm["attributes"]["acr.loa.map"] == '{"urn:sosnadmin:loa:1":1,"urn:sosnadmin:loa:2":2}'
    assert realm["authenticatorConfig"][1]["config"]["loa-max-age"] == "300"


def test_missing_client_or_unscoped_directory_is_rejected():
    module = load_module()
    with pytest.raises(ValueError):
        module.build_realm({}, "OU=Pilot,DC=sosnadmin,DC=local")
    with pytest.raises(ValueError):
        module.build_realm(pilot(), "DC=sosnadmin,DC=local")


def test_all_nested_components_match_keycloak_2681_export_representation():
    module = load_module()
    realm = module.build_realm(pilot(), "OU=Pilot,DC=sosnadmin,DC=local")
    module.validate_component_exports(realm["components"])
    ldap = realm["components"]["org.keycloak.storage.UserStorageProvider"][0]
    assert "providerType" not in ldap
    for mapper in ldap["subComponents"]["org.keycloak.storage.ldap.mappers.LDAPStorageMapper"]:
        assert "providerType" not in mapper


@pytest.mark.parametrize("mutation", [
    lambda component: component.update(providerType="api-only"),
    lambda component: component.update(parentId="api-only"),
    lambda component: component.update(config={"enabled": True}),
    lambda component: component.update(subComponents={"type": {}}),
])
def test_export_component_validator_rejects_unknown_api_fields_and_wrong_shapes(mutation):
    module = load_module()
    realm = module.build_realm(pilot(), "OU=Pilot,DC=sosnadmin,DC=local")
    ldap = realm["components"]["org.keycloak.storage.UserStorageProvider"][0]
    mutation(ldap)
    with pytest.raises(ValueError):
        module.validate_component_exports(realm["components"])


def test_export_shape_validation_reaches_nested_ldap_mappers():
    module = load_module()
    realm = module.build_realm(pilot(), "OU=Pilot,DC=sosnadmin,DC=local")
    ldap = realm["components"]["org.keycloak.storage.UserStorageProvider"][0]
    mapper = ldap["subComponents"]["org.keycloak.storage.ldap.mappers.LDAPStorageMapper"][0]
    mapper["parentId"] = "api-only"
    with pytest.raises(ValueError):
        module.validate_component_exports(realm["components"])


def test_exact_pilot_uses_object_scope_to_avoid_keycloak_subtree_base_exclusion():
    module = load_module()
    dn = "CN=ssopilot-20261027,OU=TEST,DC=sosnadmin,DC=local"
    realm = module.build_realm(pilot(), dn)
    config = realm["components"]["org.keycloak.storage.UserStorageProvider"][0]["config"]
    assert config["usersDn"] == [dn]
    assert config["searchScope"] == ["0"]
    # Keycloak 26.8.1 LDAPIdentityStore.java lines266-269 omits the base entry
    # from SUBTREE(2), while OBJECT(0) includes that same sole matching entry.
    def retained(scope, result_dn):
        return scope != 2 or dn != result_dn
    assert retained(int(config["searchScope"][0]), dn)
    assert not retained(2, dn)
