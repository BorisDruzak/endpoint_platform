"""Bounded pilot inventory; default PlanOnly, --run performs approved probes.

Only local loopback HTTP is used for the root operator's Admin REST requests.
GET of the fixed synthetic username may import that single LDAP identity.
No client enablement, AD change, bulk sync, password reset or role assignment.
The separate --repair-exact-pilot-scope mode plans a one-field provider update;
only adding --apply permits that update, with unchanged exact user DN/secrets.
Official pinned source for LDAP diagnostic POST and JSON shape:
https://github.com/keycloak/keycloak/blob/26.8.1/federation/ldap/src/main/java/org/keycloak/services/resources/admin/TestLdapConnectionResource.java
https://github.com/keycloak/keycloak/blob/26.8.1/core/src/main/java/org/keycloak/representations/idm/TestLdapConnectionRepresentation.java
Other GET contracts: https://www.keycloak.org/docs-api/26.8.1/rest-api/index.html
"""
from __future__ import annotations

import argparse
import copy
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid


BASE = "http://127.0.0.1:8088"
PREFIX = "/admin/realms/sosnadmin"
TOKEN_PATH = "/realms/master/protocol/openid-connect/token"
LDAP_TEST_PATH = PREFIX + "/testLDAPConnection"
ENV_FILE = Path("/run/keycloak-provision-20261027/provision.env")
BIND_DN = "CN=svc-keycloak-ldap,CN=Users,DC=sosnadmin,DC=local"
PILOT_DN = "CN=ssopilot-20261027,OU=TEST,DC=sosnadmin,DC=local"
CLIENTS = ("helpdesk-web", "endpoint-admin", "worktime-employee")
CLIENT_CALLBACKS = {
    "helpdesk-web": "https://helpdesk.sosnadmin.local/api/web/session/oidc/callback",
    "endpoint-admin": "https://endpoint.sosnadmin.local/auth/admin/callback",
    "worktime-employee": "https://endpoint.sosnadmin.local/auth/employee/callback",
}
MFA_ACR = "urn:sosnadmin:loa:2"
STORAGE_PROVIDER_TYPE = "org.keycloak.storage.UserStorageProvider"


def self_audience_mapper(client_id):
    require(client_id in CLIENTS, "AudienceTargetClientProhibited")
    return {"name": "self-introspection-audience", "protocol": "openid-connect",
            "protocolMapper": "oidc-audience-mapper",
            "config": {"included.client.audience": client_id, "access.token.claim": "true",
                       "id.token.claim": "false", "introspection.token.claim": "true",
                       "userinfo.token.claim": "false"}}


def scope_update_payload():
    # Audit serialization resolves provider properties from this representation,
    # not from the existing model. Omitting either identifier causes HTTP500 in
    # StripSecretsUtils even though config-key merging itself supports partials.
    return {"providerType": STORAGE_PROVIDER_TYPE, "providerId": "ldap",
            "config": {"searchScope": ["0"]}}


class AcceptanceError(Exception):
    """Contains only fixed, non-secret diagnostic codes authored below."""


def require(condition, code):
    if not condition:
        raise AcceptanceError(code)


class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise AcceptanceError("RedirectProhibited")


class LocalAdminClient:
    def __init__(self, *, request_budget=16):
        require(1 <= request_budget <= 48, "InvalidRequestBudget")
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirects())
        self.token = None
        self.requests = 0
        self.scope_write_path = None
        self.client_enable_payloads = {}
        self.audience_mapper_payloads = {}
        self.basic_scope_write_paths = set()
        self.request_budget = request_budget

    def request(self, method, path, *, payload=None, form=None, authenticated=True):
        scope_write = (method == "PUT" and path == self.scope_write_path and
                       payload == scope_update_payload() and form is None)
        enable_write = (method == "PUT" and path in self.client_enable_payloads and
                        payload == self.client_enable_payloads[path] and form is None)
        mapper_write = (method == "POST" and path in self.audience_mapper_payloads and
                        payload == self.audience_mapper_payloads[path] and form is None)
        basic_write = (method == "PUT" and path in self.basic_scope_write_paths and payload is None and form is None)
        require(method == "GET" or (method == "POST" and path in {TOKEN_PATH, LDAP_TEST_PATH}) or scope_write or enable_write or mapper_write or basic_write, "MutationProhibited")
        if scope_write:
            self.scope_write_path = None  # Permit exactly one reviewed field update.
        if enable_write:
            del self.client_enable_payloads[path]
        if mapper_write:
            del self.audience_mapper_payloads[path]
        if basic_write:
            self.basic_scope_write_paths.remove(path)
        require(path == TOKEN_PATH or path.startswith(PREFIX + "/") or path == PREFIX, "PathProhibited")
        require(not path.startswith("//") and ".." not in path and "\r" not in path and "\n" not in path, "PathProhibited")
        self.requests += 1
        require(self.requests <= self.request_budget, "RequestBudgetExceeded")
        headers = {"Accept": "application/json"}
        data = None
        if payload is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(payload).encode("utf-8")
        if form is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            data = urllib.parse.urlencode(form).encode("ascii")
        if authenticated:
            require(bool(self.token), "AdminTokenMissing")
            headers["Authorization"] = "Bearer " + self.token
        request = urllib.request.Request(BASE + path, data=data, method=method, headers=headers)
        try:
            with self.opener.open(request, timeout=10) as response:
                body = response.read(1024 * 1024 + 1)
                require(len(body) <= 1024 * 1024, "ResponseTooLarge")
                return json.loads(body) if body else None
        except urllib.error.HTTPError as error:
            raise AcceptanceError(f"LocalAdminHTTP{error.code}") from None
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, UnicodeError):
            raise AcceptanceError("LocalAdminRequestFailed") from None

    def login(self, password):
        result = self.request("POST", TOKEN_PATH, authenticated=False, form={
            "grant_type": "password", "client_id": "admin-cli",
            "username": "sso-bootstrap", "password": password,
        })
        require(isinstance(result, dict) and isinstance(result.get("access_token"), str), "AdminAuthenticationFailed")
        self.token = result["access_token"]


def inspect_pilot(client, environment, expected_guid, *, expected_clients_enabled=False):
    require(str(uuid.UUID(expected_guid)) == expected_guid, "ExpectedGuidMustBeCanonical")
    require(environment.get("SSO_LDAP_BIND_DN") == BIND_DN, "UnexpectedBindIdentity")
    require(bool(environment.get("SSO_LDAP_BIND_PASSWORD")), "BindCredentialMissing")
    realm = client.request("GET", PREFIX)
    require(realm.get("registrationAllowed") is False and realm.get("resetPasswordAllowed") is False, "RealmLocalPasswordSurfaceEnabled")
    require(realm.get("browserFlow") == "sso-browser", "UnexpectedBrowserFlow")
    acr = json.loads(realm.get("attributes", {}).get("acr.loa.map", "{}"))
    require(acr.get(MFA_ACR) == 2, "MfaAcrMappingMissing")
    components = client.request("GET", PREFIX + "/components?type=org.keycloak.storage.UserStorageProvider&name=sosnadmin-ad-readonly")
    require(isinstance(components, list) and len(components) == 1, "AmbiguousLdapProvider")
    component = components[0]
    require(component.get("providerId") == "ldap", "UnexpectedStorageProvider")
    config = component.get("config", {})
    for name, expected in {"editMode": "READ_ONLY", "uuidLDAPAttribute": "objectGUID",
                           "usersDn": PILOT_DN, "syncRegistrations": "false", "searchScope": "0",
                           "connectionUrl": "ldaps://AD-MAIN.sosnadmin.local:636"}.items():
        require(config.get(name) == [expected], "UnexpectedLdapConfiguration")
    for action in ("testConnection", "testAuthentication"):
        client.request("POST", LDAP_TEST_PATH, payload={
            "action": action, "connectionUrl": "ldaps://AD-MAIN.sosnadmin.local:636",
            "bindDn": BIND_DN, "bindCredential": environment["SSO_LDAP_BIND_PASSWORD"],
            "useTruststoreSpi": "always", "connectionTimeout": "5000",
            "componentId": component["id"], "startTls": "false", "authType": "simple",
        })
    users = client.request("GET", PREFIX + "/users?username=ssopilot-20261027&exact=true&max=2&briefRepresentation=false")
    require(isinstance(users, list) and len(users) == 1, "AmbiguousOrMissingPilot")
    pilot = users[0]
    require(pilot.get("username") == "ssopilot-20261027" and pilot.get("enabled") is True, "UnexpectedPilotState")
    require(pilot.get("federationLink") == component["id"], "PilotNotLdapFederated")
    require(pilot.get("attributes", {}).get("LDAP_ID") == [expected_guid], "PilotAdGuidMismatch")
    for client_id in CLIENTS:
        clients = client.request("GET", PREFIX + "/clients?clientId=" + client_id)
        require(isinstance(clients, list) and len(clients) == 1, "AmbiguousOrMissingClient")
        application = clients[0]
        require(application.get("clientId") == client_id and application.get("enabled") is expected_clients_enabled, "PilotClientStateMismatch")
        require(application.get("publicClient") is False and application.get("directAccessGrantsEnabled") is False and
                application.get("serviceAccountsEnabled") is False, "UnexpectedClientGrantConfiguration")
        require(application.get("attributes", {}).get("pkce.code.challenge.method") == "S256", "PkceS256Missing")
        mappings = [mapper for mapper in application.get("protocolMappers", []) if mapper.get("name") == "ad-object-guid"]
        require(len(mappings) == 1 and mappings[0].get("config", {}).get("user.attribute") == "LDAP_ID" and
                mappings[0]["config"].get("claim.name") == "ad_object_guid" and
                mappings[0]["config"].get("id.token.claim") == "true", "AdGuidClaimMapperMissing")
    executions = client.request("GET", PREFIX + "/authentication/flows/sso-level-2/executions")
    otp = [execution for execution in executions if execution.get("providerId") == "auth-otp-form"]
    condition = [execution for execution in executions if execution.get("providerId") == "conditional-level-of-authentication"]
    require(len(otp) == 1 and otp[0].get("requirement") == "REQUIRED", "RequiredOtpMissing")
    require(len(condition) == 1 and condition[0].get("requirement") == "REQUIRED" and
            bool(condition[0].get("authenticationConfig")), "RequiredMfaLevelConditionMissing")
    configuration_id = urllib.parse.quote(condition[0]["authenticationConfig"], safe="")
    condition_config = client.request("GET", PREFIX + "/authentication/config/" + configuration_id)
    require(condition_config.get("config", {}).get("loa-condition-level") == "2" and
            condition_config["config"].get("loa-max-age") == "300", "MfaLevelOrAgeMismatch")
    return {"status": "PilotInventoryVerified", "ldap_tls_connection": True,
            "ldap_readonly_bind": True, "pilot_guid_matches": True,
            "clients_disabled": not expected_clients_enabled, "mfa_flow_required": True,
            "browser_mfa_and_token_flow_tested": False}


def repair_exact_pilot_scope(client, *, apply=False,
                             backup_path=ENV_FILE.parent / "ldap-scope-before-audit-v2.json"):
    """Change only this exact pilot's scope2 to scope0 with disabled clients.

    ComponentResource.updateComponent / RepresentationToModel.updateComponent
    at26.8.1 merge supplied config keys and preserve omitted secret fields.
    The PUT changes only searchScope and includes unchanged providerType/Id for
    StripSecretsUtils audit serialization. It contains no credential fields.
    """
    components = client.request("GET", PREFIX + "/components?type=org.keycloak.storage.UserStorageProvider&name=sosnadmin-ad-readonly")
    require(isinstance(components, list) and len(components) == 1, "AmbiguousLdapProvider")
    component = components[0]
    require(component.get("providerId") == "ldap" and component.get("providerType") == STORAGE_PROVIDER_TYPE and
            bool(component.get("id")), "UnexpectedStorageProvider")
    config = component.get("config", {})
    for name, expected in {"searchScope": "2", "usersDn": PILOT_DN, "editMode": "READ_ONLY",
                           "uuidLDAPAttribute": "objectGUID", "syncRegistrations": "false",
                           "connectionUrl": "ldaps://AD-MAIN.sosnadmin.local:636"}.items():
        require(config.get(name) == [expected], "ScopeRepairPreconditionFailed")
    for client_id in CLIENTS:
        applications = client.request("GET", PREFIX + "/clients?clientId=" + client_id)
        require(isinstance(applications, list) and len(applications) == 1 and
                applications[0].get("clientId") == client_id and applications[0].get("enabled") is False,
                "ScopeRepairRequiresDisabledClients")
    if not apply:
        return {"status": "ExactPilotScopeRepairPlan", "old_search_scope": "2",
                "new_search_scope": "0", "user_dn_unchanged": True,
                "secret_update_fields": 0, "clients_disabled": True}
    path = PREFIX + "/components/" + urllib.parse.quote(component["id"], safe="")
    baseline = copy.deepcopy(component)
    require(client.request("GET", path) == baseline, "ProviderChangedConcurrently")
    # This backup intentionally contains no secret or full configuration values.
    # It is enough to review/revert this one non-secret field, root0600 only.
    metadata = {"component_id": component["id"], "users_dn": PILOT_DN,
                "old_search_scope": "2", "new_search_scope": "0"}
    descriptor = os.open(backup_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(metadata, stream)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    client.scope_write_path = path
    client.request("PUT", path, payload=scope_update_payload())
    expected_component = copy.deepcopy(baseline)
    expected_component["config"]["searchScope"] = ["0"]
    require(client.request("GET", path) == expected_component, "UnexpectedProviderChangeAfterScopeRepair")
    return {"status": "ExactPilotScopeRepaired", "user_dn_unchanged": True,
            "secret_update_fields": 0, "other_configuration_unchanged": True,
            "clients_disabled": True}


def read_private_environment():
    metadata = ENV_FILE.lstat()
    require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 0 and
            metadata.st_mode & 0o777 == 0o600 and metadata.st_nlink == 1, "PrivateProvisionEnvironmentRequired")
    require(metadata.st_size <= 16384, "ProvisionEnvironmentTooLarge")
    environment = {}
    for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
        require("=" in line, "InvalidProvisionEnvironment")
        name, value = line.split("=", 1)
        require(name not in environment, "DuplicateProvisionEnvironmentKey")
        environment[name] = value
    require(bool(environment.get("SSO_BOOTSTRAP_PASSWORD")), "BootstrapCredentialMissing")
    return environment


def enable_pilot_clients(client, environment, expected_guid, *, apply=False,
                         backup_path=ENV_FILE.parent / "client-enable-before-v2.json"):
    # Revalidate secure LDAP, exact single-user scope/GUID and required MFA;
    # this operation does not enable any application feature flag or role.
    inspect_pilot(client, environment, expected_guid)
    prepared = []
    for client_id in CLIENTS:
        listed = client.request("GET", PREFIX + "/clients?clientId=" + client_id)
        require(len(listed) == 1 and listed[0].get("clientId") == client_id and
                listed[0].get("enabled") is False and bool(listed[0].get("id")), "AmbiguousOrEnabledPilotClient")
        path = PREFIX + "/clients/" + urllib.parse.quote(listed[0]["id"], safe="")
        detail = client.request("GET", path)
        require(detail.get("id") == listed[0]["id"] and detail.get("clientId") == client_id and
                detail.get("enabled") is False, "ClientListDetailIdentityMismatch")
        require(detail.get("protocol") == "openid-connect" and detail.get("clientAuthenticatorType") == "client-secret" and
                detail.get("redirectUris") == [CLIENT_CALLBACKS[client_id]] and detail.get("standardFlowEnabled") is True and
                detail.get("implicitFlowEnabled") is False and detail.get("webOrigins") == [], "UnexpectedClientProtocolOrCallback")
        required_level = "1" if client_id == "worktime-employee" else "2"
        require(detail.get("attributes", {}).get("minimum.acr.value") == required_level and
                detail["attributes"].get("default.acr.values") == "urn:sosnadmin:loa:" + required_level,
                "UnexpectedClientMinimumMfaLevel")
        require(client.request("GET", path) == detail, "ClientDetailChangedConcurrently")
        prepared.append((client_id, path, copy.deepcopy(detail)))
    if not apply:
        return {"status": "PilotClientEnablePlan", "clients": list(CLIENTS),
                "pilot_guid_matches": True, "exact_callbacks_validated": True,
                "mfa_configuration_validated": True, "applications_changed": False}
    descriptor = os.open(backup_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        # Non-secret rollback metadata, never full client representations.
        json.dump({"pilot_ad_guid": expected_guid, "clients": [
            {"id": detail["id"], "clientId": client_id, "enabled": False,
             "redirectUris": detail["redirectUris"]} for client_id, _, detail in prepared]}, stream)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    completed = 0
    for client_id, path, baseline in prepared:
        require(client.request("GET", path) == baseline, "ClientDetailChangedBeforeEnable")
        #26.8.1 derives webOrigins from redirectUris when this field is omitted
        # and current origins are empty. Keep the BFF's explicit empty origins.
        payload = {"id": baseline["id"], "clientId": client_id, "protocol": "openid-connect",
                   "enabled": True, "webOrigins": []}
        client.client_enable_payloads = {path: payload}
        try:
            client.request("PUT", path, payload=payload)
            expected = copy.deepcopy(baseline)
            expected["enabled"] = True
            require(client.request("GET", path) == expected, "UnexpectedClientChangeAfterEnable")
            completed += 1
        except AcceptanceError as error:
            raise AcceptanceError(f"ClientEnableVerificationStoppedAfter{completed}Of3:{error}") from None
    return {"status": "PilotClientsEnabledApplicationsUnchanged", "clients": list(CLIENTS),
            "application_flags_enabled": False, "roles_or_ad_changed": False,
            "browser_oidc_acceptance_still_required": True}


def restore_helpdesk_normalization(client, expected_guid, *, apply=False,
                                   receipt_path=ENV_FILE.parent / "client-enable-before.json",
                                   backup_path=ENV_FILE.parent / "helpdesk-normalization-before.json"):
    """Restore only the known first-client partial enable/derived-origin state.

    The original receipt is read, never overwritten. No credentials/config
    reconstruction occurs: the payload explicitly restores two non-secret
    fields and the postcondition compares the complete current detail baseline.
    """
    require(not receipt_path.is_symlink() and receipt_path.is_file(), "OriginalEnableReceiptRequired")
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    require(receipt.get("pilot_ad_guid") == expected_guid, "OriginalEnableReceiptGuidMismatch")
    entries = receipt.get("clients", [])
    require(len(entries) == 3 and {entry.get("clientId") for entry in entries} == set(CLIENTS), "OriginalEnableReceiptClientsMismatch")
    helpdesk_detail = None
    helpdesk_path = None
    for client_id in CLIENTS:
        old = next(entry for entry in entries if entry.get("clientId") == client_id)
        require(old.get("enabled") is False and old.get("redirectUris") == [CLIENT_CALLBACKS[client_id]], "OriginalEnableReceiptStateMismatch")
        listed = client.request("GET", PREFIX + "/clients?clientId=" + client_id)
        require(len(listed) == 1 and listed[0].get("id") == old.get("id") and listed[0].get("clientId") == client_id, "RestoreClientIdentityMismatch")
        path = PREFIX + "/clients/" + urllib.parse.quote(old["id"], safe="")
        detail = client.request("GET", path)
        require(detail.get("id") == old["id"] and detail.get("clientId") == client_id and
                detail.get("redirectUris") == old["redirectUris"] and detail.get("protocol") == "openid-connect" and
                detail.get("publicClient") is False and detail.get("directAccessGrantsEnabled") is False and
                detail.get("serviceAccountsEnabled") is False, "RestoreClientConfigurationMismatch")
        require(client.request("GET", path) == detail, "RestoreClientChangedConcurrently")
        if client_id == "helpdesk-web":
            require(detail.get("enabled") is True and detail.get("webOrigins") == ["https://helpdesk.sosnadmin.local"], "NotTheKnownHelpdeskNormalizationState")
            helpdesk_detail, helpdesk_path = copy.deepcopy(detail), path
        else:
            require(detail.get("enabled") is False and detail.get("webOrigins") == [], "OtherPilotClientChanged")
    if not apply:
        return {"status": "HelpdeskNormalizationRestorePlan", "only_client": "helpdesk-web",
                "restore_enabled": False, "restore_web_origins_empty": True, "original_receipt_preserved": True}
    require(client.request("GET", helpdesk_path) == helpdesk_detail, "HelpdeskChangedBeforeRestore")
    descriptor = os.open(backup_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump({"id": helpdesk_detail["id"], "clientId": "helpdesk-web", "enabled": True,
                   "webOrigins": ["https://helpdesk.sosnadmin.local"]}, stream)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    payload = {"id": helpdesk_detail["id"], "clientId": "helpdesk-web", "protocol": "openid-connect",
               "enabled": False, "webOrigins": []}
    client.client_enable_payloads = {helpdesk_path: payload}
    client.request("PUT", helpdesk_path, payload=payload)
    expected = copy.deepcopy(helpdesk_detail)
    expected.update(enabled=False, webOrigins=[])
    require(client.request("GET", helpdesk_path) == expected, "UnexpectedClientChangeAfterNormalizationRestore")
    return {"status": "HelpdeskNormalizationRestoredAllClientsDisabled", "original_receipt_preserved": True,
            "secrets_or_application_config_changed": False}


def canonical_mapper(mapper):
    result = {key: copy.deepcopy(mapper.get(key)) for key in ("name", "protocol", "protocolMapper", "config")}
    if result["name"] == "self-introspection-audience" and result["protocolMapper"] == "oidc-audience-mapper" and isinstance(result["config"], dict):
        # Models GET materializes this exact false provider default; client
        # detail GET may omit it for the first pre-amendment mapper. Treat only
        # absent/false as equivalent. True or any other extra config still fails.
        result["config"].setdefault("userinfo.token.claim", "false")
    return result


def checked_audience_mappers(mappers, client_id):
    require(isinstance(mappers, list) and len(mappers) in (1, 2), "UnexpectedPilotMapperInventory")
    names = [mapper.get("name") for mapper in mappers]
    require(len(names) == len(set(names)) and set(names) <= {"ad-object-guid", "self-introspection-audience"} and
            "ad-object-guid" in names, "ConflictingPilotMapperInventory")
    existing = [mapper for mapper in mappers if mapper.get("name") == "self-introspection-audience"]
    if existing:
        require(canonical_mapper(existing[0]) == self_audience_mapper(client_id), "ConflictingSelfAudienceMapper")
    return bool(existing)


def add_self_audiences(client, environment, expected_guid, *, apply=False,
                       receipt_path=ENV_FILE.parent / "self-audience-mappers-before.json"):
    """Add only the exact own-client audience mappers; never update clients.

    Keycloak26.8.1 AudienceProtocolMapper and AccessTokenIntrospectionProvider
    require this audience for strict introspection. No audience-check bypass,
    shared realm audience, ID token mapper, client secret or role is changed.
    """
    inspect_pilot(client, environment, expected_guid, expected_clients_enabled=True)
    prepared = []
    for client_id in CLIENTS:
        listed = client.request("GET", PREFIX + "/clients?clientId=" + client_id)
        require(len(listed) == 1 and listed[0].get("clientId") == client_id and
                listed[0].get("enabled") is True and bool(listed[0].get("id")), "AudienceClientIdentityMismatch")
        path = PREFIX + "/clients/" + urllib.parse.quote(listed[0]["id"], safe="")
        detail = client.request("GET", path)
        require(detail.get("id") == listed[0]["id"] and detail.get("clientId") == client_id and
                detail.get("enabled") is True and detail.get("redirectUris") == [CLIENT_CALLBACKS[client_id]] and
                detail.get("webOrigins") == [] and detail.get("protocol") == "openid-connect" and
                detail.get("clientAuthenticatorType") == "client-secret" and detail.get("standardFlowEnabled") is True and
                detail.get("implicitFlowEnabled") is False, "AudienceClientConfigurationMismatch")
        level = "1" if client_id == "worktime-employee" else "2"
        attributes = detail.get("attributes", {})
        require(attributes.get("minimum.acr.value") == level and attributes.get("default.acr.values") == "urn:sosnadmin:loa:" + level,
                "AudienceClientMfaMismatch")
        require(attributes.get("allow.token.introspection.without.audience.check", "false") == "false", "AudienceCheckBypassProhibited")
        require(client.request("GET", path) == detail, "AudienceClientChangedConcurrently")
        mapper_path = path + "/protocol-mappers/models"
        mappers = client.request("GET", mapper_path)
        present = checked_audience_mappers(mappers, client_id)
        require(sorted((canonical_mapper(x) for x in mappers), key=lambda x: x["name"]) ==
                sorted((canonical_mapper(x) for x in detail.get("protocolMappers", [])), key=lambda x: x["name"]),
                "AudienceMapperReadPathsDisagree")
        prepared.append((client_id, path, mapper_path, copy.deepcopy(detail), copy.deepcopy(mappers), present))
    missing = sum(not item[-1] for item in prepared)
    if not apply:
        return {"status": "SelfAudienceMapperPlan", "clients": list(CLIENTS), "missing_mappers": missing,
                "id_token_audience_unchanged": True, "audience_checks_preserved": True}
    if missing == 0:
        return {"status": "SelfAudienceMappersVerified", "created_mappers": 0,
                "id_token_audience_unchanged": True, "audience_checks_preserved": True}
    receipt = {"pilot_ad_guid": expected_guid, "clients": [
        {"id": detail["id"], "clientId": client_id, "mapper": self_audience_mapper(client_id)}
        for client_id, _, _, detail, _, _ in prepared]}
    if receipt_path.exists() or receipt_path.is_symlink():
        # The first reviewed request omitted only the provider's false userinfo
        # default. Preserve that exact original receipt while resuming remaining
        # additive operations; accept no other payload/identity difference.
        legacy_receipt = copy.deepcopy(receipt)
        for entry in legacy_receipt["clients"]:
            del entry["mapper"]["config"]["userinfo.token.claim"]
        require(not receipt_path.is_symlink() and receipt_path.is_file() and
                json.loads(receipt_path.read_text(encoding="utf-8")) in (receipt, legacy_receipt), "AudienceReceiptConflict")
    else:
        descriptor = os.open(receipt_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(receipt, stream)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
    created = 0
    for client_id, path, mapper_path, baseline, old_mappers, present in prepared:
        if present:
            continue
        require(client.request("GET", path) == baseline, "AudienceClientChangedBeforeCreate")
        payload = self_audience_mapper(client_id)
        client.audience_mapper_payloads = {mapper_path: payload}
        try:
            client.request("POST", mapper_path, payload=payload)
            current_mappers = client.request("GET", mapper_path)
            require(checked_audience_mappers(current_mappers, client_id) and len(current_mappers) == len(old_mappers) + 1,
                    "AudienceMapperCreationNotVerified")
            require([x for x in current_mappers if x.get("name") != "self-introspection-audience"] == old_mappers,
                    "ExistingGuidMapperChanged")
            current = client.request("GET", path)
            require({k: v for k, v in current.items() if k != "protocolMappers"} ==
                    {k: v for k, v in baseline.items() if k != "protocolMappers"}, "OtherClientConfigurationChanged")
            require(sorted((canonical_mapper(x) for x in current.get("protocolMappers", [])), key=lambda x: x["name"]) ==
                    sorted((canonical_mapper(x) for x in current_mappers), key=lambda x: x["name"]), "CreatedMapperReadPathsDisagree")
            created += 1
        except AcceptanceError as error:
            raise AcceptanceError(f"AudienceMapperCreateStoppedAfter{created}Of3:{error}") from None
    return {"status": "SelfAudienceMappersVerified", "created_mappers": created,
            "id_token_audience_unchanged": True, "audience_checks_preserved": True,
            "client_secrets_flags_roles_unchanged": True}


def basic_scope_mappers():
    # Exact26.8.1 OIDCLoginProtocolFactory builtins, excluding generated IDs.
    return [
        {"name": "sub", "protocol": "openid-connect", "protocolMapper": "oidc-sub-mapper",
         "config": {"access.token.claim": "true", "introspection.token.claim": "true"}},
        {"name": "auth_time", "protocol": "openid-connect", "protocolMapper": "oidc-usersessionmodel-note-mapper",
         "config": {"user.session.note": "AUTH_TIME", "id.token.claim": "true", "introspection.token.claim": "true",
                    "access.token.claim": "true", "claim.name": "auth_time", "jsonType.label": "long"}},
    ]


def scope_id_map(scopes):
    require(isinstance(scopes, list) and all(isinstance(x, dict) and x.get("id") and x.get("name") for x in scopes),
            "MalformedDefaultScopeInventory")
    result = {x["name"]: x["id"] for x in scopes}
    require(len(result) == len(scopes) and len(set(result.values())) == len(scopes), "DuplicateDefaultScopes")
    return result


def add_basic_scope(client, environment, expected_guid, *, apply=False,
                    receipt_path=ENV_FILE.parent / "basic-client-scope-before.json"):
    """Bind the existing stock basic scope, via bodyless audited association PUT.

    No realm-default scopes, scope definitions, optional scopes, client settings,
    secrets, mapper definitions or role mappings are updated.
    Official26.8.1 ClientResource.addDefaultClientScope is additive and audited.
    """
    inspect_pilot(client, environment, expected_guid, expected_clients_enabled=True)
    basics = [x for x in client.request("GET", PREFIX + "/client-scopes") if x.get("name") == "basic"]
    require(len(basics) == 1, "AmbiguousBasicScope")
    basic = basics[0]
    require(basic.get("protocol") == "openid-connect" and basic.get("id") and
            basic.get("attributes") == {"include.in.token.scope": "false", "display.on.consent.screen": "false"},
            "UnexpectedBasicScopeDefinition")
    expected_mappers = sorted(basic_scope_mappers(), key=lambda x: x["name"])
    require(sorted((canonical_mapper(x) for x in basic.get("protocolMappers", [])), key=lambda x: x["name"]) == expected_mappers,
            "BasicScopeNotStockMappers")
    roles_path = PREFIX + "/client-scopes/" + urllib.parse.quote(basic["id"], safe="") + "/scope-mappings"
    require(client.request("GET", roles_path) == {}, "BasicScopeHasRoleMappings")
    prepared = []
    for name in CLIENTS:
        listed = client.request("GET", PREFIX + "/clients?clientId=" + name)
        require(len(listed) == 1 and listed[0].get("id") and listed[0].get("clientId") == name, "BasicClientIdentityMismatch")
        path = PREFIX + "/clients/" + urllib.parse.quote(listed[0]["id"], safe="")
        detail = client.request("GET", path)
        require(detail.get("id") == listed[0]["id"] and detail.get("clientId") == name and detail.get("enabled") is True and
                detail.get("redirectUris") == [CLIENT_CALLBACKS[name]] and detail.get("webOrigins") == [] and
                detail.get("protocol") == "openid-connect" and detail.get("clientAuthenticatorType") == "client-secret" and
                detail.get("standardFlowEnabled") is True and detail.get("implicitFlowEnabled") is False, "BasicClientConfigurationMismatch")
        level = "1" if name == "worktime-employee" else "2"
        attributes = detail.get("attributes", {})
        require(attributes.get("minimum.acr.value") == level and attributes.get("default.acr.values") == "urn:sosnadmin:loa:" + level and
                attributes.get("allow.token.introspection.without.audience.check", "false") == "false", "BasicClientMfaOrAudienceMismatch")
        require(checked_audience_mappers(detail.get("protocolMappers", []), name), "SelfAudienceRequiredBeforeBasicScope")
        require(detail.get("optionalClientScopes") == [], "UnexpectedOptionalScopes")
        scopes = scope_id_map(client.request("GET", path + "/default-client-scopes"))
        require(set(scopes) in ({"profile", "email", "acr"}, {"basic", "profile", "email", "acr"}) and
                set(detail.get("defaultClientScopes", [])) == set(scopes), "UnexpectedDefaultScopes")
        require("basic" not in scopes or scopes["basic"] == basic["id"], "WrongBasicScopeBinding")
        require(client.request("GET", path) == detail, "BasicClientChangedConcurrently")
        prepared.append((name, path, copy.deepcopy(detail), scopes))
    missing = sum("basic" not in x[3] for x in prepared)
    if not apply:
        return {"status": "BasicClientScopePlan", "clients": list(CLIENTS), "missing_bindings": missing,
                "stock_basic_scope_verified": True, "role_mappings_absent": True}
    if not missing:
        return {"status": "BasicClientScopesVerified", "added_bindings": 0}
    receipt = {"pilot_ad_guid": expected_guid, "basic_scope_id": basic["id"], "clients": [
        {"id": detail["id"], "clientId": name, "original_scope_ids": {k: v for k, v in scopes.items() if k != "basic"}}
        for name, _, detail, scopes in prepared]}
    if receipt_path.exists() or receipt_path.is_symlink():
        require(not receipt_path.is_symlink() and receipt_path.is_file() and
                json.loads(receipt_path.read_text(encoding="utf-8")) == receipt, "BasicReceiptConflict")
    else:
        descriptor = os.open(receipt_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(receipt, stream)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
    added = 0
    for name, path, baseline, scopes in prepared:
        if "basic" in scopes:
            continue
        require(client.request("GET", path) == baseline, "BasicClientChangedBeforeBinding")
        binding_path = path + "/default-client-scopes/" + urllib.parse.quote(basic["id"], safe="")
        client.basic_scope_write_paths = {binding_path}
        try:
            client.request("PUT", binding_path)
            current = client.request("GET", path)
            require({k: v for k, v in current.items() if k != "defaultClientScopes"} ==
                    {k: v for k, v in baseline.items() if k != "defaultClientScopes"}, "OtherClientConfigurationChanged")
            expected_scopes = dict(scopes, basic=basic["id"])
            require(set(current.get("defaultClientScopes", [])) == set(expected_scopes) and
                    scope_id_map(client.request("GET", path + "/default-client-scopes")) == expected_scopes,
                    "BasicScopeBindingNotVerified")
            added += 1
        except AcceptanceError as error:
            raise AcceptanceError(f"BasicScopeBindingStoppedAfter{added}Of3:{error}") from None
    require(client.request("GET", roles_path) == {}, "BasicRoleMappingsChanged")
    return {"status": "BasicClientScopesVerified", "added_bindings": added,
            "client_secrets_mappers_flags_roles_unchanged": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true", help="Perform reviewed checks; may import only the fixed synthetic pilot")
    parser.add_argument("--repair-exact-pilot-scope", action="store_true", help="Plan only the fixed pilot's scope2-to0 correction; no directory widening")
    parser.add_argument("--enable-pilot-clients", action="store_true", help="Plan fixed3clients only after full pilot inventory; add --apply to enable")
    parser.add_argument("--restore-helpdesk-enable-normalization", action="store_true", help="Plan only the known first-client partial enable reversal; add --apply to restore")
    parser.add_argument("--add-self-audience-mappers", action="store_true", help="Plan exact own-client access/introspection audiences; add --apply for additive mapper creation")
    parser.add_argument("--add-basic-client-scope", action="store_true", help="Plan existing stock basic scope association to fixed3clients; add --apply for bodyless additive PUT")
    parser.add_argument("--apply", action="store_true", help="Apply the reviewed exact-scope repair only")
    parser.add_argument("--expected-ad-guid", help="Non-secret canonical AD objectGUID of the fixed synthetic pilot")
    args = parser.parse_args()
    modes = (args.run, args.repair_exact_pilot_scope, args.enable_pilot_clients, args.restore_helpdesk_enable_normalization, args.add_self_audience_mappers, args.add_basic_client_scope)
    require(not args.apply or any(modes[1:]), "ApplyRequiresExplicitRepairOrEnableMode")
    require(sum(modes) <= 1, "SelectOneOperation")
    if not any(modes):
        print(json.dumps({"status": "PlanOnly", "target": BASE, "pilot": "ssopilot-20261027",
                          "possible_single_pilot_import": True, "client_or_ad_changes": False}))
        return
    require(sys.platform == "linux" and os.geteuid() == 0, "RunRequiresApprovedLinuxRoot")
    if any((args.run, args.enable_pilot_clients, args.restore_helpdesk_enable_normalization, args.add_self_audience_mappers, args.add_basic_client_scope)):
        require(bool(args.expected_ad_guid), "ExpectedAdGuidRequired")
        # Validate before any HTTP or credential-file read.
        require(str(uuid.UUID(args.expected_ad_guid)) == args.expected_ad_guid, "ExpectedGuidMustBeCanonical")
    addresses = subprocess.run(["hostname", "-I"], check=True, capture_output=True, text=True).stdout.split()
    require("192.168.100.19" in addresses, "WrongDeploymentHost")
    environment = read_private_environment()
    client = LocalAdminClient(request_budget=48 if args.add_self_audience_mappers or args.add_basic_client_scope else 32 if args.enable_pilot_clients else 16)
    client.login(environment["SSO_BOOTSTRAP_PASSWORD"])
    if args.repair_exact_pilot_scope:
        result = repair_exact_pilot_scope(client, apply=args.apply)
    elif args.enable_pilot_clients:
        result = enable_pilot_clients(client, environment, args.expected_ad_guid, apply=args.apply)
    elif args.restore_helpdesk_enable_normalization:
        result = restore_helpdesk_normalization(client, args.expected_ad_guid, apply=args.apply)
    elif args.add_self_audience_mappers:
        result = add_self_audiences(client, environment, args.expected_ad_guid, apply=args.apply)
    elif args.add_basic_client_scope:
        result = add_basic_scope(client, environment, args.expected_ad_guid, apply=args.apply)
    else:
        result = inspect_pilot(client, environment, args.expected_ad_guid)
    print(json.dumps(result))


if __name__ == "__main__":
    try:
        main()
    except AcceptanceError as error:
        print(json.dumps({"status": "PilotInventoryFailed", "check": str(error)}))
        raise SystemExit(1) from None
    except Exception:
        # Never serialize HTTP bodies, response representations or locals.
        print(json.dumps({"status": "PilotInventoryFailed", "check": "UnexpectedOrMalformedResponse"}))
        raise SystemExit(1) from None
