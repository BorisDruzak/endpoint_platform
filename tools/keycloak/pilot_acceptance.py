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
MFA_ACR = "urn:sosnadmin:loa:2"


class AcceptanceError(Exception):
    """Contains only fixed, non-secret diagnostic codes authored below."""


def require(condition, code):
    if not condition:
        raise AcceptanceError(code)


class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise AcceptanceError("RedirectProhibited")


class LocalAdminClient:
    def __init__(self):
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirects())
        self.token = None
        self.requests = 0
        self.scope_write_path = None

    def request(self, method, path, *, payload=None, form=None, authenticated=True):
        scope_write = (method == "PUT" and path == self.scope_write_path and
                       payload == {"config": {"searchScope": ["0"]}} and form is None)
        require(method == "GET" or (method == "POST" and path in {TOKEN_PATH, LDAP_TEST_PATH}) or scope_write, "MutationProhibited")
        if scope_write:
            self.scope_write_path = None  # Permit exactly one reviewed field update.
        require(path == TOKEN_PATH or path.startswith(PREFIX + "/") or path == PREFIX, "PathProhibited")
        require(not path.startswith("//") and ".." not in path and "\r" not in path and "\n" not in path, "PathProhibited")
        self.requests += 1
        require(self.requests <= 16, "RequestBudgetExceeded")
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


def inspect_pilot(client, environment, expected_guid):
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
        require(application.get("clientId") == client_id and application.get("enabled") is False, "PilotClientAlreadyEnabled")
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
            "clients_disabled": True, "mfa_flow_required": True,
            "browser_mfa_and_token_flow_tested": False}


def repair_exact_pilot_scope(client, *, apply=False,
                             backup_path=ENV_FILE.parent / "ldap-scope-before.json"):
    """Change only this exact pilot's scope2 to scope0 with disabled clients.

    ComponentResource.updateComponent / RepresentationToModel.updateComponent
    at26.8.1 merge supplied config keys and preserve omitted secret fields.
    Therefore the PUT deliberately contains only searchScope, no credential.
    """
    components = client.request("GET", PREFIX + "/components?type=org.keycloak.storage.UserStorageProvider&name=sosnadmin-ad-readonly")
    require(isinstance(components, list) and len(components) == 1, "AmbiguousLdapProvider")
    component = components[0]
    require(component.get("providerId") == "ldap" and bool(component.get("id")), "UnexpectedStorageProvider")
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
    client.request("PUT", path, payload={"config": {"searchScope": ["0"]}})
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true", help="Perform reviewed checks; may import only the fixed synthetic pilot")
    parser.add_argument("--repair-exact-pilot-scope", action="store_true", help="Plan only the fixed pilot's scope2-to0 correction; no directory widening")
    parser.add_argument("--apply", action="store_true", help="Apply the reviewed exact-scope repair only")
    parser.add_argument("--expected-ad-guid", help="Non-secret canonical AD objectGUID of the fixed synthetic pilot")
    args = parser.parse_args()
    require(not args.apply or args.repair_exact_pilot_scope, "ApplyOnlyValidForScopeRepair")
    require(not (args.run and args.repair_exact_pilot_scope), "SelectInventoryOrScopeRepair")
    if not args.run and not args.repair_exact_pilot_scope:
        print(json.dumps({"status": "PlanOnly", "target": BASE, "pilot": "ssopilot-20261027",
                          "possible_single_pilot_import": True, "client_or_ad_changes": False}))
        return
    require(sys.platform == "linux" and os.geteuid() == 0, "RunRequiresApprovedLinuxRoot")
    if args.run:
        require(bool(args.expected_ad_guid), "ExpectedAdGuidRequired")
        # Validate before any HTTP or credential-file read.
        require(str(uuid.UUID(args.expected_ad_guid)) == args.expected_ad_guid, "ExpectedGuidMustBeCanonical")
    addresses = subprocess.run(["hostname", "-I"], check=True, capture_output=True, text=True).stdout.split()
    require("192.168.100.19" in addresses, "WrongDeploymentHost")
    environment = read_private_environment()
    client = LocalAdminClient()
    client.login(environment["SSO_BOOTSTRAP_PASSWORD"])
    result = (repair_exact_pilot_scope(client, apply=args.apply) if args.repair_exact_pilot_scope else
              inspect_pilot(client, environment, args.expected_ad_guid))
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
