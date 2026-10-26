"""Render non-secret, disabled-by-default Keycloak pilot configuration.

Secrets remain environment placeholders resolved only by Keycloak import on host.
No AD operation or network request is performed by this renderer.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from urllib.parse import urlsplit


CLIENTS = {
    "helpdesk-web": "SSO_HELPDESK_CLIENT_SECRET",
    "endpoint-admin": "SSO_ENDPOINT_CLIENT_SECRET",
    "worktime-employee": "SSO_WORKTIME_CLIENT_SECRET",
}
MFA_ACR = "urn:sosnadmin:loa:2"
COMPONENT_EXPORT_FIELDS = frozenset({"id", "name", "providerId", "subType", "subComponents", "config"})


def validate_component_exports(collection):
    """Validate the pinned 26.8.1 ComponentExportRepresentation recursively.

    providerType belongs to the containing map key, unlike the Admin REST
    ComponentRepresentation. Official source: core/src/main/java/org/keycloak/
    representations/idm/ComponentExportRepresentation.java at tag26.8.1.
    """
    if not isinstance(collection, dict):
        raise ValueError("Exported components must be a provider-type map")
    for provider_type, components in collection.items():
        if not isinstance(provider_type, str) or not provider_type or not isinstance(components, list):
            raise ValueError("Each exported provider type must contain a component list")
        for component in components:
            if not isinstance(component, dict) or set(component) - COMPONENT_EXPORT_FIELDS:
                raise ValueError("Unsupported field in exported component")
            for field in ("name", "providerId"):
                if not isinstance(component.get(field), str) or not component[field]:
                    raise ValueError("Exported component requires name and providerId")
            for field in ("id", "subType"):
                if field in component and not isinstance(component[field], str):
                    raise ValueError("Optional exported identifiers must be strings")
            config = component.get("config", {})
            if not isinstance(config, dict) or any(
                not isinstance(key, str) or not isinstance(values, list) or
                any(not isinstance(value, str) for value in values)
                for key, values in config.items()
            ):
                raise ValueError("Exported configuration must map strings to string lists")
            validate_component_exports(component.get("subComponents", {}))


def execution(authenticator, requirement="REQUIRED", **extra):
    return {"authenticator": authenticator, "authenticatorFlow": False,
            "requirement": requirement, **extra}


def subflow(alias, requirement, priority):
    return {"flowAlias": alias, "authenticatorFlow": True,
            "requirement": requirement, "priority": priority}


def flow(alias, executions, top=False):
    return {"alias": alias, "providerId": "basic-flow", "topLevel": top,
            "builtIn": False, "authenticationExecutions": executions}


def build_realm(redirects: dict[str, str], users_dn: str, *, enable_clients=False):
    if set(redirects) != set(CLIENTS):
        raise ValueError("Specify exactly three independent application clients")
    if not users_dn.upper().endswith(",DC=SOSNADMIN,DC=LOCAL") or not users_dn.upper().startswith(("OU=", "CN=")):
        raise ValueError("Use an approved pilot OU/container; whole-domain sync is prohibited")
    clients = []
    for name, redirect in redirects.items():
        url = urlsplit(redirect)
        if (url.scheme != "https" or not url.hostname or
                not url.hostname.endswith(".sosnadmin.local") or
                url.username or url.password or url.port not in (None, 443) or
                not url.path.startswith("/") or url.query or url.fragment or
                any(c in redirect for c in ("*", "\\", "\r", "\n", "%"))):
            raise ValueError("Redirect must be an exact internal HTTPS callback without credentials/query/wildcards")
        clients.append({
            "clientId": name, "protocol": "openid-connect", "enabled": enable_clients,
            "publicClient": False, "clientAuthenticatorType": "client-secret",
            "secret": "${" + CLIENTS[name] + "}", "standardFlowEnabled": True,
            "implicitFlowEnabled": False, "directAccessGrantsEnabled": False,
            "serviceAccountsEnabled": False, "fullScopeAllowed": False,
            "redirectUris": [redirect], "webOrigins": [],
            "attributes": {"pkce.code.challenge.method": "S256",
                           "access.token.signed.response.alg": "RS256",
                           "id.token.signed.response.alg": "RS256",
                           "default.acr.values": MFA_ACR if name != "worktime-employee" else "urn:sosnadmin:loa:1",
                           "minimum.acr.value": "2" if name != "worktime-employee" else "1"},
            "defaultClientScopes": ["profile", "email", "acr"],
            "optionalClientScopes": [],
            "protocolMappers": [{
                "name": "ad-object-guid", "protocol": "openid-connect",
                "protocolMapper": "oidc-usermodel-attribute-mapper",
                "config": {"user.attribute": "LDAP_ID", "claim.name": "ad_object_guid",
                           "jsonType.label": "String", "id.token.claim": "true",
                           "access.token.claim": "true", "userinfo.token.claim": "true",
                           "introspection.token.claim": "true"},
            }],
        })
    ldap_config = {
        "enabled": "true", "priority": "0", "vendor": "ad", "editMode": "READ_ONLY",
        "importEnabled": "true", "syncRegistrations": "false", "cachePolicy": "NO_CACHE",
        "connectionUrl": "ldaps://AD-MAIN.sosnadmin.local:636", "startTls": "false",
        "useTruststoreSpi": "always", "connectionPooling": "false",
        "bindDn": "${SSO_LDAP_BIND_DN}", "bindCredential": "${SSO_LDAP_BIND_PASSWORD}",
        "authType": "simple", "usersDn": users_dn, "searchScope": "2",
        "usernameLDAPAttribute": "sAMAccountName", "rdnLDAPAttribute": "cn",
        "uuidLDAPAttribute": "objectGUID", "userObjectClasses": "person, organizationalPerson, user",
        "customUserSearchFilter": "(&(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
        "pagination": "true", "batchSizeForSync": "100",
        "fullSyncPeriod": "-1", "changedSyncPeriod": "-1",
        "connectionTimeout": "5000", "readTimeout": "5000",
        "allowKerberosAuthentication": "false", "useKerberosForPasswordAuthentication": "false",
    }
    attribute_mappers = []
    for user_attr, ldap_attr in (("username", "sAMAccountName"), ("firstName", "givenName"),
                                ("lastName", "sn"), ("email", "mail")):
        attribute_mappers.append({"name": user_attr, "providerId": "user-attribute-ldap-mapper",
            "config": {"user.model.attribute": [user_attr], "ldap.attribute": [ldap_attr],
                       "read.only": ["true"], "always.read.value.from.ldap": ["true"],
                       "is.mandatory.in.ldap": ["true" if user_attr == "username" else "false"]}})
    attribute_mappers.append({"name": "msad-account-state", "providerId": "msad-user-account-control-mapper",
        "config": {}})
    realm = {
        "realm": "sosnadmin", "enabled": True, "sslRequired": "all",
        "registrationAllowed": False, "registrationEmailAsUsername": False,
        "resetPasswordAllowed": False, "editUsernameAllowed": False,
        "loginWithEmailAllowed": False, "duplicateEmailsAllowed": False,
        "rememberMe": False, "bruteForceProtected": True, "failureFactor": 5,
        "waitIncrementSeconds": 60, "maxFailureWaitSeconds": 900,
        "accessTokenLifespan": 300, "ssoSessionIdleTimeout": 900,
        "ssoSessionMaxLifespan": 28800, "clientSessionIdleTimeout": 900,
        "clientSessionMaxLifespan": 28800, "accessCodeLifespan": 60,
        "revokeRefreshToken": True, "refreshTokenMaxReuse": 0,
        "defaultSignatureAlgorithm": "RS256", "browserFlow": "sso-browser",
        "eventsEnabled": True, "eventsExpiration": 604800,
        "adminEventsEnabled": True, "adminEventsDetailsEnabled": False,
        "attributes": {"acr.loa.map": '{"urn:sosnadmin:loa:1":1,"urn:sosnadmin:loa:2":2}'},
        "clients": clients,
        "components": {"org.keycloak.storage.UserStorageProvider": [{
            "name": "sosnadmin-ad-readonly", "providerId": "ldap",
            "config": {k: [v] for k, v in ldap_config.items()},
            "subComponents": {"org.keycloak.storage.ldap.mappers.LDAPStorageMapper": attribute_mappers},
        }]},
        "authenticationFlows": [
            flow("sso-browser", [execution("auth-cookie", "ALTERNATIVE", priority=10),
                                  subflow("sso-forms", "ALTERNATIVE", 20)], True),
            flow("sso-forms", [subflow("sso-level-1", "CONDITIONAL", 10),
                                subflow("sso-level-2", "CONDITIONAL", 20)]),
            flow("sso-level-1", [execution("conditional-level-of-authentication", authenticatorConfig="sso-loa-1", priority=10),
                                  execution("auth-username-password-form", priority=20)]),
            flow("sso-level-2", [execution("conditional-level-of-authentication", authenticatorConfig="sso-loa-2", priority=10),
                                  execution("auth-otp-form", priority=20)]),
        ],
        "authenticatorConfig": [
            {"alias": "sso-loa-1", "config": {"loa-condition-level": "1", "loa-max-age": "28800"}},
            {"alias": "sso-loa-2", "config": {"loa-condition-level": "2", "loa-max-age": "300"}},
        ],
    }
    validate_component_exports(realm["components"])
    return realm


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--helpdesk-callback", required=True)
    parser.add_argument("--endpoint-callback", required=True)
    parser.add_argument("--worktime-callback", required=True)
    parser.add_argument("--pilot-users-dn", required=True)
    parser.add_argument("--enable-clients", action="store_true", help="Only after secure LDAP and MFA acceptance")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    realm = build_realm({"helpdesk-web": args.helpdesk_callback, "endpoint-admin": args.endpoint_callback,
                         "worktime-employee": args.worktime_callback}, args.pilot_users_dn,
                        enable_clients=args.enable_clients)
    with args.output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(realm, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


if __name__ == "__main__":
    main()
