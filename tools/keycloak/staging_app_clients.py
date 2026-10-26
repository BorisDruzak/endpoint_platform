"""Fixed, independent staging OIDC clients. Plan by default; no app/AD writes.

Keycloak26.8.1 Admin REST ClientResource (create/update) is the provider API:
https://www.keycloak.org/docs-api/26.8.1/rest-api/index.html
The existing realm's exact pilot, LDAPS and MFA preflight remains mandatory.
Client creation and enablement are separate explicit operator operations.
"""
from __future__ import annotations

import argparse
import copy
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid

SOURCE_ROOT = Path(__file__).resolve().parents[2]
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))
from tools.keycloak import pilot_acceptance as pilot
from tools.keycloak.prepare_app_secrets import parse_values, write_exclusive

PREFIX = pilot.PREFIX
STAGING_CLIENTS = {
    'helpdesk-staging-web': 'https://helpdesk-staging.sosnadmin.local/api/web/session/oidc/callback',
    'endpoint-staging-admin': 'https://endpoint-staging.sosnadmin.local/auth/admin/callback',
    'worktime-staging-employee': 'https://endpoint-staging.sosnadmin.local/auth/employee/callback',
}
SECRET_NAMES = {
    'helpdesk-staging-web': 'SSO_STAGING_HELPDESK_CLIENT_SECRET',
    'endpoint-staging-admin': 'SSO_STAGING_ENDPOINT_CLIENT_SECRET',
    'worktime-staging-employee': 'SSO_STAGING_WORKTIME_CLIENT_SECRET',
}
SECRET_FILE = Path('/etc/keycloak/staging-apps-20261027.env')
PROVISION_FILE = Path('/etc/keycloak/pilot-provision-20261027.env')
PRODUCTION_SECRET_NAMES = ('SSO_HELPDESK_CLIENT_SECRET', 'SSO_ENDPOINT_CLIENT_SECRET', 'SSO_WORKTIME_CLIENT_SECRET')
ASSURANCE_SCOPE_IDS = {'basic': '08d943a1-63e2-4418-8d06-47251e20b6c1',
                       'acr': '1dfaf6d5-7c5c-4dc5-b1c3-011fcc730e75'}


def client_payload(name, secret):
    pilot.require(name in STAGING_CLIENTS, 'StagingClientNameProhibited')
    pilot.require(isinstance(secret, str) and re.fullmatch(r'[A-Za-z0-9_-]{43,128}', secret), 'InvalidStagingSecret')
    level = '1' if name == 'worktime-staging-employee' else '2'
    return {
        'clientId': name, 'protocol': 'openid-connect', 'enabled': False,
        'publicClient': False, 'clientAuthenticatorType': 'client-secret', 'secret': secret,
        'standardFlowEnabled': True, 'implicitFlowEnabled': False,
        'directAccessGrantsEnabled': False, 'serviceAccountsEnabled': False,
        'fullScopeAllowed': False, 'redirectUris': [STAGING_CLIENTS[name]], 'webOrigins': [],
        'authenticationFlowBindingOverrides': {},
        'defaultClientScopes': ['basic', 'profile', 'email', 'acr'], 'optionalClientScopes': [],
        'attributes': {'pkce.code.challenge.method': 'S256',
            'access.token.signed.response.alg': 'RS256', 'id.token.signed.response.alg': 'RS256',
            'default.acr.values': 'urn:sosnadmin:loa:' + level, 'minimum.acr.value': level},
        'protocolMappers': [
            {'name': 'ad-object-guid', 'protocol': 'openid-connect',
             'protocolMapper': 'oidc-usermodel-attribute-mapper',
             'config': {'user.attribute': 'LDAP_ID', 'claim.name': 'ad_object_guid',
                'jsonType.label': 'String', 'id.token.claim': 'true', 'access.token.claim': 'true',
                'userinfo.token.claim': 'true', 'introspection.token.claim': 'true'}},
            {'name': 'self-introspection-audience', 'protocol': 'openid-connect',
             'protocolMapper': 'oidc-audience-mapper',
             'config': {'included.client.audience': name, 'access.token.claim': 'true',
                'introspection.token.claim': 'true', 'id.token.claim': 'false', 'userinfo.token.claim': 'false'}},
        ],
    }


class StagingAdminClient:
    """Loopback-only bounded API; mutation permits are exact and one-use."""
    def __init__(self):
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), pilot.NoRedirects())
        self.token = None
        self.requests = 0
        self.writes = {}

    def request(self, method, path, *, payload=None, form=None, authenticated=True):
        permit = (method, path)
        allowed_write = permit in self.writes and self.writes[permit] == payload and form is None
        pilot.require(method == 'GET' or (method == 'POST' and path in (pilot.TOKEN_PATH, pilot.LDAP_TEST_PATH)) or
                      allowed_write, 'MutationProhibited')
        if allowed_write:
            del self.writes[permit]
        pilot.require(path == pilot.TOKEN_PATH or path == PREFIX or path.startswith(PREFIX + '/'), 'PathProhibited')
        pilot.require('..' not in path and '\r' not in path and '\n' not in path and not path.startswith('//'), 'PathProhibited')
        self.requests += 1
        pilot.require(self.requests <= 96, 'RequestBudgetExceeded')
        headers = {'Accept': 'application/json'}
        data = None
        if payload is not None:
            data = json.dumps(payload).encode('utf-8'); headers['Content-Type'] = 'application/json'
        if form is not None:
            data = urllib.parse.urlencode(form).encode('ascii'); headers['Content-Type'] = 'application/x-www-form-urlencoded'
        if authenticated:
            pilot.require(bool(self.token), 'AdminTokenMissing')
            headers['Authorization'] = 'Bearer ' + self.token
        request = urllib.request.Request(pilot.BASE + path, method=method, headers=headers, data=data)
        try:
            with self.opener.open(request, timeout=10) as response:
                body = response.read(1024 * 1024 + 1)
                pilot.require(len(body) <= 1024 * 1024, 'ResponseTooLarge')
                return json.loads(body) if body else None
        except urllib.error.HTTPError as error:
            raise pilot.AcceptanceError('StagingAdminHTTP' + str(error.code)) from None
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, UnicodeError):
            raise pilot.AcceptanceError('StagingAdminRequestFailed') from None

    def login(self, password):
        result = self.request('POST', pilot.TOKEN_PATH, authenticated=False, form={
            'grant_type': 'password', 'client_id': 'admin-cli', 'username': 'sso-bootstrap', 'password': password})
        pilot.require(isinstance(result, dict) and isinstance(result.get('access_token'), str), 'AdminAuthenticationFailed')
        self.token = result['access_token']


def private_file(path):
    metadata = path.lstat()
    pilot.require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 0 and
                  stat.S_IMODE(metadata.st_mode) == 0o600, 'PrivateRootFileRequired')
    for parent in path.parents:
        details = parent.lstat()
        pilot.require(stat.S_ISDIR(details.st_mode) and details.st_uid == 0 and not(details.st_mode & 0o022), 'PrivatePhysicalParentRequired')


def read_secrets(path):
    private_file(path)
    values = parse_values(path.read_text(encoding='utf-8'))
    pilot.require(set(values) == set(SECRET_NAMES.values()), 'UnexpectedStagingSecretInventory')
    result = {name: values[key] for name, key in SECRET_NAMES.items()}
    for name, secret in result.items():
        client_payload(name, secret)
    pilot.require(len(set(result.values())) == 3, 'IndependentStagingSecretsRequired')
    return result


def client_path(client):
    identifier = client.get('id')
    pilot.require(isinstance(identifier, str) and 1 <= len(identifier) <= 128 and
                  re.fullmatch(r'[A-Za-z0-9_-]+', identifier), 'InvalidClientIdentity')
    return PREFIX + '/clients/' + urllib.parse.quote(identifier, safe='')


def existing_client(api, name):
    rows = api.request('GET', PREFIX + '/clients?clientId=' + name)
    pilot.require(isinstance(rows, list) and len(rows) <= 1, 'AmbiguousClientIdentity')
    if not rows:
        return None
    pilot.require(rows[0].get('clientId') == name, 'ClientIdentityMismatch')
    detail = api.request('GET', client_path(rows[0]))
    pilot.require(detail.get('clientId') == name and detail.get('id') == rows[0]['id'], 'ClientIdentityMismatch')
    return detail


def production_snapshot(api, baseline=None):
    result = {}
    for name in pilot.CLIENTS:
        client = existing_client(api, name) if baseline is None else api.request('GET', client_path(baseline[name]))
        pilot.require(client is not None and client.get('clientId') == name and
                      (baseline is None or client.get('id') == baseline[name]['id']), 'ProductionClientMissingOrReplaced')
        result[name] = copy.deepcopy(client)
    return result


def scope_inventory(api):
    """Verify stock assurance scopes and no scope roles before binding/enable.

    UUIDs were independently read from this fixed realm; definitions match
    OIDCLoginProtocolFactory26.8.1 addBasicClientScope/addAcrClientScope.
    """
    scopes = api.request('GET', PREFIX + '/client-scopes')
    pilot.require(isinstance(scopes, list), 'MalformedScopeInventory')
    selected = {name: [s for s in scopes if s.get('name') == name] for name in ('basic', 'profile', 'email', 'acr')}
    pilot.require(all(len(values) == 1 for values in selected.values()), 'MissingOrAmbiguousStagingScope')
    selected = {name: values[0] for name, values in selected.items()}
    ids = pilot.scope_id_map(list(selected.values()))
    for name, definition in selected.items():
        pilot.require(definition.get('protocol') == 'openid-connect', 'StagingScopeProtocolMismatch')
        roles = api.request('GET', PREFIX + '/client-scopes/' + urllib.parse.quote(ids[name], safe='') + '/scope-mappings')
        pilot.require(roles == {}, 'StagingScopeRoleMappingsProhibited')
    expected_mappers = {'basic': pilot.basic_scope_mappers(), 'acr': [
        {'name': 'acr loa level', 'protocol': 'openid-connect', 'protocolMapper': 'oidc-acr-mapper',
         'config': {'id.token.claim': 'true', 'introspection.token.claim': 'true', 'access.token.claim': 'true'}}]}
    for name in ('basic', 'acr'):
        definition = selected[name]
        pilot.require(ids[name] == ASSURANCE_SCOPE_IDS[name] and
                      definition.get('attributes') == {'include.in.token.scope': 'false', 'display.on.consent.screen': 'false'},
                      'UnexpectedAssuranceScopeIdentity')
        canonical = lambda values: sorted([pilot.canonical_mapper(m) for m in values], key=lambda x: x['name'])
        pilot.require(canonical(definition.get('protocolMappers', [])) == canonical(expected_mappers[name]),
                      'AssuranceScopeNotStockMappers')
    return ids


def verify_identity_retention(api):
    providers = api.request('GET', PREFIX + '/components?type=' + pilot.STORAGE_PROVIDER_TYPE + '&name=sosnadmin-ad-readonly')
    pilot.require(isinstance(providers, list) and len(providers) == 1, 'AmbiguousIdentityProvider')
    config = providers[0].get('config', {})
    pilot.require(providers[0].get('providerId') == 'ldap' and providers[0].get('id') == pilot.LDAP_COMPONENT_ID and
                  all(config.get(key) == [value] for key, value in {
                      'usersDn': pilot.PILOT_DN, 'searchScope': '0', 'editMode': 'READ_ONLY',
                      'cachePolicy': 'NO_CACHE',
                      'customUserSearchFilter': '(objectCategory=person)', 'removeInvalidUsersEnabled': 'false',
                  }.items()), 'IdentityRetentionFixRequiredBeforePilotLookup')
    mappers = api.request('GET', PREFIX + '/components?parent=' + urllib.parse.quote(pilot.LDAP_COMPONENT_ID, safe='') +
                          '&type=' + pilot.LDAP_MAPPER_TYPE)
    state = [m for m in mappers if m.get('providerId') == 'msad-user-account-control-mapper']
    pilot.require(len(state) == 1 and state[0].get('id') == pilot.LDAP_MSAD_COMPONENT_ID and
                  state[0].get('parentId') == pilot.LDAP_COMPONENT_ID and state[0].get('name') == 'msad-account-state' and
                  state[0].get('config', {}).get('always.read.enabled.value.from.ldap') == ['true'],
                  'FreshAdEnabledStateRequiredBeforePilotLookup')


def validate_staging(api, name, detail, secret, scope_ids):
    expected = client_payload(name, secret)
    for key, value in expected.items():
        if key in {'secret', 'enabled', 'attributes', 'protocolMappers', 'defaultClientScopes', 'authenticationFlowBindingOverrides'}:
            continue
        pilot.require(detail.get(key) == value, 'StagingClientConfigurationMismatch')
    pilot.require(type(detail.get('enabled')) is bool, 'InvalidStagingClientState')
    pilot.require(detail.get('authenticationFlowBindingOverrides') in (None, {}), 'StagingFlowOverrideProhibited')
    pilot.require(detail.get('bearerOnly', False) is False and detail.get('authorizationServicesEnabled', False) is False,
                  'UnexpectedStagingGrantConfiguration')
    attributes = detail.get('attributes', {})
    pilot.require(all(attributes.get(k) == v for k, v in expected['attributes'].items()) and
                  attributes.get('allow.token.introspection.without.audience.check', 'false') == 'false', 'StagingClientAssuranceMismatch')
    scopes = detail.get('defaultClientScopes', [])
    pilot.require(len(scopes) == 4 and set(scopes) == set(expected['defaultClientScopes']), 'StagingClientScopeMismatch')
    bindings = pilot.scope_id_map(api.request('GET', client_path(detail) + '/default-client-scopes'))
    pilot.require(bindings == scope_ids, 'StagingScopeBindingMismatch')
    canonical = lambda values: sorted([pilot.canonical_mapper(m) for m in values], key=lambda x: x['name'])
    pilot.require(canonical(detail.get('protocolMappers', [])) == canonical(expected['protocolMappers']), 'StagingMapperMismatch')
    material = api.request('GET', client_path(detail) + '/client-secret')
    pilot.require(isinstance(material, dict) and material.get('type') == 'secret' and
                  secrets.compare_digest(material.get('value', ''), secret), 'StagingSecretMismatch')


def prepare_clients(api, environment, expected_guid, *, secret_file=SECRET_FILE, apply=False, enable=False):
    # Do not invoke the existing exact-username lookup before the reviewed
    # provider policy is present: old exclusion/filter defaults can delete
    # an imported user's stable subject and OTP on a disabled-user lookup.
    verify_identity_retention(api)
    pilot.inspect_pilot(api, environment, expected_guid, expected_clients_enabled=True)
    scope_ids = scope_inventory(api)
    baseline = production_snapshot(api)
    materials = read_secrets(secret_file) if secret_file.exists() or secret_file.is_symlink() else None
    production_secrets = {environment[name] for name in PRODUCTION_SECRET_NAMES if environment.get(name)}
    pilot.require(materials is None or not set(materials.values()).intersection(production_secrets), 'StagingSecretReusesProduction')
    clients = {name: existing_client(api, name) for name in STAGING_CLIENTS}
    pilot.require(materials is not None or all(c is None for c in clients.values()), 'ExistingStagingClientWithoutOwnedSecrets')
    if enable:
        pilot.require(materials is not None and all(c is not None for c in clients.values()), 'PrepareAllStagingClientsBeforeEnable')
    if materials:
        for name, detail in clients.items():
            if detail is not None:
                validate_staging(api, name, detail, materials[name], scope_ids)
    missing = sum(client is None for client in clients.values())
    if not apply:
        return {'status': 'StagingEnablePlan' if enable else 'StagingClientsPlan', 'missing_clients': missing,
                'clients': dict(STAGING_CLIENTS), 'production_clients_changed': False, 'application_flags_changed': False}
    if materials is None:
        materials = {name: secrets.token_urlsafe(48) for name in STAGING_CLIENTS}
        pilot.require(len(set(materials.values())) == 3 and not set(materials.values()).intersection(production_secrets),
            'IndependentStagingSecretsRequired')
        write_exclusive(secret_file, ''.join(SECRET_NAMES[name] + '=' + materials[name] + '\n' for name in STAGING_CLIENTS).encode('ascii'))
    created = enabled = 0
    for name, detail in clients.items():
        if detail is None:
            payload = client_payload(name, materials[name])
            api.writes = {('POST', PREFIX + '/clients'): copy.deepcopy(payload)}
            api.request('POST', PREFIX + '/clients', payload=payload)
            detail = existing_client(api, name)
            pilot.require(detail is not None and detail.get('enabled') is False, 'StagingCreateNotVerified')
            validate_staging(api, name, detail, materials[name], scope_ids)
            created += 1
        elif enable and detail['enabled'] is False:
            fresh = existing_client(api, name)
            pilot.require(fresh == detail, 'StagingClientChangedBeforeEnable')
            pilot.require(scope_inventory(api) == scope_ids, 'StagingScopeChangedBeforeEnable')
            validate_staging(api, name, fresh, materials[name], scope_ids)
            path = client_path(detail)
            payload = {'id': detail['id'], 'clientId': name, 'enabled': True, 'webOrigins': []}
            api.writes = {('PUT', path): copy.deepcopy(payload)}
            api.request('PUT', path, payload=payload)
            current = existing_client(api, name)
            pilot.require({k: v for k, v in current.items() if k != 'enabled'} ==
                          {k: v for k, v in detail.items() if k != 'enabled'} and current.get('enabled') is True,
                          'OtherStagingClientFieldsChanged')
            validate_staging(api, name, current, materials[name], scope_ids)
            enabled += 1
        pilot.require(production_snapshot(api, baseline) == baseline, 'ProductionClientsChanged')
    return {'status': 'StagingClientsEnabled' if enable else 'StagingClientsPrepared',
            'created_clients': created, 'enabled_clients': enabled, 'production_clients_changed': False,
            'application_flags_changed': False, 'ad_changed': False, 'secret_values_logged': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true', help='Apply only the reviewed fixed staging operation')
    parser.add_argument('--enable-staging-clients', action='store_true', help='Separate enablement; no app flag/config changes')
    parser.add_argument('--expected-ad-guid', required=True)
    args = parser.parse_args()
    pilot.require(str(uuid.UUID(args.expected_ad_guid)) == args.expected_ad_guid, 'ExpectedGuidMustBeCanonical')
    pilot.require(sys.platform == 'linux' and os.geteuid() == 0, 'ApprovedLinuxRootRequired')
    addresses = subprocess.run(['hostname', '-I'], capture_output=True, text=True, check=True, timeout=5).stdout.split()
    pilot.require('192.168.100.19' in addresses, 'WrongDeploymentHost')
    private_file(PROVISION_FILE)
    environment = parse_values(PROVISION_FILE.read_text(encoding='utf-8'))
    pilot.require(all(isinstance(environment.get(name), str) and len(environment[name]) >= 43
                      for name in PRODUCTION_SECRET_NAMES) and
                  len({environment[name] for name in PRODUCTION_SECRET_NAMES}) == 3,
                  'IndependentProductionSecretInventoryRequired')
    api = StagingAdminClient()
    api.login(environment['SSO_BOOTSTRAP_PASSWORD'])
    print(json.dumps(prepare_clients(api, environment, args.expected_ad_guid, apply=args.apply, enable=args.enable_staging_clients)))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'status': 'StagingClientOperationRefused', 'reconcile_before_retry': True,
                          'error_code': str(error) if isinstance(error, pilot.AcceptanceError) else type(error).__name__,
                          'secret_values_logged': False}))
        raise SystemExit(1) from None
