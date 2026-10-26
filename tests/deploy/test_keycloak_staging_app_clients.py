"""Fixed staging client creation must never adopt or mutate production clients."""
import copy
import importlib.util
import json
from pathlib import Path
import urllib.error

import pytest

ROOT = Path(__file__).resolve().parents[2]
GUID = 'ee51f8b3-a7a8-4a69-808f-45adc6b35139'


def module():
    spec = importlib.util.spec_from_file_location('staging_app_clients', ROOT / 'tools/keycloak/staging_app_clients.py')
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


class FakeAdmin:
    def __init__(self, runtime):
        self.runtime = runtime
        self.clients = {name: {'id': 'prod-' + name, 'clientId': name, 'enabled': True,
                              'secret': 'P' * 64 + str(i), 'production_field': 'preserve'}
                        for i, name in enumerate(runtime.pilot.CLIENTS)}
        self.calls = []
        self.writes = {}
        self.fail_after_create = False
        self.change_production = False
        self.scopes = {
            'basic': {'id': runtime.ASSURANCE_SCOPE_IDS['basic'], 'name': 'basic', 'protocol': 'openid-connect',
                'attributes': {'include.in.token.scope': 'false', 'display.on.consent.screen': 'false'},
                'protocolMappers': runtime.pilot.basic_scope_mappers()},
            'acr': {'id': runtime.ASSURANCE_SCOPE_IDS['acr'], 'name': 'acr', 'protocol': 'openid-connect',
                'attributes': {'include.in.token.scope': 'false', 'display.on.consent.screen': 'false'},
                'protocolMappers': [{'name': 'acr loa level', 'protocol': 'openid-connect', 'protocolMapper': 'oidc-acr-mapper',
                    'config': {'id.token.claim': 'true', 'introspection.token.claim': 'true', 'access.token.claim': 'true'}}]},
            'profile': {'id': 'profile-scope', 'name': 'profile', 'protocol': 'openid-connect'},
            'email': {'id': 'email-scope', 'name': 'email', 'protocol': 'openid-connect'},
        }
        self.scope_roles = {}
        self.binding_drift = {}
        self.detail_counts = {}
        self.drift_before_enable = False
        self.identity_retention_fixed = True
        self.fresh_enabled_state = True

    def request(self, method, path, *, payload=None, **kwargs):
        self.calls.append((method, path))
        if method == 'POST':
            assert path == self.runtime.PREFIX + '/clients'
            assert self.writes.pop((method, path)) == payload
            name = payload['clientId']
            self.clients[name] = dict(copy.deepcopy(payload), id='stage-' + name)
            if self.change_production:
                self.clients['helpdesk-web']['production_field'] = 'changed elsewhere'
            if self.fail_after_create:
                self.fail_after_create = False
                raise self.runtime.pilot.AcceptanceError('UncertainCreateOutcome')
            return None
        if method == 'PUT':
            assert self.writes.pop((method, path)) == payload
            name = path.rsplit('/', 1)[1].removeprefix('stage-')
            assert name in self.runtime.STAGING_CLIENTS
            self.clients[name]['enabled'] = True
            return None
        assert method == 'GET'
        if '/components?type=' in path:
            return [{'id': self.runtime.pilot.LDAP_COMPONENT_ID, 'providerId': 'ldap', 'config': {'usersDn': [self.runtime.pilot.PILOT_DN],
                'searchScope': ['0'], 'editMode': ['READ_ONLY'],
                'cachePolicy': ['NO_CACHE'],
                'customUserSearchFilter': ['(objectCategory=person)'],
                'removeInvalidUsersEnabled': ['false' if self.identity_retention_fixed else 'true']}}]
        if '/components?parent=' in path:
            return [{'id': self.runtime.pilot.LDAP_MSAD_COMPONENT_ID, 'parentId': self.runtime.pilot.LDAP_COMPONENT_ID,
                'name': 'msad-account-state', 'providerId': 'msad-user-account-control-mapper',
                'config': {'always.read.enabled.value.from.ldap': ['true' if self.fresh_enabled_state else 'false']}}]
        if path == self.runtime.PREFIX + '/client-scopes':
            return copy.deepcopy(list(self.scopes.values()))
        if path.endswith('/scope-mappings'):
            return copy.deepcopy(self.scope_roles)
        if path.endswith('/default-client-scopes'):
            identifier = path.removesuffix('/default-client-scopes').rsplit('/', 1)[1]
            client = next(c for c in self.clients.values() if c['id'] == identifier)
            return [{'name': n, 'id': self.binding_drift.get(n, self.scopes[n]['id'])} for n in client['defaultClientScopes']]
        if '?clientId=' in path:
            name = path.split('?clientId=', 1)[1]
            return [copy.deepcopy(self.clients[name])] if name in self.clients else []
        if path.endswith('/client-secret'):
            identifier = path.removesuffix('/client-secret').rsplit('/', 1)[1]
            return {'type': 'secret', 'value': next(c['secret'] for c in self.clients.values() if c['id'] == identifier)}
        identifier = path.rsplit('/', 1)[1]
        client = next(c for c in self.clients.values() if c['id'] == identifier)
        self.detail_counts[identifier] = self.detail_counts.get(identifier, 0) + 1
        if self.drift_before_enable and identifier == 'stage-helpdesk-staging-web' and self.detail_counts[identifier] == 2:
            client['authenticationFlowBindingOverrides'] = {'browser': 'weak-password-only-flow'}
        return copy.deepcopy(client)


def setup(monkeypatch):
    runtime = module()
    monkeypatch.setattr(runtime.pilot, 'inspect_pilot', lambda *_a, **_kw: {'pilot_guid_matches': True})
    monkeypatch.setattr(runtime, 'private_file', lambda _p: None)
    return runtime, FakeAdmin(runtime)


def test_fixed_payloads_keep_staging_callbacks_pkce_mfa_and_exact_self_audience():
    runtime = module()
    assert len(runtime.STAGING_CLIENTS) == 3
    for name, callback in runtime.STAGING_CLIENTS.items():
        payload = runtime.client_payload(name, 'S' * 64)
        assert payload['redirectUris'] == [callback]
        assert '-staging.sosnadmin.local/' in callback
        assert payload['enabled'] is False
        assert payload['webOrigins'] == [] and payload['optionalClientScopes'] == []
        assert set(payload['defaultClientScopes']) == {'basic', 'profile', 'email', 'acr'}
        assert all(payload[key] is False for key in ('publicClient', 'directAccessGrantsEnabled', 'implicitFlowEnabled', 'serviceAccountsEnabled', 'fullScopeAllowed'))
        assert payload['attributes']['pkce.code.challenge.method'] == 'S256'
        audience = next(m for m in payload['protocolMappers'] if m['name'] == 'self-introspection-audience')
        assert audience['config'] == {'included.client.audience': name, 'access.token.claim': 'true',
            'introspection.token.claim': 'true', 'id.token.claim': 'false', 'userinfo.token.claim': 'false'}
    with pytest.raises(runtime.pilot.AcceptanceError):
        runtime.client_payload('endpoint-admin', 'S' * 64)


def test_plan_does_not_generate_secrets_or_write_files(monkeypatch, tmp_path):
    runtime, api = setup(monkeypatch)
    monkeypatch.setattr(runtime.secrets, 'token_urlsafe', lambda *_a: pytest.fail('Plan generated secrets'))
    before = copy.deepcopy(api.clients)
    result = runtime.prepare_clients(api, {}, GUID, secret_file=tmp_path/'stage.env')
    assert result['status'] == 'StagingClientsPlan' and result['missing_clients'] == 3
    assert not list(tmp_path.iterdir()) and api.clients == before
    assert all(method == 'GET' for method, _ in api.calls)


def test_partial_create_reconciles_without_secret_rotation_and_preserves_production(monkeypatch, tmp_path):
    runtime, api = setup(monkeypatch)
    path = tmp_path/'stage.env'
    original = copy.deepcopy(api.clients)
    api.fail_after_create = True
    with pytest.raises(runtime.pilot.AcceptanceError, match='UncertainCreateOutcome'):
        runtime.prepare_clients(api, {}, GUID, secret_file=path, apply=True)
    material = path.read_bytes()
    assert len(api.clients) == 4
    result = runtime.prepare_clients(api, {}, GUID, secret_file=path, apply=True)
    assert result['created_clients'] == 2 and path.read_bytes() == material
    assert {k: api.clients[k] for k in original} == original
    assert all(api.clients[name]['enabled'] is False for name in runtime.STAGING_CLIENTS)
    result = runtime.prepare_clients(api, {}, GUID, secret_file=path, apply=True)
    assert result['created_clients'] == 0 and path.read_bytes() == material
    assert not any(value in json.dumps(result) for value in runtime.read_secrets(path).values())


@pytest.mark.parametrize('drift', ['callback', 'scope', 'secret', 'audience-bypass', 'flow-override'])
def test_existing_drift_refuses_before_any_write(monkeypatch, tmp_path, drift):
    runtime, api = setup(monkeypatch)
    path = tmp_path/'stage.env'
    runtime.prepare_clients(api, {}, GUID, secret_file=path, apply=True)
    client = api.clients['endpoint-staging-admin']
    if drift == 'callback': client['redirectUris'] = ['https://endpoint.sosnadmin.local/auth/admin/callback']
    elif drift == 'scope': client['defaultClientScopes'].append('roles')
    elif drift == 'secret': client['secret'] = 'foreign-secret'
    elif drift == 'audience-bypass': client['attributes']['allow.token.introspection.without.audience.check'] = 'true'
    else: client['authenticationFlowBindingOverrides'] = {'browser': 'weak-flow'}
    api.calls.clear()
    with pytest.raises(runtime.pilot.AcceptanceError):
        runtime.prepare_clients(api, {}, GUID, secret_file=path, apply=True)
    assert all(method == 'GET' for method, _ in api.calls)


def test_production_change_during_create_stops_remaining_mutations(monkeypatch, tmp_path):
    runtime, api = setup(monkeypatch)
    api.change_production = True
    with pytest.raises(runtime.pilot.AcceptanceError, match='ProductionClientsChanged'):
        runtime.prepare_clients(api, {}, GUID, secret_file=tmp_path/'stage.env', apply=True)
    assert len([method for method, _ in api.calls if method == 'POST']) == 1


def test_enable_is_separate_exact_idempotent_operation(monkeypatch, tmp_path):
    runtime, api = setup(monkeypatch)
    path = tmp_path/'stage.env'
    runtime.prepare_clients(api, {}, GUID, secret_file=path, apply=True)
    api.calls.clear()
    result = runtime.prepare_clients(api, {}, GUID, secret_file=path, enable=True)
    assert result['status'] == 'StagingEnablePlan' and all(m == 'GET' for m, _ in api.calls)
    result = runtime.prepare_clients(api, {}, GUID, secret_file=path, apply=True, enable=True)
    assert result['enabled_clients'] == 3
    assert runtime.prepare_clients(api, {}, GUID, secret_file=path, apply=True, enable=True)['enabled_clients'] == 0


def test_http_mutation_permit_is_one_shot_and_cannot_target_production():
    runtime = module()
    client = runtime.StagingAdminClient()
    for method, path, payload in [('PUT',runtime.PREFIX+'/clients/prod',{'enabled':True}),
                                  ('DELETE',runtime.PREFIX+'/users/any',None),
                                  ('POST',runtime.PREFIX+'/clients',{'clientId':'endpoint-admin'})]:
        with pytest.raises(runtime.pilot.AcceptanceError,match='MutationProhibited'):
            client.request(method,path,payload=payload)


def test_uncertain_http_write_consumes_exact_permit_before_retry(monkeypatch):
    runtime = module()
    client = runtime.StagingAdminClient()
    client.token = 'synthetic-memory-only-admin-authority'
    payload = runtime.client_payload('helpdesk-staging-web', 'S' * 64)
    path = runtime.PREFIX + '/clients'
    client.writes[('POST', path)] = payload
    def fail(*_a, **_kw):
        raise urllib.error.URLError('synthetic private transport message')
    monkeypatch.setattr(client.opener, 'open', fail)
    with pytest.raises(runtime.pilot.AcceptanceError, match='StagingAdminRequestFailed'):
        client.request('POST', path, payload=payload)
    assert client.writes == {}
    with pytest.raises(runtime.pilot.AcceptanceError, match='MutationProhibited'):
        client.request('POST', path, payload=payload)


def test_existing_secret_store_cannot_reuse_production_credentials(monkeypatch, tmp_path):
    runtime, api = setup(monkeypatch)
    path = tmp_path / 'stage.env'
    runtime.prepare_clients(api, {}, GUID, secret_file=path, apply=True)
    shared = next(iter(runtime.read_secrets(path).values()))
    api.calls.clear()
    with pytest.raises(runtime.pilot.AcceptanceError, match='StagingSecretReusesProduction'):
        runtime.prepare_clients(api, {'SSO_HELPDESK_CLIENT_SECRET': shared}, GUID, secret_file=path, apply=True)
    assert all(method == 'GET' for method, _ in api.calls)


@pytest.mark.parametrize('drift', ['basic-mapper', 'acr-mapper', 'scope-id', 'scope-role', 'client-binding'])
def test_assurance_scope_definition_and_uuid_drift_refuses_before_enable(monkeypatch, tmp_path, drift):
    runtime, api = setup(monkeypatch)
    path = tmp_path / 'stage.env'
    runtime.prepare_clients(api, {}, GUID, secret_file=path, apply=True)
    if drift == 'basic-mapper': api.scopes['basic']['protocolMappers'][0]['config']['claim.value'] = 'forged-sub'
    elif drift == 'acr-mapper': api.scopes['acr']['protocolMappers'][0]['config']['id.token.claim'] = 'false'
    elif drift == 'scope-id': api.scopes['acr']['id'] = 'same-name-foreign-uuid'
    elif drift == 'scope-role': api.scope_roles = {'realmMappings': [{'name': 'admin'}]}
    else: api.binding_drift['basic'] = 'foreign-binding'
    api.calls.clear()
    with pytest.raises(runtime.pilot.AcceptanceError):
        runtime.prepare_clients(api, {}, GUID, secret_file=path, apply=True, enable=True)
    assert all(method == 'GET' for method, _ in api.calls)


def test_each_disabled_client_is_rechecked_immediately_before_enable(monkeypatch, tmp_path):
    runtime, api = setup(monkeypatch)
    path = tmp_path / 'stage.env'
    runtime.prepare_clients(api, {}, GUID, secret_file=path, apply=True)
    api.calls.clear(); api.detail_counts.clear(); api.drift_before_enable = True
    with pytest.raises(runtime.pilot.AcceptanceError, match='StagingClientChangedBeforeEnable'):
        runtime.prepare_clients(api, {}, GUID, secret_file=path, apply=True, enable=True)
    assert all(method == 'GET' for method, _ in api.calls)


def test_largest_enable_path_fits_fixed_http_budget_and_accepts_absent_empty_override(monkeypatch, tmp_path):
    runtime, api = setup(monkeypatch)
    path = tmp_path / 'stage.env'
    runtime.prepare_clients(api, {}, GUID, secret_file=path, apply=True)
    for name in runtime.STAGING_CLIENTS:
        del api.clients[name]['authenticationFlowBindingOverrides']
    api.calls.clear()
    result = runtime.prepare_clients(api, {}, GUID, secret_file=path, apply=True, enable=True)
    assert result['enabled_clients'] == 3
    # Current inspect_pilot uses eleven requests, including MSAD; login one.
    assert len(api.calls) + 12 <= 96


@pytest.mark.parametrize('apply,enable', [(False, False), (True, False), (True, True)])
def test_unfixed_identity_retention_refuses_operation_before_pilot_user_lookup(monkeypatch, tmp_path, apply, enable):
    runtime, api = setup(monkeypatch)
    path = tmp_path / 'stage.env'
    runtime.prepare_clients(api, {}, GUID, secret_file=path, apply=True)
    api.identity_retention_fixed = False
    monkeypatch.setattr(runtime.pilot, 'inspect_pilot', lambda *_a, **_kw: pytest.fail('Unsafe user lookup'))
    api.calls.clear()
    with pytest.raises(runtime.pilot.AcceptanceError, match='IdentityRetentionFixRequiredBeforePilotLookup'):
        runtime.prepare_clients(api, {}, GUID, secret_file=path, apply=apply, enable=enable)
    assert len(api.calls) == 1 and all(method == 'GET' for method, _ in api.calls)


def test_msad_fresh_enabled_flag_is_required_before_any_pilot_lookup(monkeypatch, tmp_path):
    runtime, api = setup(monkeypatch)
    api.fresh_enabled_state = False
    monkeypatch.setattr(runtime.pilot, 'inspect_pilot', lambda *_a, **_kw: pytest.fail('Unsafe user lookup'))
    with pytest.raises(runtime.pilot.AcceptanceError, match='FreshAdEnabledStateRequiredBeforePilotLookup'):
        runtime.prepare_clients(api, {}, GUID, secret_file=tmp_path / 'stage.env', apply=True)
    assert len(api.calls) == 2 and all(method == 'GET' for method, _ in api.calls)
