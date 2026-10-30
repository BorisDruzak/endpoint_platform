from copy import deepcopy
from uuid import UUID

import pytest

from tools.keycloak.business_ad_login import Refused, provider_payload, mapper_updates, enable_exact_user, reconcile_mappers, verify_owned_resume

GUID='00000000-0000-4000-8000-000000000002'
DN='CN=admin-2,CN=Users,DC=sosnadmin,DC=local'
PROOF=dict(login='admin-2',object_guid=GUID,distinguished_name=DN,object_sid='S-1-5-21-1-2-3-1001',
    enabled=True,locked=False,password_expired=False,strict_ldaps=True,windows_sid_matches=True,observed_at_ms=1000)
PILOT=dict(id='pilot-provider',parentId='business-realm',providerId='ldap',providerType='org.keycloak.storage.UserStorageProvider',
    name='existing-pilot',config={k:[v] for k,v in dict(enabled='true',vendor='ad',editMode='READ_ONLY',usersDn='CN=ssopilot-20261027,OU=TEST,DC=sosnadmin,DC=local',
        searchScope='0',connectionUrl='ldaps://AD-MAIN.sosnadmin.local:636',uuidLDAPAttribute='objectGUID',usernameLDAPAttribute='sAMAccountName',
        bindDn='CN=svc-keycloak-ldap,CN=Users,DC=sosnadmin,DC=local',removeInvalidUsersEnabled='false',customUserSearchFilter='(objectCategory=person)',bindCredential='**********').items()})
PILOT['config'].update(allowKerberosAuthentication=['false'],useKerberosForPasswordAuthentication=['false'])

def test_exact_user_provider_preserves_pilot_and_is_disabled_until_checked():
    original=deepcopy(PILOT)
    payload=provider_payload(PILOT,PROOF,'fixture-bind-secret',now_ms=1100)
    assert PILOT==original and 'id' not in payload
    assert payload['parentId']=='business-realm'
    expected_guid=''.join('\\'+format(v,'02x') for v in UUID(GUID).bytes_le)
    assert payload['config']['customUserSearchFilter']==['(&(objectCategory=person)(objectGUID='+expected_guid+'))']
    for key,value in dict(usersDn=DN,searchScope='0',enabled='false',editMode='READ_ONLY',syncRegistrations='false',fullSyncPeriod='-1',changedSyncPeriod='-1').items():
        assert payload['config'][key]==[value]

def test_provider_explicitly_matches_keycloak_ad_principal_default():
    payload=provider_payload(PILOT,PROOF,'fixture',now_ms=1100)
    assert payload['config']['krbPrincipalAttribute']==['userPrincipalName']
    assert payload['config']['allowKerberosAuthentication']==['false']

@pytest.mark.parametrize('change',[dict(login='other'),dict(enabled=False),dict(locked=True),dict(password_expired=True),dict(windows_sid_matches=False),dict(strict_ldaps=False),dict(observed_at_ms=0),dict(object_guid='invalid')])
def test_unqualified_or_stale_identity_is_refused(change):
    with pytest.raises(Refused):provider_payload(PILOT,PROOF|change,'fixture',now_ms=300001)

def test_mapper_plan_is_confined_to_new_provider_and_preserves_msad_checks():
    old=dict(id='old-map',parentId='pilot-provider',name='MSAD',providerId='msad-user-account-control-mapper',
        providerType='org.keycloak.storage.ldap.mappers.LDAPStorageMapper',config={'always.read.enabled.value.from.ldap':['true']})
    new=deepcopy(old);new.update(id='new-map',parentId='new-provider');new['config']={'always.read.enabled.value.from.ldap':['false']}
    updates=mapper_updates([old],[new],'pilot-provider','new-provider')
    assert updates==[('new-map',dict(old,id='new-map',parentId='new-provider'))]
    with pytest.raises(Refused):mapper_updates([old],[old],'pilot-provider','new-provider')

class Ops:
    def __init__(self):self.calls=[];self.created=None;self.payload=None;self.enabled=False
    def preflight(self,proof):self.calls.append('preflight');return deepcopy(PILOT),[]
    def backup(self):self.calls.append('backup');return {'toc_verified':True,'sha256':'a'*64}
    def save(self,name,value):self.calls.append(name)
    def create(self,payload):self.calls.append('create');self.payload=deepcopy(payload);self.created='new-provider';return self.created
    def read(self,pid):assert pid==self.created;return dict(self.payload,id=pid)
    def mappers(self,pid):return []
    def update_mapper(self,*args):pytest.fail('no mapper update expected')
    def update(self,pid,payload):assert pid==self.created;self.calls.append('enable' if payload['config']['enabled']==['true'] else 'disable');self.payload=deepcopy(payload)
    def unchanged(self):self.calls.append('unchanged')

def test_enable_requires_backup_disabled_readback_and_unchanged_originals():
    ops=Ops();result=enable_exact_user(ops,PROOF,'fixture',now_ms=1100,apply=True)
    assert result['status']=='BusinessAdLoginEnabled'
    assert ops.calls.index('backup')<ops.calls.index('create')<ops.calls.index('enable')
    assert ops.calls.index('unchanged')<ops.calls.index('enable')
    assert not any('role' in call or 'password' in call for call in ops.calls)

def test_readback_failure_never_enables_new_provider():
    ops=Ops()
    def bad_read(pid):return dict(ops.payload,id=pid,config=ops.payload['config']|{'searchScope':['2']})
    ops.read=bad_read
    with pytest.raises(Refused):enable_exact_user(ops,PROOF,'fixture',now_ms=1100,apply=True)
    assert 'enable' not in ops.calls

def test_default_plan_does_not_create_or_enable():
    ops=Ops();result=enable_exact_user(ops,PROOF,'fixture',now_ms=1100)
    assert result['status']=='BusinessAdLoginPlanOnly'
    assert not {'backup','create','enable'}.intersection(ops.calls)

@pytest.mark.parametrize(('method','path'),[
    ('PUT','/admin/realms/sosnadmin/users/user/role-mappings/realm'),
    ('PUT','/admin/realms/sosnadmin/components/pilot-provider'),
    ('POST','/admin/realms/sosnadmin/users'),
    ('DELETE','/admin/realms/sosnadmin/components/new-provider'),
])
def test_native_transport_rejects_roles_users_existing_provider_and_deletion(method,path):
    from tools.keycloak.business_ad_login_native import Native
    native=object.__new__(Native);native.phase='apply';native.provider_id='new-provider';native.owned_ids={'new-provider'}
    native.requests=0;native.token='fixture';native.token_until=0;native.fresh=lambda:None
    native.renew=lambda **kw:pytest.fail('a prohibited request must not refresh or contact the server')
    with pytest.raises(Refused,match='AdminRequestProhibited'):native.http(method,path,payload={})
    assert native.requests==0

def test_enable_postcheck_failure_disables_only_created_provider():
    ops=Ops();count=0;disabled=[]
    def unchanged():
        nonlocal count
        count+=1
        if count==2:raise Refused('Postcheck')
    ops.unchanged=unchanged
    ops.disable_owned=lambda pid,payload:disabled.append((pid,payload['name']))
    with pytest.raises(Refused,match='Postcheck'):enable_exact_user(ops,PROOF,'fixture',now_ms=1100,apply=True)
    assert disabled==[('new-provider','business-admin2-ad-readonly')]

def test_native_cleanup_read_disable_read_survives_expired_proof(monkeypatch):
    import json
    from types import SimpleNamespace
    from tools.keycloak import business_ad_login_native as n
    native=object.__new__(n.Native);native.phase='apply';native.provider_id='new-provider';native.owned_ids={'new-provider'}
    native.requests=0;native.token='fixture';native.refresh=None;native.token_until=10000;native.bindings=SimpleNamespace(recovery=False)
    native.assert_binding=lambda:None;native.save=lambda *args:None
    def expired():raise Refused('FreshRequestRequired')
    native.fresh=expired;calls=[];enabled=True
    class Response:
        def __init__(self,value):self.raw=json.dumps(value).encode() if value else b'';self.status=200;self.headers={}
        def __enter__(self):return self
        def __exit__(self,*args):pass
        def read(self,limit):return self.raw
    class Opener:
        def open(self,req,timeout):
            nonlocal enabled
            calls.append((req.method,req.full_url))
            if req.method=='PUT':
                assert json.loads(req.data)=={'providerId':'ldap','providerType':n.TYPE,'config':{'enabled':['false']}}
                enabled=False;return Response(None)
            return Response(dict(id='new-provider',name='business-admin2-ad-readonly',parentId='business-realm',providerId='ldap',config={'enabled':['true' if enabled else 'false']}))
    native.opener=Opener();monkeypatch.setattr(n.time,'monotonic',lambda:1000)
    native.disable_owned('new-provider',{'parentId':'business-realm'})
    assert [v[0] for v in calls]==['GET','PUT','GET'] and not enabled
    assert all(v[1]=='http://127.0.0.1:8088/admin/realms/sosnadmin/components/new-provider' for v in calls)
    with pytest.raises(Refused,match='CleanupScope'):
        native.http('GET',n.COMPONENTS+'/pilot-provider',recovery=True)

@pytest.mark.parametrize('operation',['login','backup','create','create_mapper','remove_mapper','update_mapper','update','unchanged'])
def test_native_binding_failure_blocks_auth_backup_and_provider_writes(operation):
    from tools.keycloak.business_ad_login_native import Native
    native=object.__new__(Native);native.fresh=lambda:None
    def wrong_database():raise Refused('DatabaseOidChanged')
    native.assert_binding=wrong_database
    native.http=lambda *args,**kwargs:pytest.fail('unbound target must not receive a request')
    arguments={'create':({},),'create_mapper':({},),'remove_mapper':('mapper',{}),'update_mapper':('mapper',{}),'update':('provider',{})}.get(operation,())
    with pytest.raises(Refused,match='DatabaseOidChanged'):getattr(native,operation)(*arguments)

@pytest.mark.parametrize('origin',['https://sso.sosnadmin.local','http://127.0.0.1:8088','https://foreign.example'])
def test_created_location_is_parsed_only_for_canonical_origins(monkeypatch,origin):
    from tools.keycloak import business_ad_login_native as n
    native=object.__new__(n.Native);native.assert_binding=lambda:None;native.pilot=PILOT;native.proof=PROOF
    native.environment={'SSO_LDAP_BIND_PASSWORD':'fixture'};native.provider_id=None;native.owned_ids=set()
    native.http=lambda *a,**kw:(201,{'Location':origin+n.COMPONENTS+'/new-provider'},None)
    monkeypatch.setattr(n.time,'time',lambda:1.1)
    payload=provider_payload(PILOT,PROOF,'fixture',now_ms=1100)
    if origin.endswith('foreign.example'):
        with pytest.raises(Refused,match='ProviderLocation'):native.create(payload)
        assert not native.owned_ids
    else:assert native.create(payload)=='new-provider'

def test_resume_requires_exact_disabled_payload_and_original_create_fingerprint():
    import hashlib,json
    payload=provider_payload(PILOT,PROOF,'fixture',now_ms=1100)
    legacy=deepcopy(payload);legacy['config'].pop('krbPrincipalAttribute')
    fingerprint=hashlib.sha256(json.dumps(legacy,sort_keys=True).encode()).hexdigest()
    verify_owned_resume(dict(payload,id='new-provider'),payload,fingerprint)
    with pytest.raises(Refused,match='OwnedCreateIntentMismatch'):
        verify_owned_resume(dict(payload,id='new-provider'),payload,'f'*64)
    changed=deepcopy(payload);changed['config']['enabled']=['true']
    with pytest.raises(Refused,match='ProviderReadbackMismatch'):verify_owned_resume(changed,payload,fingerprint)

def test_native_resume_returns_owned_id_without_second_provider_post(monkeypatch):
    import hashlib,json
    from tools.keycloak import business_ad_login_native as n
    native=object.__new__(n.Native);native.assert_binding=lambda:None;native.pilot=PILOT;native.proof=PROOF
    native.environment={'SSO_LDAP_BIND_PASSWORD':'fixture'};native.provider_id=native.resume_id='new-provider';native.owned_ids={'new-provider'}
    payload=provider_payload(PILOT,PROOF,'fixture',now_ms=1100);legacy=deepcopy(payload);legacy['config'].pop('krbPrincipalAttribute')
    native.prior_intent=hashlib.sha256(json.dumps(legacy,sort_keys=True).encode()).hexdigest()
    native.read=lambda pid:dict(payload,id=pid);native.save=lambda *args:None
    native.http=lambda *a,**kw:pytest.fail('resume must never create a second provider')
    monkeypatch.setattr(n.time,'time',lambda:1.1)
    assert native.create(payload)=='new-provider'

def test_generated_mapper_reconciliation_preserves_matching_ids_and_only_replaces_owned_defaults():
    from types import SimpleNamespace
    mapper_type='org.keycloak.storage.ldap.mappers.LDAPStorageMapper'
    def row(name,pid,mid,kind='user-attribute-ldap-mapper'):
        return dict(name=name,parentId=pid,id=mid,providerType=mapper_type,providerId=kind,config={'read.only':['true']})
    old=[row('username','pilot','old-u'),row('firstName','pilot','old-f'),row('msad-account-state','pilot','old-m','msad-user-account-control-mapper')]
    current=[row('username','new','new-u'),row('full name','new','new-auto','full-name-ldap-mapper'),row('MSAD account controls','new','new-msad','msad-user-account-control-mapper')]
    actions=[]
    def update(mid,payload):
        actions.append(('update',mid));current[:]=[deepcopy(payload) if value['id']==mid else value for value in current]
    def create(payload):
        actions.append(('create',payload['name']));current.append(dict(deepcopy(payload),id='created-'+payload['name']))
    def remove(mid,expected):
        actions.append(('remove',mid));assert expected['parentId']=='new';current[:]=[value for value in current if value['id']!=mid]
    ops=SimpleNamespace(mappers=lambda pid:deepcopy(current),update_mapper=update,create_mapper=create,remove_mapper=remove,save=lambda *args:None)
    reconcile_mappers(ops,old,'pilot','new')
    assert {value['name'] for value in current}=={value['name'] for value in old}
    assert next(value['id'] for value in current if value['name']=='username')=='new-u'
    assert {value[1] for value in actions if value[0]=='remove'}=={'new-auto','new-msad'}
    assert all(not value[1].startswith('old-') for value in actions)

def test_unknown_generated_mapper_is_refused_before_any_mutation():
    from types import SimpleNamespace
    current=[dict(id='new-role',parentId='new',name='foreign-role-map',providerType='org.keycloak.storage.ldap.mappers.LDAPStorageMapper',providerId='role-ldap-mapper',config={})]
    def mutation(*args):pytest.fail('unknown mapper must not be modified')
    ops=SimpleNamespace(mappers=lambda pid:current,save=mutation,update_mapper=mutation,create_mapper=mutation,remove_mapper=mutation)
    with pytest.raises(Refused,match='UnexpectedGeneratedMapper'):reconcile_mappers(ops,[],'pilot','new')

def test_different_owned_default_mapper_is_recreated_without_merged_extra_keys():
    from types import SimpleNamespace
    kind='org.keycloak.storage.ldap.mappers.LDAPStorageMapper'
    old=dict(id='original',name='username',parentId='pilot',providerType=kind,providerId='user-attribute-ldap-mapper',config={'read.only':['true']})
    current=[dict(old,id='generated',parentId='new',config={'read.only':['false'],'extra-default':['true']})]
    removed=[]
    def remove(mid,expected):removed.append(mid);current.clear()
    def create(value):current.append(dict(value,id='cloned'))
    ops=SimpleNamespace(mappers=lambda pid:deepcopy(current),remove_mapper=remove,create_mapper=create,save=lambda *args:None,
        update_mapper=lambda *args:pytest.fail('PUT would retain default config keys'))
    reconcile_mappers(ops,[old],'pilot','new')
    assert removed==['generated'] and current[0]['config']==old['config']
