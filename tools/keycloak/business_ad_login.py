"""Exact-account business SSO extension; inert by default, no app-role grants.

An approved native adapter supplies fresh directory proof, private backup and
Admin REST access. The existing pilot provider and imported identities are never
update targets. The operator must preserve original user/credential/role rows.
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
import uuid

PROVIDER_NAME='business-admin2-ad-readonly'
STORAGE='org.keycloak.storage.UserStorageProvider'
MAPPERS='org.keycloak.storage.ldap.mappers.LDAPStorageMapper'
PILOT_DN='CN=ssopilot-20261027,OU=TEST,DC=sosnadmin,DC=local'

class Refused(ValueError): pass
def need(value,code):
    if not value: raise Refused(code)

def validate_identity(proof,now_ms):
    need(type(proof) is dict and proof.get('login')=='admin-2','SelectedAccountMismatch')
    need(all(proof.get(k) is True for k in ('enabled','strict_ldaps','windows_sid_matches')) and
        all(proof.get(k) is False for k in ('locked','password_expired')),'DirectoryProofRequired')
    observed=proof.get('observed_at_ms')
    need(type(observed) is int and type(now_ms) is int and 0<=now_ms-observed<=300000,'FreshDirectoryProofRequired')
    for key in ('distinguished_name','object_sid','object_guid'):
        need(type(proof.get(key)) is str and 0<len(proof[key])<=2048 and not any(c in proof[key] for c in '\r\n\0'),'IdentityEncoding')
    need(proof['distinguished_name'].lower().endswith(',dc=sosnadmin,dc=local') and proof['distinguished_name'].lower()!=PILOT_DN.lower(),'SelectedDnMismatch')
    need(re.fullmatch(r'S-1-5-21-(?:[0-9]{1,10}-){3}[0-9]{1,10}',proof['object_sid']),'IdentitySid')
    try: guid=uuid.UUID(proof['object_guid'])
    except ValueError: raise Refused('IdentityGuid') from None
    need(str(guid)==proof['object_guid'] and guid.int!=0,'IdentityGuid')
    return guid

def provider_payload(pilot,proof,bind_password,*,now_ms):
    guid=validate_identity(proof,now_ms)
    need(pilot.get('providerId')=='ldap' and pilot.get('providerType')==STORAGE and type(pilot.get('parentId')) is str,'PilotProviderShape')
    config=pilot.get('config'); need(type(config) is dict,'PilotConfig')
    for key,value in dict(enabled='true',vendor='ad',editMode='READ_ONLY',usersDn=PILOT_DN,searchScope='0',
        connectionUrl='ldaps://AD-MAIN.sosnadmin.local:636',uuidLDAPAttribute='objectGUID',usernameLDAPAttribute='sAMAccountName',
        removeInvalidUsersEnabled='false',bindDn='CN=svc-keycloak-ldap,CN=Users,DC=sosnadmin,DC=local').items():
        need(config.get(key)==[value],'PilotScopeMismatch')
    need(type(bind_password) is str and 1<=len(bind_password)<=1024,'BindCredentialRequired')
    config=copy.deepcopy(config)
    binary=''.join('\\'+format(value,'02x') for value in guid.bytes_le)
    changes=dict(enabled='false',priority='1',usersDn=proof['distinguished_name'],searchScope='0',
        customUserSearchFilter='(&(objectCategory=person)(objectGUID='+binary+'))',bindCredential=bind_password,
        syncRegistrations='false',fullSyncPeriod='-1',changedSyncPeriod='-1',cachePolicy='NO_CACHE',importEnabled='true')
    config.update({key:[value] for key,value in changes.items()})
    return dict(name=PROVIDER_NAME,parentId=pilot['parentId'],providerId='ldap',providerType=STORAGE,config=config)

def canonical(value):
    need(type(value) is dict,'ComponentShape')
    return {key:copy.deepcopy(value[key]) for key in ('name','parentId','providerId','providerType','config') if key in value}

def readback_matches(actual,expected):
    actual=canonical(actual); expected=canonical(expected)
    # Admin REST masks credentials. They must never be fetched back into evidence.
    for value in (actual,expected): value.get('config',{}).pop('bindCredential',None)
    need(actual==expected,'ProviderReadbackMismatch')

def mapper_updates(pilot_rows,new_rows,pilot_id,new_id):
    need(pilot_id!=new_id and type(pilot_rows) is list and type(new_rows) is list and len(pilot_rows)<=12,'MapperScope')
    old={row.get('name'):row for row in pilot_rows}; new={row.get('name'):row for row in new_rows}
    need(len(old)==len(pilot_rows) and len(new)==len(new_rows) and set(old)==set(new),'MapperNames')
    changes=[]
    for name,row in old.items():
        target=new[name]
        need(row.get('parentId')==pilot_id and target.get('parentId')==new_id and row.get('providerType')==target.get('providerType')==MAPPERS,'MapperParent')
        need(row.get('providerId')==target.get('providerId') and row['providerId'] in ('user-attribute-ldap-mapper','full-name-ldap-mapper','msad-user-account-control-mapper'),'MapperType')
        need(type(target.get('id')) is str and target['id']!=row.get('id'),'MapperIdentity')
        desired=canonical(row); desired.update(id=target['id'],parentId=new_id)
        if canonical(target)!=canonical(desired): changes.append((target['id'],desired))
    return changes

def enable_exact_user(ops,proof,bind_password,*,now_ms,apply=False):
    pilot,pilot_mappers=ops.preflight(proof)
    payload=provider_payload(pilot,proof,bind_password,now_ms=now_ms)
    result=dict(status='BusinessAdLoginPlanOnly',selected_account_count=1,pilot_provider_changed=False,app_roles_changed=False)
    if not apply: return result
    backup=ops.backup();need(backup.get('toc_verified') is True and re.fullmatch('[0-9a-f]{64}',backup.get('sha256','')),'VerifiedBackupRequired')
    ops.save('create-intent.json',dict(payload_sha256=hashlib.sha256(json.dumps(payload,sort_keys=True).encode()).hexdigest(),initially_enabled=False))
    created=None; enable_attempted=False
    try:
        created=ops.create(payload);need(type(created) is str and re.fullmatch('[A-Za-z0-9_-]{1,128}',created),'CreatedProviderIdentity')
        ops.save('owned-provider.json',dict(id=created,name=PROVIDER_NAME,parentId=payload['parentId']))
        readback_matches(ops.read(created),payload)
        for mapper_id,desired in mapper_updates(pilot_mappers,ops.mappers(created),pilot['id'],created):ops.update_mapper(mapper_id,desired)
        need(not mapper_updates(pilot_mappers,ops.mappers(created),pilot['id'],created),'MapperReadbackMismatch')
        ops.unchanged()
        desired=copy.deepcopy(payload);desired['config']['enabled']=['true']
        ops.save('enable-intent.json',dict(id=created,enabled=True));enable_attempted=True
        ops.update(created,desired);readback_matches(ops.read(created),desired);ops.unchanged()
        result.update(status='BusinessAdLoginEnabled',backup=backup,provider_enabled=True,existing_identities_preserved=True)
        ops.save('result.json',result);return result
    except Exception:
        if created is not None and enable_attempted:
            # The native adapter must requalify this created ID/name/parent before
            # disabling only this provider; a timeout never authorizes blind retry.
            ops.disable_owned(created,payload)
        raise

if __name__=='__main__':
    print(json.dumps({'status':'PlanOnly','runtime_actions':False,'selected_account_count':1}))
