"""Fixed-host native adapter for the exact-account business LDAP extension.

PlanOnly without --run. Credential-bearing data stays in root memory/private
backup; no user-password request, AD write, role grant, sync or service restart.
"""
from __future__ import annotations
import copy, hashlib, ipaddress, json, os, pathlib, re, shutil, stat, subprocess, sys, time, types
import urllib.error, urllib.parse, urllib.request
from tools.keycloak import business_ad_login as policy

P=pathlib.Path
ROOT=P('/root/keycloak-business-ad-login-admin2-20261030-v1')
PREFIX='/admin/realms/sosnadmin'; MASTER='/admin/realms/master'
TOKEN='/realms/master/protocol/openid-connect/token'; LOGOUT='/realms/master/protocol/openid-connect/logout'
COMPONENTS=PREFIX+'/components'; TYPE=policy.STORAGE; MAPPERS=policy.MAPPERS
PILOT_ID='HqtFYF0QRMy-SARJtaSFzw'
TABLES=('realm','realm_attribute','client','client_attributes','protocol_mapper','protocol_mapper_config',
    'authentication_flow','authentication_execution','authenticator_config','authenticator_config_entry',
    'user_entity','user_attribute','credential','keycloak_role','composite_role','user_role_mapping',
    'keycloak_group','group_attribute','user_group_membership','group_role_mapping','component','component_config')

def need(value,code): policy.need(value,code)
def sha(value):return hashlib.sha256(value).hexdigest()
def encoded(value):return (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
def identity(s):return tuple(getattr(s,key) for key in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
def private(path,maximum=1024**2):
    s=P(path).lstat();need(stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and s.st_size<=maximum,'PrivateFileRequired')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        need(identity(os.fstat(fd))==identity(s),'PrivateFileChanged');raw=os.read(fd,maximum+1);need(len(raw)==s.st_size and identity(P(path).lstat())==identity(s),'PrivateFileChanged');return raw
    finally:os.close(fd)
def sync(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
def write(path,value):
    raw=encoded(value);fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,'wb',closefd=False) as stream:stream.write(raw);stream.flush();os.fsync(fd)
    finally:os.close(fd)
    sync(P(path).parent)
def opaque(value):
    need(type(value) is str and re.fullmatch('[A-Za-z0-9_-]{1,128}',value),'ComponentIdentity');return value
class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):raise policy.Refused('RedirectProhibited')

class Native:
    def __init__(self,request):
        need(os.geteuid()==0 and sys.platform=='linux','NativeRootRequired')
        need(set(request)=={'mode','issued_at_ms','expires_at_ms','source_sha256'} and request['mode'] in ('plan','apply'),'RequestShape')
        self.request=request;self.phase=request['mode'];self.provider_id=None;self.owned_ids=set();self.token=None;self.refresh=None;self.token_until=0;self.requests=0
        self.fresh()
        s=ROOT.lstat();need(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o700,'PrivateRootRequired')
        source=private(ROOT/'business_ad_login_native.py');need(sha(source)==request['source_sha256'],'SourcePin')
        freeze=json.loads(private(ROOT/'freeze.json'));need(set(freeze)=={'business_ad_login.py','business_ad_login_native.py','proof.json'},'SourceClosure')
        need(all(sha(private(ROOT/name))==value for name,value in freeze.items()),'SourceClosure')
        self.proof=json.loads(private(ROOT/'proof.json'));policy.validate_identity(self.proof,int(time.time()*1000))
        addresses=json.loads(subprocess.run(['/usr/sbin/ip','-j','address','show'],check=True,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=10).stdout)
        need('192.168.100.19' in {a.get('local') for row in addresses for a in row.get('addr_info',[])},'HostMismatch')
        self.attempt=ROOT/self.phase;need(not os.path.lexists(self.attempt),'ConsumedAttempt')
        os.mkdir(self.attempt,0o700);sync(ROOT);self.save('consumed.json',request)
        self.conf=P('/etc/keycloak/keycloak.conf');s=self.conf.lstat();need(stat.S_ISREG(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022,'ConfigOwnership')
        raw=self.conf.read_bytes();self.config_sha=sha(raw);values={}
        for line in raw.decode().splitlines():
            if '=' in line and not line.lstrip().startswith('#'):
                k,v=line.split('=',1);need(k.strip() not in values,'DuplicateConfig');values[k.strip()]=v.strip()
        url=urllib.parse.urlsplit(values['db-url'].removeprefix('jdbc:'))
        need(url.hostname=='127.0.0.1' and url.port==5544 and url.path=='/keycloak','DatabaseBinding')
        self.pg={'PATH':'/usr/bin:/bin','LC_ALL':'C','PGHOST':url.hostname,'PGPORT':'5544','PGDATABASE':'keycloak','PGUSER':values['db-username'],
            'PGPASSWORD':values['db-password'],'PGCONNECT_TIMEOUT':'5','PGPASSFILE':'/dev/null','PGSERVICEFILE':'/dev/null','PGOPTIONS':'-c default_transaction_read_only=on -c statement_timeout=15000'}
        env=private('/run/keycloak-provision-20261027/provision.env',16384);self.environment={}
        for line in env.decode().splitlines():
            k,v=line.split('=',1);need(k not in self.environment,'DuplicateOperatorInput');self.environment[k]=v
        need(self.environment.get('SSO_LDAP_BIND_DN')=='CN=svc-keycloak-ldap,CN=Users,DC=sosnadmin,DC=local' and self.environment.get('SSO_BOOTSTRAP_PASSWORD') and self.environment.get('SSO_LDAP_BIND_PASSWORD'),'OperatorInput')
        self.pid=self.command(['/usr/bin/systemctl','show','keycloak.service','--property=MainPID','--value']).strip()
        need(self.pid.isdigit() and int(self.pid)>0,'KeycloakInactive')
        self.opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirects())
        self.bindings=self.load_binding();self.service_process=None;self.assert_binding()

    def load_binding(self):
        # Reuse the previously reviewed read-only physical/Unix/JDBC guard,
        # without invoking any owner, promotion or lifecycle entry point.
        modules={}
        for name,digest in {'_promotion_io':'8d74e021c08df2c5f4e9630c3087841a7827016dacb6b419a8262670097b2ee0',
            'promotion_guards':'8b798f06c4bbe1bc1426007a07aad4ca8215a00e889d00cb0468b29aeaf7319e'}.items():
            path=P('/root/keycloak-owner-prepare-v4')/(name+'.py');raw=private(path);need(sha(raw)==digest,'CanonicalGuardSourcePin')
            module=types.ModuleType('business_binding_'+name);module.__file__=str(path)
            exec(compile(raw,str(path),'exec'),module.__dict__);modules[name]=module
        io=modules['_promotion_io'];io.host_guard();bound=io.NativeIO(modules['promotion_guards'])
        pg_unit=bound.unit('postgresql@16-keycloak.service');need(pg_unit['ActiveState']=='active' and pg_unit['SubState']=='running','CanonicalPostgresInactive')
        bound.canonical={'units':{'postgresql@16-keycloak.service':{'process':io.proc(int(pg_unit['MainPID']))}}}
        import pwd
        account=pwd.getpwnam('keycloak');bound.service_uid=account.pw_uid;bound.service_gid=account.pw_gid
        self.binding_module=io
        return bound

    def assert_binding(self):
        self.bindings.request('postgres',"SELECT jsonb_build_object('bound',true);")
        result=self.bindings.request('keycloak',"SELECT jsonb_build_object('bound',true);",26068)
        need(result=={'bound':True},'CanonicalDatabaseBinding')
        main=self.bindings.service_db(26068)
        need(str(main['pid']).encode()==self.pid and (self.service_process is None or main==self.service_process),'CanonicalKeycloakProcessChanged')
        self.service_process=main
        # Verify that the exact unit's process tree owns the Admin REST listener,
        # in addition to its JDBC sockets being bound to canonical OID26068.
        observations={}
        for name in os.listdir('/proc'):
            if name.isdecimal():
                try:value=self.binding_module.discover_process(int(name))
                except FileNotFoundError:continue
                if value is not None:observations[value['pid']]=value
        ids={main['pid']};prior=None
        while prior!=ids:prior=set(ids);ids|={pid for pid,value in observations.items() if value['ppid'] in ids}
        inodes=set()
        for pid in ids:
            value=self.binding_module.proc(pid);need(value['uid']==main['uid'] and value['gid']==main['gid'],'AdminProcessIdentity')
            for fd in (P('/proc')/str(pid)/'fd').iterdir():
                try:target=os.readlink(fd)
                except FileNotFoundError:continue
                if target.startswith('socket:['):inodes.add(target[8:-1])
        found=False
        for net in ('tcp','tcp6'):
            raw=(P('/proc/net')/net).read_text();need(len(raw)<=1024**2,'AdminSocketBound')
            for line in raw.splitlines()[1:]:
                fields=line.split()
                if len(fields)>9 and fields[3]=='0A' and int(fields[1].split(':')[1],16)==8088:
                    value=bytes.fromhex(fields[1].split(':')[0]);address=value[::-1] if len(value)==4 else b''.join(value[i:i+4][::-1] for i in range(0,16,4))
                    address=ipaddress.ip_address(address)
                    need((address.is_loopback or getattr(address,'ipv4_mapped',None) and address.ipv4_mapped.is_loopback) and fields[9] in inodes,'AdminListenerOwnership')
                    found=True
        need(found,'AdminListenerUnavailable')

    def fresh(self):
        p=self.request;stamp=int(time.time()*1000)
        need(type(p['issued_at_ms']) is int and type(p['expires_at_ms']) is int and p['issued_at_ms']<=stamp<p['expires_at_ms'] and 0<p['expires_at_ms']-p['issued_at_ms']<=300000,'FreshRequestRequired')
        if hasattr(self,'proof'):policy.validate_identity(self.proof,stamp)
    def save(self,name,value):
        need(re.fullmatch(r'[a-z-]+\.json',name),'ReceiptName');write(self.attempt/name,value)
    def command(self,args,timeout=20,*,input=None,env=None):
        result=subprocess.run(args,input=input,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout)
        need(result.returncode==0,'NativeCommandFailed');return result.stdout
    def query(self,sql):
        metadata=b"SELECT json_build_object('database',current_database(),'oid',(SELECT oid::bigint FROM pg_database WHERE datname=current_database()),'port',inet_server_port());\n"
        body=b'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;\n'+metadata+sql.encode()+b'\nCOMMIT;'
        lines=self.command(['/usr/bin/psql','-X','-qAt','-v','ON_ERROR_STOP=1'],input=body,env=self.pg).splitlines()
        need(len(lines)==2 and json.loads(lines[0])=={'database':'keycloak','oid':26068,'port':5544},'SnapshotDatabaseBinding')
        return json.loads(lines[1])
    def snapshot(self):
        ids=','.join("'"+opaque(value)+"'" for value in sorted(self.owned_ids)) or "''"
        parts=[]
        for table in TABLES:
            clause=f' WHERE t.id NOT IN ({ids})' if table=='component' else f' WHERE t.component_id NOT IN ({ids})' if table=='component_config' else ''
            parts.append("'"+table+"',(SELECT COALESCE(json_agg(row ORDER BY row::text),'[]'::json) FROM (SELECT to_jsonb(t) AS row FROM public."+table+' t'+clause+') x)')
        rows=self.query('SELECT json_build_object('+','.join(parts)+');')
        need(sum(len(encoded(value)) for value in rows.values())<=8*1024**2,'SnapshotBound')
        return {table:dict(count=len(value),sha256=sha(encoded(value))) for table,value in rows.items()}

    def http(self,method,path,*,payload=None,form=None,authenticated=True,recovery=False):
        owned_disable=(self.phase=='apply' and self.provider_id is not None and method=='PUT' and
            path==COMPONENTS+'/'+self.provider_id and payload=={'providerId':'ldap','providerType':TYPE,'config':{'enabled':['false']}})
        owned_read=(self.phase=='apply' and self.provider_id is not None and method=='GET' and path==COMPONENTS+'/'+self.provider_id and payload is None and form is None)
        cleanup_refresh=(method=='POST' and path==TOKEN and not authenticated and self.refresh is not None and
            form=={'grant_type':'refresh_token','client_id':'admin-cli','refresh_token':self.refresh} and payload is None)
        if recovery:
            need(time.monotonic()<=getattr(self,'cleanup_until',0) and (owned_disable or owned_read or cleanup_refresh),'CleanupScope')
        elif path!=LOGOUT:self.fresh()
        allowed_get={PREFIX,PREFIX+'/events/config',COMPONENTS+'?type='+TYPE,MASTER+'/components?type='+TYPE,
            COMPONENTS+'?parent='+PILOT_ID+'&type='+MAPPERS}
        if self.provider_id:allowed_get|={COMPONENTS+'/'+self.provider_id,COMPONENTS+'?parent='+self.provider_id+'&type='+MAPPERS}
        allowed=(method=='GET' and path in allowed_get) or (method=='POST' and path in (TOKEN,LOGOUT))
        allowed=allowed or (self.phase=='apply' and method=='POST' and path==COMPONENTS and self.provider_id is None)
        allowed=allowed or (self.phase=='apply' and method=='PUT' and self.provider_id is not None and path.rsplit('/',1)[-1] in self.owned_ids and path.startswith(COMPONENTS+'/'))
        need(allowed,'AdminRequestProhibited');self.requests+=1;need(self.requests<=80,'RequestBudget')
        if authenticated and self.token is not None and time.monotonic()>=self.token_until-5:
            self.renew(allow_expired_proof=recovery)
        headers={'Accept':'application/json'};data=None
        if authenticated:need(self.token is not None,'OperatorAuthentication');headers['Authorization']='Bearer '+self.token
        if payload is not None:headers['Content-Type']='application/json';data=json.dumps(payload).encode()
        if form is not None:headers['Content-Type']='application/x-www-form-urlencoded';data=urllib.parse.urlencode(form).encode()
        try:
            with self.opener.open(urllib.request.Request('http://127.0.0.1:8088'+path,data=data,headers=headers,method=method),timeout=10) as response:
                raw=response.read(1024**2+1);need(len(raw)<=1024**2,'ResponseBound')
                return response.status,dict(response.headers),json.loads(raw) if raw else None
        except urllib.error.HTTPError as error:raise policy.Refused('AdminHTTP'+str(error.code)) from None
        except (urllib.error.URLError,TimeoutError):raise policy.Refused('AdminResponseUncertain') from None
    def login(self):
        self.assert_binding()
        _,_,result=self.http('POST',TOKEN,authenticated=False,form={'grant_type':'password','client_id':'admin-cli','username':'sso-bootstrap','password':self.environment['SSO_BOOTSTRAP_PASSWORD']})
        need(type(result) is dict and type(result.get('access_token')) is str and type(result.get('refresh_token')) is str,'OperatorAuthentication')
        self.accept_token(result)
    def accept_token(self,result):
        need(type(result.get('access_token')) is str and type(result.get('refresh_token')) is str and type(result.get('expires_in')) is int and 10<=result['expires_in']<=3600,'OperatorTokenShape')
        self.token=result['access_token'];self.refresh=result['refresh_token'];self.token_until=time.monotonic()+result['expires_in']
    def renew(self,*,allow_expired_proof=False):
        need(self.refresh is not None,'OperatorRefreshRequired')
        # Refresh only this operator session. A narrow disable may finish after
        # the input deadline; it cannot enable or otherwise mutate a provider.
        _,_,result=self.http('POST',TOKEN,authenticated=False,recovery=allow_expired_proof,
            form={'grant_type':'refresh_token','client_id':'admin-cli','refresh_token':self.refresh})
        self.accept_token(result)
    def logout(self):
        if self.refresh:self.http('POST',LOGOUT,authenticated=False,form={'client_id':'admin-cli','refresh_token':self.refresh})
        self.token=None;self.refresh=None
    def get(self,path):return self.http('GET',path)[2]

    def preflight(self,proof):
        self.fresh();realm=self.get(PREFIX);need(type(realm) is dict and realm.get('realm')=='sosnadmin' and realm.get('registrationAllowed') is False,'RealmBinding')
        events=self.get(PREFIX+'/events/config');need(events.get('adminEventsDetailsEnabled') is False,'SecretAuditDetailsProhibited')
        providers=self.get(COMPONENTS+'?type='+TYPE);need(type(providers) is list and len(providers)==1 and providers[0].get('id')==PILOT_ID,'InitialPilotScope')
        pilot=providers[0];need(pilot['parentId']==realm['id'],'PilotRealm')
        owner=[value for value in self.get(MASTER+'/components?type='+TYPE) if value.get('name')=='permanent-owner-ad-readonly']
        need(len(owner)==1,'MasterOwnerBinding');cfg=owner[0]['config'];guid=''.join('\\'+format(v,'02x') for v in policy.validate_identity(proof,int(time.time()*1000)).bytes_le)
        need(cfg.get('usersDn')==[proof['distinguished_name']] and cfg.get('customUserSearchFilter')==['(&(objectCategory=person)(objectGUID='+guid+'))'] and cfg.get('enabled')==['true'],'MasterOwnerIdentityMismatch')
        # Credential comparison happens only inside RAM; no secret value or token
        # is returned, backed up as JSON or included in the diagnostic receipts.
        identity=self.query("SELECT json_build_object('existing_business',(SELECT count(*) FROM user_entity u JOIN realm r ON r.id=u.realm_id WHERE r.name='sosnadmin' AND u.username='admin-2'),'owner_guid',(SELECT a.value FROM user_attribute a JOIN user_entity u ON u.id=a.user_id JOIN realm r ON r.id=u.realm_id WHERE r.name='master' AND u.username='admin-2' AND a.name='LDAP_ID'),'bind',(SELECT value FROM component_config WHERE component_id='"+PILOT_ID+"' AND name='bindCredential'));" )
        need(identity['existing_business']==0 and identity['owner_guid']==proof['object_guid'],'ImportedIdentityCollision')
        need(identity['bind']==self.environment['SSO_LDAP_BIND_PASSWORD'],'BindChannelMismatch')
        mappers=self.get(COMPONENTS+'?parent='+PILOT_ID+'&type='+MAPPERS)
        need(any(v.get('providerId')=='msad-user-account-control-mapper' and v.get('config',{}).get('always.read.enabled.value.from.ldap')==['true'] for v in mappers),'MsadEnabledReadRequired')
        self.before=self.snapshot();self.profile_sha=sha(encoded({'providers':providers,'owner':owner,'rows':self.before}))
        if self.phase=='apply':
            planned=json.loads(private(ROOT/'plan/result.json'));need(planned['status']=='BusinessAdLoginPlanOnly' and planned['profile_sha256']==self.profile_sha,'PlanProfileDrift')
            need(json.loads(private(ROOT/'plan/logout.json'))['verified'] is True,'PlanOperatorLogoutRequired')
        return pilot,mappers
    def backup(self):
        self.fresh();self.assert_binding();need(shutil.disk_usage(ROOT).free>=512*1024**2,'BackupCapacity')
        path=self.attempt/'keycloak-before.dump';fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        try:
            result=subprocess.run(['/usr/bin/pg_dump','-w','-Fc','--lock-wait-timeout=5000'],env=self.pg,stdout=fd,stderr=subprocess.PIPE,timeout=120)
            need(result.returncode==0,'BackupFailed');os.fsync(fd)
        finally:os.close(fd)
        sync(self.attempt);self.command(['/usr/bin/pg_restore','--list',str(path)],30)
        raw=private(path,256*1024**2);need(raw.startswith(b'PGDMP'),'BackupFormat')
        result={'path':str(path),'sha256':sha(raw),'bytes':len(raw),'toc_verified':True,'restore_tested':False};self.save('backup.json',result);self.unchanged();return result
    def create(self,payload):
        self.assert_binding()
        need(payload==policy.provider_payload(self.pilot,self.proof,self.environment['SSO_LDAP_BIND_PASSWORD'],now_ms=int(time.time()*1000)),'ProviderPayloadMismatch')
        status,headers,_=self.http('POST',COMPONENTS,payload=payload);need(status==201,'ProviderCreateStatus')
        location=urllib.parse.urlsplit(headers.get('Location',headers.get('location','')))
        need(location.path.startswith(COMPONENTS+'/') and not location.query and not location.fragment and
            (location.netloc,location.scheme) in (('',''),('127.0.0.1:8088','http'),('sso.sosnadmin.local','https')),'ProviderLocation')
        self.provider_id=opaque(location.path[len(COMPONENTS)+1:]);self.owned_ids.add(self.provider_id);return self.provider_id
    def read(self,pid):
        need(pid==self.provider_id,'OwnedProviderRequired');value=self.get(COMPONENTS+'/'+pid)
        need(value.get('id')==pid,'ProviderReadIdentity');return value
    def mappers(self,pid):
        need(pid==self.provider_id,'OwnedProviderRequired');rows=self.get(COMPONENTS+'?parent='+pid+'&type='+MAPPERS)
        need(type(rows) is list and len(rows)<=12 and all(v.get('parentId')==pid for v in rows),'OwnedMapperShape')
        self.owned_ids.update(opaque(value['id']) for value in rows);return rows
    def update_mapper(self,mid,payload):
        self.assert_binding()
        need(mid in self.owned_ids and mid!=self.provider_id and payload.get('parentId')==self.provider_id,'OwnedMapperRequired')
        self.http('PUT',COMPONENTS+'/'+mid,payload=payload)
    def update(self,pid,payload):
        self.assert_binding()
        need(pid==self.provider_id and payload==self.desired,'EnablePayloadMismatch');self.http('PUT',COMPONENTS+'/'+pid,payload=payload)
    def unchanged(self):
        self.assert_binding()
        need(sha(self.conf.read_bytes())==self.config_sha and self.command(['/usr/bin/systemctl','show','keycloak.service','--property=MainPID','--value']).strip()==self.pid,'RuntimeConfigDrift')
        need(self.snapshot()==self.before,'ExistingIdentityOrAuthorizationDrift')
    def disable_owned(self,pid,payload):
        need(pid==self.provider_id and pid in self.owned_ids,'OwnedDisableBinding');self.cleanup_until=time.monotonic()+45
        self.bindings.recovery=True;self.assert_binding()
        actual=self.http('GET',COMPONENTS+'/'+pid,recovery=True)[2]
        need(actual.get('id')==pid and actual.get('name')==policy.PROVIDER_NAME and actual.get('parentId')==payload['parentId'] and actual.get('providerId')=='ldap','OwnedDisableBinding')
        self.http('PUT',COMPONENTS+'/'+pid,recovery=True,payload={'providerId':'ldap','providerType':TYPE,'config':{'enabled':['false']}})
        value=self.http('GET',COMPONENTS+'/'+pid,recovery=True)[2]
        need(value.get('id')==pid and value['config'].get('enabled')==['false'],'OwnedDisableUncertain');self.save('disabled-after-hold.json',{'owned_provider_disabled':True})

def run(request):
    import fcntl
    s=ROOT.lstat();need(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o700,'PrivateRootRequired')
    fd=os.open(ROOT/'release.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    ops=None;global_fd=None
    try:
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        path=P('/run/keycloak-identity-recovery.lock');s=path.lstat();need(stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600,'CanonicalLock')
        global_fd=os.open(path,os.O_RDWR|os.O_NOFOLLOW);need(identity(os.fstat(global_fd))==identity(s),'CanonicalLockChanged');fcntl.flock(global_fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        ops=Native(request);ops.login()
        # Retain one fresh preflight; policy invokes this wrapper, not a second
        # import-triggering user lookup or a second authentication operation.
        ops.pilot,old_mappers=ops.preflight(ops.proof)
        ops.desired=policy.provider_payload(ops.pilot,ops.proof,ops.environment['SSO_LDAP_BIND_PASSWORD'],now_ms=int(time.time()*1000));ops.desired['config']['enabled']=['true']
        ops.preflight=lambda proof:(ops.pilot,old_mappers)
        result=policy.enable_exact_user(ops,ops.proof,ops.environment['SSO_LDAP_BIND_PASSWORD'],now_ms=int(time.time()*1000),apply=ops.phase=='apply')
        if ops.phase=='plan':result.update(profile_sha256=ops.profile_sha);ops.save('result.json',result)
        result['request_count']=ops.requests;return result
    finally:
        try:
            if ops is not None:
                try:ops.logout();ops.save('logout.json',{'verified':True})
                finally:ops.bindings.close_io()
        finally:
            if global_fd is not None:os.close(global_fd)
            os.close(fd)

if __name__=='__main__':
    if sys.argv[1:]!=['--run']:print(json.dumps({'status':'PlanOnly','runtime_actions':False}))
    else:
        try:print(json.dumps(run(json.load(sys.stdin))))
        except Exception as error:
            import traceback
            print(json.dumps({'status':'Hold','error_type':type(error).__name__,'error_code':str(error) if isinstance(error,policy.Refused) else None,
                'frames':[{'function':f.name,'line':f.lineno} for f in traceback.extract_tb(error.__traceback__)]}))
