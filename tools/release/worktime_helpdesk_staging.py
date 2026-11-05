"""Fixed .118 WorkTime server release, following PRODUCTION_RUNBOOK sections1/4/7.

Linux root only. Input on stdin: mode prepare|activate, archive path, SHA256,
full commit and expiry UTC epoch. No credentials are accepted or printed.
The caller installs this reviewed script and archive in a private root capsule.
"""
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import socket
import stat
import subprocess
import sys
import tarfile
import time
import fcntl

BASE = Path('/opt/endpoint-staging')
OLD = BASE / 'releases/endpoint-platform-1b6ce5a83dd1'
ENV = Path('/etc/endpoint-staging/endpoint-platform.env')
UNITS = ['endpoint-staging.service', 'endpoint-staging-worker.service']


def need(ok):
    if not ok: raise RuntimeError('Staging release guard failed')


def command(args, *, data=None, timeout=60, stdout=subprocess.PIPE):
    result = subprocess.run(args, input=data, stdout=stdout, stderr=subprocess.PIPE, timeout=timeout)
    need(result.returncode == 0)
    return result.stdout


def sql(query):
    return command(['runuser','-u','postgres','--','psql','-XAt','-v','ON_ERROR_STOP=1','-d','endpoint_staging_db'],data=query.encode()).decode().strip()


def revision(): return sql('SELECT version_num FROM alembic_version;')


def seal():
    tables = sql("SELECT tablename FROM pg_tables WHERE schemaname='public' AND (tablename LIKE 'worktime_%' OR tablename IN ('confirmed_identities','scoped_role_grants','admin_users')) ORDER BY tablename;").splitlines()
    tables = [table for table in tables if table != 'worktime_login_flows']
    result = {}
    for table in tables:
        need(re.fullmatch('[a-z_]+',table))
        result[table] = sql("SELECT count(*)::text || ':' || md5(COALESCE(string_agg(row::text,',' ORDER BY row::text),'')) FROM (SELECT to_jsonb(t)-'authority_kind' AS row FROM "+table+' t) s;')
    return result


def quiescent():
    for table, states in [('commands',"'delivered','acknowledged','running'"),('command_deliveries',"'delivered','acknowledged','running'"),('endpoint_operations',"'delivered','acknowledged','running'"),('endpoint_operation_steps',"'delivered','acknowledged','running'"),('context_collections',"'delivered','collecting','result_received','validated'"),('update_targets',"'requested','scheduled'")]:
        need(sql('SELECT count(*) FROM '+table+' WHERE status IN ('+states+');') == '0')


def active():
    for unit in UNITS: need(command(['systemctl','is-active',unit]).strip() == b'active')


def healthy(base):
    deadline=time.monotonic()+40
    while time.monotonic()<deadline:
        result=subprocess.run(['curl','--fail','--silent','--show-error','--connect-timeout','2','--max-time','3','http://127.0.0.1:18000/healthz'],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=4)
        if result.returncode==0:
            for unit in UNITS:
                pid=command(['systemctl','show',unit,'-p','MainPID','--value']).decode().strip()
                need(pid.isdecimal() and int(pid)>0 and Path('/proc/'+pid+'/cwd').resolve()==base)
            return
        time.sleep(1)
    raise RuntimeError('Staging readiness failed')


def private(path):
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600)
    return path.read_bytes()


def validate_migrate_unit(raw):
    migrate=dict(line.split('=',1) for line in raw.splitlines())
    need(set(migrate)=={'ExecStart','EnvironmentFiles','WorkingDirectory'})
    need(migrate['WorkingDirectory']=='/opt/endpoint-staging/current' and migrate['EnvironmentFiles']==str(ENV)+' (ignore_errors=no)')
    executable='/opt/endpoint-staging/current/venv/bin/python'
    need(re.fullmatch(r'\{ path='+re.escape(executable)+r' ; argv\[\]='+re.escape(executable+' -m alembic upgrade head')+r' ; ignore_errors=no ; start_time=[^{};]* ; stop_time=[^{};]* ; pid=\d+ ; code=[^{};]* ; status=[^{};]* \}',migrate['ExecStart']) is not None)


def save(path, value):
    with path.open('xb') as stream:
        os.chmod(path,0o600);stream.write(json.dumps(value,sort_keys=True).encode());stream.flush();os.fsync(stream.fileno())


def child(base, code):
    return command(['systemd-run','--quiet','--wait','--collect','--pipe','--property=User=endpoint-staging','--property=Group=endpoint-staging',
        '--property=EnvironmentFile='+str(ENV),'--property=NoNewPrivileges=yes','--property=RuntimeMaxSec=60','--setenv=PYTHONDONTWRITEBYTECODE=1',
        '--working-directory='+str(base),str(base/'venv/bin/python'),'-I','-B','-c','import sys;sys.path.insert(0,'+repr(str(base))+')\n'+code],timeout=75)


def candidate(base):
    child(base,"from endpoint_server.config import Settings\nfrom urllib.parse import urlsplit\ns=Settings.from_environment()\nu=urlsplit(s.database_url)\nassert u.hostname in ('127.0.0.1','localhost') and u.path=='/endpoint_staging_db' and u.username=='endpoint_staging' and u.port in (None,5432)\nassert s.public_base_url=='https://endpoint-staging.sosnadmin.local' and s.worktime_enabled and s.oidc.enabled\nassert not s.endpoint_module_execution_enabled\nfrom endpoint_server.main import create_app\ncreate_app(s)")
    command([str(base/'venv/bin/python'),'-I','-B','-m','pip','check'])


def tree(base, inventory):
    actual = set()
    for path in base.rglob('*'):
        relative = path.relative_to(base).as_posix()
        if relative == 'venv' or relative.startswith('venv/'): continue
        need(not path.is_symlink()); actual.add(relative)
        need(relative in inventory)
        mode, digest = inventory[relative]
        need(stat.S_IMODE(path.stat().st_mode) == mode)
        if digest is not None: need(path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() == digest)
        else: need(path.is_dir())
    need(actual == set(inventory))


def main(p):
    need(os.geteuid()==0 and socket.gethostname()=='test-helpdesk')
    need('192.168.101.118' in command(['hostname','-I']).decode().split())
    need(set(p)=={'mode','archive','sha256','commit','expires'} and p['mode'] in {'prepare','activate'})
    need(type(p['expires']) is int and time.time()<p['expires']<time.time()+900)
    need(re.fullmatch('[a-f0-9]{40}',p['commit']) and re.fullmatch('[a-f0-9]{64}',p['sha256']))
    archive=Path(p['archive']);root=archive.parent
    need(root.parent==Path('/root') and root.name.startswith('worktime-helpdesk-20261105-') and root.is_dir() and stat.S_IMODE(root.stat().st_mode)==0o700)
    need(Path(__file__).resolve()==root/'release.py')
    private(root/'release.py'); raw=private(archive);need(hashlib.sha256(raw).hexdigest()==p['sha256'])
    lock=os.open(root/'release.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600);fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    need((BASE/'current').resolve()==OLD and os.readlink(BASE/'current')==str(OLD))
    validate_migrate_unit(command(['systemctl','show','endpoint-staging-migrate.service','-p','ExecStart','-p','EnvironmentFiles','-p','WorkingDirectory']).decode())
    need(revision()=='0043_worktime_recorded');active();quiescent()
    need(shutil.disk_usage(BASE).free>=10*1024**3)
    name='endpoint-platform-'+p['commit'][:12];new=BASE/'releases'/name;inventory={}
    with tarfile.open(archive,'r:gz') as source:
        for member in source:
            parts=Path(member.name).parts
            need(parts and parts[0]==name and '..' not in parts and not member.name.startswith('/') and (member.isfile() or member.isdir()))
            need(member.uid==0 and member.gid==0 and member.mode==(0o644 if member.isfile() else 0o755))
            relative='/'.join(parts[1:])
            if relative: need(relative not in inventory);inventory[relative]=(member.mode,hashlib.sha256(source.extractfile(member).read()).hexdigest() if member.isfile() else None)
    need('webapp/dist/index.html' in inventory and 'endpoint_server/auth/worktime_handoff.py' in inventory)
    controls=hashlib.sha256(private(ENV)).hexdigest()
    if p['mode']=='prepare':
        need(not new.exists() and not (root/'prepared.json').exists());before=seal()
        unpack=root/'unpack';unpack.mkdir(mode=0o700)
        command(['tar','-xzf',str(archive),'--no-same-owner','--no-same-permissions','-C',str(unpack)])
        tree(unpack/name,inventory);os.rename(unpack/name,new);tree(new,inventory)
        command(['/usr/bin/python3.12','-I','-B','-m','venv',str(new/'venv')])
        frozen=command([str(OLD/'venv/bin/python'),'-I','-B','-m','pip','freeze','--all'])
        constraints=root/'constraints.txt';constraints.write_bytes(frozen);constraints.chmod(0o600)
        command([str(new/'venv/bin/python'),'-I','-B','-m','pip','install','--no-deps','--only-binary=:all:','--no-input','--disable-pip-version-check','--no-cache-dir','-r',str(constraints)],timeout=300)
        need(command([str(new/'venv/bin/python'),'-I','-B','-m','pip','freeze','--all'])==frozen)
        tree(new,inventory);candidate(new);need(seal()==before and hashlib.sha256(private(ENV)).hexdigest()==controls);active()
        save(root/'prepared.json',{'commit':p['commit'],'archive_sha256':p['sha256'],'controls':controls,'business':before})
        return {'status':'Prepared','commit':p['commit']}
    prepared=json.loads(private(root/'prepared.json'))
    need(prepared['commit']==p['commit'] and prepared['archive_sha256']==p['sha256'] and prepared['controls']==controls and prepared['business']==seal())
    tree(new,inventory);candidate(new);need(not (root/'activation.json').exists())
    save(root/'activation.json',{'previous':str(OLD),'candidate':str(new),'revision':revision()})
    switched=False
    try:
        command(['systemctl','stop',UNITS[1],UNITS[0]]);quiescent();before=seal();need(before==prepared['business'])
        backup=Path('/var/backups')/root.name;backup.mkdir(mode=0o700);pg=pwd.getpwnam('postgres');os.chown(backup,pg.pw_uid,pg.pw_gid)
        dump=backup/'pre-release.dump'
        command(['runuser','-u','postgres','--','pg_dump','-Fc','-d','endpoint_staging_db','-f',str(dump)],timeout=180)
        command(['runuser','-u','postgres','--','pg_restore','-l',str(dump)])
        save(root/'backup.json',{'path':str(dump),'sha256':hashlib.sha256(dump.read_bytes()).hexdigest(),'revision':revision()})
        temp=BASE/('.current-'+p['commit'][:12]);need(not temp.exists());temp.symlink_to(new);os.replace(temp,BASE/'current');switched=True
        command(['systemctl','start','endpoint-staging-migrate.service'],timeout=120)
        need(revision()=='0044_worktime_helpdesk' and seal()==before)
        command(['systemctl','start',UNITS[0],UNITS[1]]);active()
        healthy(new)
        need(hashlib.sha256(private(ENV)).hexdigest()==controls)
        result={'status':'Accepted','commit':p['commit'],'revision':revision(),'business_preserved':seal()==before,'selector':str(new)}
        need(result['business_preserved']);save(root/'accepted.json',result);return result
    except Exception:
        # Additive migration stays applied; no downgrade or business replay.
        if switched:
            command(['systemctl','stop',UNITS[1],UNITS[0]])
            temp=BASE/('.rollback-'+p['commit'][:12]);need(not temp.exists());temp.symlink_to(OLD);os.replace(temp,BASE/'current')
        command(['systemctl','start',UNITS[0],UNITS[1]])
        healthy(OLD)
        raise


if __name__=='__main__' and sys.argv[1:]==['--run']:
    try: print(json.dumps(main(json.load(sys.stdin))))
    except Exception as error:
        import traceback
        print(json.dumps({'status':'Failed','error_type':type(error).__name__,'frames':[{'function':frame.name,'line':frame.lineno} for frame in traceback.extract_tb(error.__traceback__)]}))
        sys.exit(1)
