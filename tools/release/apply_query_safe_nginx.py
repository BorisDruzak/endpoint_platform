#!/usr/bin/env python3
"""Reviewed config-only repair for the two existing .19 application sites.

Default is a syntax-validated plan. No application, DB, TLS, or env changes.
"""
import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import uuid

PROFILES = {
    'helpdesk': ('helpdesk.sosnadmin.local','helpdesk_path_only'),
    'endpoint-platform': ('endpoint.sosnadmin.local','endpoint_platform_path_only'),
}
SAFE_FIELDS = {'$time_iso8601','$remote_addr','$request_method','$uri','$status','$body_bytes_sent','$request_time'}


class ConfigurationError(ValueError):
    pass


def run(command):
    # Never echo config diagnostics or process output into evidence/logs.
    result = subprocess.run(command,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
    if result.returncode:
        raise ConfigurationError(f'Command failed: {command[0]}')


def physical(path, *, directory=False):
    path=Path(path)
    for current in (path,*path.parents):
        details=current.lstat()
        if stat.S_ISLNK(details.st_mode) or details.st_uid!=0 or details.st_mode & 0o022:
            raise ConfigurationError('Expected root-owned physical non-writable config path')
    if directory != path.is_dir() or (not directory and not path.is_file()):
        raise ConfigurationError('Unexpected config path type')


def validate_asset(payload, site):
    host,format_name=PROFILES[site]
    text=payload.decode('utf-8')
    body=re.search(r'log_format '+format_name+r' escape=json\s+(.*?);',text,re.S)
    if body is None or set(re.findall(r'\$\w+',body.group(1)))!=SAFE_FIELDS:
        raise ConfigurationError('Expected reviewed path-only access format')
    if (text.count('server_name '+host+';')!=2
        or text.count(f'access_log /var/log/nginx/{site}.access.log {format_name};')!=2):
        raise ConfigurationError('Expected explicit safe access logs on both site servers')
    callbacks=('/api/web/session/oidc/callback',) if site=='helpdesk' else ('/auth/admin/callback','/auth/employee/callback')
    for callback in callbacks:
        location=re.search(r'location = '+re.escape(callback)+r'\s*\{(.*?)\}',text,re.S)
        if location is None or 'error_log /dev/null crit;' not in location.group(1):
            raise ConfigurationError('Expected exact callback error-log protection')


def non_logging_lines(payload,site):
    """Recognize only this repair's logging additions; retain every other line.

    A newly protected exact callback must copy the existing generic proxy body.
    Custom callback access/proxy behavior is not a logging-only repair.
    """
    text=payload.decode('utf-8')
    format_name=PROFILES[site][1]
    def lines(value):
        return [line.strip() for line in value.splitlines() if line.strip() and not line.strip().startswith('#')]
    generic=re.search(r'location\s+/\s*\{([^{}]*)\}',text,re.S)
    if generic is None:
        raise ConfigurationError('Expected existing generic application proxy')
    callbacks=('/api/web/session/oidc/callback',) if site=='helpdesk' else ('/auth/admin/callback','/auth/employee/callback')
    for callback in callbacks:
        pattern=r'location\s*=\s*'+re.escape(callback)+r'\s*\{([^{}]*)\}'
        def remove(match):
            body=re.sub(r'error_log\s+/dev/null\s+crit;','',match.group(1))
            if lines(body)!=lines(generic.group(1)):
                raise ConfigurationError('Unexpected callback behavior; explicit review required')
            return ''
        text=re.sub(pattern,remove,text,flags=re.S)
    text=re.sub(r'log_format\s+'+re.escape(format_name)+r'\s+escape=json\s+.*?;','',text,flags=re.S)
    text=re.sub(r'(?m)^[ \t]*access_log[ \t]+/var/log/nginx/'+re.escape(site)+
        r'\.access\.log[ \t]+'+re.escape(format_name)+r';[ \t]*$','',text)
    return lines(text)


def atomic_write(path,payload,mode=0o644):
    temporary=path.with_name('.'+path.name+'.'+uuid.uuid4().hex)
    try:
        descriptor=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL,mode)
        with os.fdopen(descriptor,'wb') as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary,mode)
        os.replace(temporary,path)
        if os.name=='posix':
            directory=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def apply_site(source,expected_sha256,site,*,apply=False,nginx_root=Path('/etc/nginx'),
               backup_root=Path('/var/backups'),execute=run,check=physical):
    if site not in PROFILES or not re.fullmatch('[0-9a-f]{64}',expected_sha256):
        raise ConfigurationError('Exact site and reviewed asset SHA256 required')
    source=Path(source)
    if source.is_symlink() or not source.is_file():
        raise ConfigurationError('Expected physical source asset')
    payload=source.read_bytes()
    if hashlib.sha256(payload).hexdigest()!=expected_sha256:
        raise ConfigurationError('Reviewed source checksum mismatch')
    validate_asset(payload,site)
    target=nginx_root/'sites-available'/site
    enabled=nginx_root/'sites-enabled'/site
    check(target)
    check(nginx_root/'sites-enabled',directory=True)
    check(nginx_root/'nginx.conf')
    if not enabled.is_symlink() or enabled.resolve(strict=True)!=target:
        raise ConfigurationError('Existing enabled site must point to its exact physical target')
    before=target.read_bytes()
    old_sha=hashlib.sha256(before).hexdigest()
    if non_logging_lines(before,site)!=non_logging_lines(payload,site):
        raise ConfigurationError('Non-logging site configuration differs; explicit review required')
    execute(['nginx','-t'])
    if before==payload:
        return {'status':'Unchanged','site':site,'sha256':expected_sha256,'non_logging_directives_unchanged':True}
    candidate=target.with_name('.'+site+'.candidate-'+uuid.uuid4().hex)
    staged=nginx_root/('.query-safe-'+site+'-'+uuid.uuid4().hex+'.conf')
    try:
        # Validate the candidate with all other active sites, without replacing
        # any live include or enabling a second copy of the same server block.
        main=(nginx_root/'nginx.conf').read_text(encoding='utf-8')
        include=r'(?m)^[ \t]*include[ \t]+'+re.escape(str(nginx_root/'sites-enabled'))+r'/\*;[ \t]*$'
        if len(re.findall(include,main))!=1:
            raise ConfigurationError('Unsupported nginx include topology; explicit review required')
        other=sorted(p for p in enabled.parent.iterdir() if p!=enabled)
        for path in other:
            # Include paths enter nginx syntax; no whitespace or directives.
            if not re.fullmatch(r'[A-Za-z0-9_./-]+',str(path)) or not path.is_file():
                raise ConfigurationError('Unexpected enabled include entry')
        replacement='\n'.join(f'    include {p};' for p in [*other,candidate])
        atomic_write(candidate,payload)
        atomic_write(staged,re.sub(include,lambda _:replacement,main).encode())
        execute(['nginx','-t','-c',str(staged)])
        if not apply:
            return {'status':'PlanValidated','site':site,'before_sha256':old_sha,'sha256':expected_sha256,
                'non_logging_directives_unchanged':True}
        # Refuse to overwrite a concurrent administrator's edit after validation.
        check(target)
        if target.read_bytes()!=before:
            raise ConfigurationError('Target changed during validation')
        archive=backup_root/site/'nginx'
        archive.mkdir(parents=True,mode=0o700,exist_ok=True)
        check(archive,directory=True)
        backup=archive/(old_sha+'.conf')
        if backup.exists():
            check(backup)
            if backup.read_bytes()!=before:
                raise ConfigurationError('Backup identity conflict')
        else:
            atomic_write(backup,before,0o600)
        try:
            atomic_write(target,payload)
            execute(['nginx','-t'])
            execute(['systemctl','reload','nginx'])
        except Exception:
            atomic_write(target,before)
            try:
                execute(['nginx','-t'])
                execute(['systemctl','reload','nginx'])
            except Exception:
                raise ConfigurationError('Original config restored; reload requires operator review') from None
            raise ConfigurationError('Apply failed; original config restored and reloaded') from None
        return {'status':'Applied','site':site,'before_sha256':old_sha,'sha256':expected_sha256,
            'non_logging_directives_unchanged':True}
    finally:
        candidate.unlink(missing_ok=True)
        staged.unlink(missing_ok=True)


@contextmanager
def deployment_lock(site):
    import fcntl
    lock=Path('/run/query-safe-nginx.lock')
    physical(lock.parent,directory=True)
    descriptor=os.open(lock,os.O_WRONLY|os.O_CREAT|os.O_NOFOLLOW,0o600)
    with os.fdopen(descriptor,'a') as stream:
        physical(lock)
        fcntl.flock(stream,fcntl.LOCK_EX)
        yield


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--site',choices=tuple(PROFILES),required=True)
    parser.add_argument('--source',type=Path,required=True)
    parser.add_argument('--source-sha256',required=True)
    parser.add_argument('--apply',action='store_true')
    args=parser.parse_args()
    if os.name!='posix' or os.geteuid()!=0:
        parser.error('Run as root on approved .19 host')
    addresses=subprocess.run(['hostname','-I'],capture_output=True,text=True,check=True,timeout=5).stdout.split()
    if '192.168.100.19' not in addresses:
        parser.error('Wrong deployment host')
    run(['systemctl','is-active','--quiet','nginx'])
    try:
        with deployment_lock(args.site):
            print(json.dumps(apply_site(args.source,args.source_sha256,args.site,apply=args.apply),sort_keys=True))
    except (ConfigurationError,OSError,UnicodeError) as error:
        reason=str(error) if isinstance(error,ConfigurationError) else type(error).__name__
        print(json.dumps({'status':'Rejected','site':args.site,'reason':reason}))
        raise SystemExit(1)


if __name__=='__main__':
    main()
