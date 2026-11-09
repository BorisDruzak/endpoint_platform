import hashlib
import importlib.util
from pathlib import Path
import re

import pytest

ROOT=Path(__file__).resolve().parents[2]
SPEC=importlib.util.spec_from_file_location('query_safe_nginx',ROOT/'tools/release/apply_query_safe_nginx.py')
MODULE=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
ASSET=ROOT/'deploy/server/endpoint-platform.nginx.conf'


def test_endpoint_nginx_retains_safe_access_and_limits_error_suppression_to_callbacks():
    text=ASSET.read_text(encoding='utf-8')
    MODULE.validate_asset(ASSET.read_bytes(),'endpoint-platform')
    for callback in ('/auth/admin/callback','/auth/employee/callback'):
        location=re.search(r'location = '+callback+r'\s*\{(.*?)\}',text,re.S).group(1)
        assert 'error_log /dev/null crit;' in location
        assert 'proxy_pass http://127.0.0.1:8000;' in location
        assert 'proxy_set_header X-Forwarded-For $remote_addr;' in location
    assert text.count('error_log /dev/null crit;')==2
    assert text.count('include /etc/nginx/snippets/endpoint-alt-distribution.conf;')==1
    assert 'return 308 https://endpoint.sosnadmin.local$request_uri;' in text


def test_wrong_site_or_sensitive_format_variables_are_rejected():
    with pytest.raises(MODULE.ConfigurationError):
        MODULE.validate_asset(ASSET.read_bytes(),'helpdesk')
    for unsafe in (b'$request',b'$request_uri',b'$args',b'$http_referer'):
        with pytest.raises(MODULE.ConfigurationError):
            MODULE.validate_asset(ASSET.read_bytes().replace(b'$uri',unsafe),'endpoint-platform')


def test_first_install_uses_real_distribution_snippet_before_site_asset():
    runbook=(ROOT/'deploy/server/PRODUCTION_RUNBOOK.md').read_text(encoding='utf-8')
    assert 'deploy/server/endpoint-alt-distribution.nginx.conf endpoint-platform-server:/tmp/' in runbook
    snippet='/tmp/endpoint-alt-distribution.nginx.conf /etc/nginx/snippets/endpoint-alt-distribution.conf'
    site='/tmp/endpoint-platform.nginx.conf /etc/nginx/sites-available/endpoint-platform'
    assert runbook.index(snippet)<runbook.index(site)
    assert 'location /downloads/alt/' in (ROOT/'deploy/server/endpoint-alt-distribution.nginx.conf').read_text()


@pytest.fixture
def installation(tmp_path):
    nginx=tmp_path/'nginx'
    available=nginx/'sites-available'; available.mkdir(parents=True)
    enabled=nginx/'sites-enabled'; enabled.mkdir()
    target=available/'endpoint-platform'
    old_text=ASSET.read_text(encoding='utf-8')
    old_text=re.sub(r'log_format endpoint_platform_path_only escape=json\s+.*?;','',old_text,flags=re.S)
    old_text=re.sub(r'^[ \t]*access_log[^\n]+\n','',old_text,flags=re.M)
    old_text=re.sub(r'location = /auth/(?:admin|employee)/callback\s*\{.*?\}','',old_text,flags=re.S)
    old=old_text.encode()
    target.write_bytes(old)
    try:
        (enabled/'endpoint-platform').symlink_to(target)
    except OSError:
        pytest.skip('Native symlink creation unavailable')
    (nginx/'nginx.conf').write_text('events {}\nhttp {\n include '+str(enabled)+'/*;\n}\n')
    source=tmp_path/'reviewed.conf'; source.write_bytes(ASSET.read_bytes())
    commands=[]
    def execute(command):
        commands.append(command)
        if command[:3]==['nginx','-t','-c']:
            staged=Path(command[3]).read_text()
            assert str(enabled/'endpoint-platform') not in staged
            assert '.candidate-' in staged
    kwargs=dict(nginx_root=nginx,backup_root=tmp_path/'backups',execute=execute,
        check=lambda *_a,**_k:None)
    digest=hashlib.sha256(source.read_bytes()).hexdigest()
    return source,target,old,digest,commands,kwargs


def test_plan_validates_isolated_candidate_and_never_reloads_or_changes_live_site(installation):
    source,target,old,digest,commands,kwargs=installation
    result=MODULE.apply_site(source,digest,'endpoint-platform',**kwargs)
    assert result['status']=='PlanValidated' and target.read_bytes()==old
    assert not any(command[0]=='systemctl' for command in commands)
    assert not list(target.parent.glob('.*candidate-*'))
    assert not list(kwargs['nginx_root'].glob('.query-safe-*'))


def test_apply_backups_exact_old_bytes_and_second_apply_is_idempotent(installation):
    source,target,old,digest,commands,kwargs=installation
    result=MODULE.apply_site(source,digest,'endpoint-platform',apply=True,**kwargs)
    assert result['status']=='Applied' and target.read_bytes()==source.read_bytes()
    backups=list(kwargs['backup_root'].rglob('*.conf'))
    assert len(backups)==1 and backups[0].read_bytes()==old
    assert backups[0].parent==kwargs['backup_root']/'query-safe-nginx'/'endpoint-platform'
    assert commands.count(['systemctl','reload','nginx'])==1
    result=MODULE.apply_site(source,digest,'endpoint-platform',apply=True,**kwargs)
    assert result['status']=='Unchanged'
    assert commands.count(['systemctl','reload','nginx'])==1


def test_failed_reload_restores_old_bytes_and_reloads_original(installation):
    source,target,old,digest,commands,kwargs=installation
    original=kwargs['execute']
    def fail_once(command):
        original(command)
        if command==['systemctl','reload','nginx'] and commands.count(command)==1:
            raise MODULE.ConfigurationError('simulated reload failure')
    kwargs['execute']=fail_once
    with pytest.raises(MODULE.ConfigurationError,match='original config restored and reloaded'):
        MODULE.apply_site(source,digest,'endpoint-platform',apply=True,**kwargs)
    assert target.read_bytes()==old
    assert commands.count(['systemctl','reload','nginx'])==2


def test_nginx_backup_never_enters_existing_database_backup_namespace(installation):
    source,target,old,digest,commands,kwargs=installation
    database=kwargs['backup_root']/'endpoint-platform'
    database.mkdir(parents=True)
    marker=database/'database-owned-marker'
    marker.write_bytes(b'private DB backup fixture')
    def guarded(path,**options):
        if path==database or database in path.parents:
            raise MODULE.ConfigurationError('Existing database backup namespace is not owned by nginx repair')
    kwargs['check']=guarded
    result=MODULE.apply_site(source,digest,'endpoint-platform',apply=True,**kwargs)
    assert result['status']=='Applied'
    assert marker.read_bytes()==b'private DB backup fixture'
    assert list(database.iterdir())==[marker]


def test_plan_checks_nearest_existing_backup_parent_without_creating_directories(installation):
    source,target,old,digest,commands,kwargs=installation
    namespace=kwargs['backup_root']/'query-safe-nginx'
    namespace.mkdir(parents=True)
    checked=[]
    def reject_foreign_parent(path,**options):
        checked.append(path)
        if path==namespace:
            raise MODULE.ConfigurationError('Unexpected backup ownership')
    kwargs['check']=reject_foreign_parent
    with pytest.raises(MODULE.ConfigurationError,match='Unexpected backup ownership'):
        MODULE.apply_site(source,digest,'endpoint-platform',**kwargs)
    assert namespace in checked and not list(namespace.iterdir())
    assert not commands and target.read_bytes()==old


def test_invalid_candidate_never_replaces_or_reloads_live_site(installation):
    source,target,old,digest,commands,kwargs=installation
    original=kwargs['execute']
    def reject_candidate(command):
        original(command)
        if command[:3]==['nginx','-t','-c']:
            raise MODULE.ConfigurationError('simulated candidate syntax failure')
    kwargs['execute']=reject_candidate
    with pytest.raises(MODULE.ConfigurationError,match='candidate syntax failure'):
        MODULE.apply_site(source,digest,'endpoint-platform',apply=True,**kwargs)
    assert target.read_bytes()==old
    assert not any(command[0]=='systemctl' for command in commands)
    assert not list(target.parent.glob('.*candidate-*'))


def test_concurrent_target_edit_is_preserved_and_wrong_source_hash_never_runs_command(installation):
    source,target,old,digest,commands,kwargs=installation
    with pytest.raises(MODULE.ConfigurationError,match='checksum mismatch'):
        MODULE.apply_site(source,'0'*64,'endpoint-platform',apply=True,**kwargs)
    assert not commands
    original=kwargs['execute']
    def edit_during_validation(command):
        original(command)
        if command[:3]==['nginx','-t','-c']:
            target.write_bytes(b'# concurrent administrator edit\n')
    kwargs['execute']=edit_during_validation
    with pytest.raises(MODULE.ConfigurationError,match='Target changed'):
        MODULE.apply_site(source,digest,'endpoint-platform',apply=True,**kwargs)
    assert target.read_bytes()==b'# concurrent administrator edit\n'
    assert not any(command[0]=='systemctl' for command in commands)


@pytest.mark.parametrize('drift',[
    lambda value:value.replace(b'deny all;',b'deny all;\n    include /etc/nginx/snippets/unrelated-live.conf;',1),
    lambda value:value.replace(b'127.0.0.1:8000',b'127.0.0.1:9000'),
])
def test_unexpected_nonlogging_drift_is_preserved_before_any_command(installation,drift):
    source,target,old,digest,commands,kwargs=installation
    changed=drift(old)
    assert changed!=old
    target.write_bytes(changed)
    with pytest.raises(MODULE.ConfigurationError,match='Non-logging site configuration differs'):
        MODULE.apply_site(source,digest,'endpoint-platform',apply=True,**kwargs)
    assert target.read_bytes()==changed and not commands


def test_custom_callback_behavior_cannot_be_silently_replaced(installation):
    source,target,old,digest,commands,kwargs=installation
    target.write_bytes(source.read_bytes().replace(b'error_log /dev/null crit;',
        b'error_log /dev/null crit;\n        proxy_set_header X-Custom-Access required;',1))
    changed=target.read_bytes()
    with pytest.raises(MODULE.ConfigurationError,match='Unexpected callback behavior'):
        MODULE.apply_site(source,digest,'endpoint-platform',apply=True,**kwargs)
    assert target.read_bytes()==changed and not commands
