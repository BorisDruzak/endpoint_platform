import importlib.util
from pathlib import Path, PurePosixPath
import sys
import types

import pytest


def module(monkeypatch):
    # The script is Linux-only; parse/guard tests do not invoke remote commands.
    for name in ('pwd','fcntl'):
        if name not in sys.modules:
            try: __import__(name)
            except ImportError: monkeypatch.setitem(sys.modules,name,types.ModuleType(name))
    source=Path(__file__).resolve().parents[2]/'tools/release/worktime_helpdesk_staging.py'
    spec=importlib.util.spec_from_file_location('staging_release_guard',source)
    result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result)
    result.ENV=PurePosixPath('/etc/endpoint-staging/endpoint-platform.env')
    return result


UNIT='''ExecStart={ path=/opt/endpoint-staging/current/venv/bin/python ; argv[]=/opt/endpoint-staging/current/venv/bin/python -m alembic upgrade head ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }
EnvironmentFiles=/etc/endpoint-staging/endpoint-platform.env (ignore_errors=no)
WorkingDirectory=/opt/endpoint-staging/current
'''


def test_exact_reviewed_migrate_unit(monkeypatch):
    module(monkeypatch).validate_migrate_unit(UNIT)


@pytest.mark.parametrize('wrong',[
    UNIT.replace(' (ignore_errors=no)\n',' (ignore_errors=no) /etc/foreign.env (ignore_errors=no)\n'),
    UNIT.replace('-m alembic upgrade head','-m alembic -x foreign upgrade head'),
    UNIT.replace('WorkingDirectory=/opt/endpoint-staging/current','WorkingDirectory=/opt/endpoint-platform/current'),
    UNIT.replace('status=0/0 }','status=0/0 } { path=/foreign ; argv[]=/foreign ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }'),
])
def test_overrides_foreign_realm_and_extra_argv_fail(monkeypatch,wrong):
    with pytest.raises(RuntimeError):module(monkeypatch).validate_migrate_unit(wrong)
