"""Additive controller dependencies cannot renew old pins or open a path selector."""
import copy
import importlib.util
from pathlib import Path

import pytest

from tools.canary.task13_continuation.codec import digest,sha256

pytestmark = pytest.mark.no_db


def module():
    assert importlib.util.find_spec('tools.canary.task13_continuation.recovery_dependencies_v2') is not None
    from tools.canary.task13_continuation import recovery_dependencies_v2
    return recovery_dependencies_v2


@pytest.fixture
def revision():
    home = Path.home()/'.cache/codex-runtimes/codex-primary-runtime/dependencies/python'
    exe, library, shell = str(home/'python.exe'), str(home/'Lib/json/__init__.py'), r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
    original = {exe:dict(bytes=10,sha256='a'*64),library:dict(bytes=20,sha256='b'*64),shell:dict(bytes=30,sha256='c'*64)}
    runtime = copy.deepcopy(original); runtime[exe] = dict(bytes=874,sha256='d'*64)
    candidate = dict(schema='task13_controller_dependency_revision_v2',baseline_closure_sha256='e'*64,
                     baseline_runtime_sha256=digest(original),runtime=runtime,
                     changed={exe:dict(before=original[exe],after=runtime[exe])},python_version='3.12.14',
                     agent_runtime_changed=False)
    review = dict(schema='task13_controller_dependency_review_v2',status='PASS',candidate_sha256=digest(candidate),
                  changed_count=1,unchanged_count=2,signatures_verified=True,python_version='3.12.14',
                  historical_closure_unchanged=True,agent_runtime_changed=False,
                  signatures={exe:dict(bytes=874,sha256='d'*64,status='VALID',signer='OpenAI OpCo, LLC')})
    return original,candidate,review


def test_exact_reviewed_delta_preserves_original_catalog(revision):
    m = module(); original,candidate,review = revision; before = copy.deepcopy(original)
    m.validate_revision(original,candidate,review,'e'*64)
    assert original == before


@pytest.mark.parametrize('fault',['open_path','missing_path','stdlib_change','shell_change','wrong_baseline',
                                  'wrong_review','unreviewed_pin','agent_change','no_signature','missing_signature','wrong_signer'])
def test_unreviewed_dependency_changes_fail_closed(revision,fault):
    m = module(); original,candidate,review = revision
    changed_exe = next(iter(candidate['changed']))
    if fault == 'open_path': candidate['runtime'][r'C:\other\python.exe'] = candidate['runtime'][changed_exe]
    elif fault == 'missing_path': del candidate['runtime'][changed_exe]
    elif fault in ('stdlib_change','shell_change'):
        name = next(n for n in original if ('Lib' in n if fault=='stdlib_change' else 'powershell.exe' in n))
        candidate['runtime'][name] = dict(bytes=100,sha256='f'*64)
        candidate['changed'][name] = dict(before=original[name],after=candidate['runtime'][name])
    elif fault == 'wrong_baseline': candidate['baseline_runtime_sha256'] = '0'*64
    elif fault == 'wrong_review': review['candidate_sha256'] = '0'*64
    elif fault == 'unreviewed_pin': candidate['runtime'][changed_exe]['sha256'] = 'f'*64
    elif fault == 'agent_change': candidate['agent_runtime_changed'] = True
    elif fault == 'no_signature': review['signatures_verified'] = False
    elif fault == 'missing_signature': review['signatures'] = {}
    else: review['signatures'][changed_exe]['signer'] = 'Untrusted signer'
    if fault not in ('wrong_review','unreviewed_pin'):
        review['candidate_sha256'] = digest(candidate)
        review['changed_count'] = len(candidate['changed'])
        review['unchanged_count'] = len(candidate['runtime'])-len(candidate['changed'])
    with pytest.raises(ValueError): m.validate_revision(original,candidate,review,'e'*64)


def test_unchanged_original_empty_python_source_remains_closed(revision):
    m = module(); original,candidate,review = revision
    empty = str(Path.home()/'.cache/codex-runtimes/codex-primary-runtime/dependencies/python/Lib/__init__.py')
    original[empty] = dict(bytes=0,sha256=sha256(b''))
    candidate['runtime'][empty] = copy.deepcopy(original[empty])
    candidate['baseline_runtime_sha256'] = digest(original)
    review.update(candidate_sha256=digest(candidate),unchanged_count=3)
    m.validate_revision(original,candidate,review,'e'*64)


def test_changed_pe_cannot_be_empty_even_with_matching_review(revision):
    m = module(); original,candidate,review = revision; name = next(iter(candidate['changed']))
    candidate['runtime'][name] = dict(bytes=0,sha256=sha256(b''))
    candidate['changed'][name]['after'] = copy.deepcopy(candidate['runtime'][name])
    review['signatures'][name].update(candidate['runtime'][name])
    review['candidate_sha256'] = digest(candidate)
    with pytest.raises(ValueError): m.validate_revision(original,candidate,review,'e'*64)
