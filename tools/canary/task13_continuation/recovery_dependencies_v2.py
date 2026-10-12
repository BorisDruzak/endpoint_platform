"""One additive reviewed controller dependency revision; old closure stays sealed."""
import sys
from pathlib import Path

from .codec import digest, hex256, integer, parse_json, require, sha256
from .storage import ProtectedStore
from . import windows

BASELINE_NAME = 'task13-command-transport-review-20261011-c'
BASELINE_SHA = 'f219ff086d1cf1623107bb66a0638ed2ae8d3d45eaf7a57dce1c68e0ba8c5cac'
REVISION_NAME = 'task13-controller-dependency-review-20261012-a'
# Exact independently verified native dependency revision; no caller selector.
CANDIDATE_SHA = '7079f7bdcef7358eba15b1c9957bc811f1b98afb022a8eca0e884cea8e1b3649'
REVIEW_SHA = '366b8d6b71eda04ea49e72e21c3f9eef12cd985396604f6fe4d9ee145eb42e55'
ENTRY = 'controller-runtime-revision.json'
REVIEW_ENTRY = 'controller-runtime-review.json'


def validate_revision(original, candidate, review, baseline_sha):
    require(candidate.get('schema') == 'task13_controller_dependency_revision_v2'
            and candidate['baseline_closure_sha256'] == baseline_sha
            and candidate['baseline_runtime_sha256'] == digest(original)
            and candidate['python_version'] == '3.12.14' and candidate['agent_runtime_changed'] is False,
            'fixed additive controller dependency baseline')
    runtime, changed = candidate['runtime'], candidate['changed']
    require(type(runtime) is dict and set(runtime) == set(original) and type(changed) is dict
            and set(changed) == {n for n in original if original[n] != runtime[n]} and 0 < len(changed) <= 64,
            'exact closed dependency catalog and explicit delta required')
    python = Path.home()/'.cache/codex-runtimes/codex-primary-runtime/dependencies/python'
    for name, spec in runtime.items():
        require(type(spec) is dict and set(spec) <= {'bytes','sha256','hardlink_count'}
                and {'bytes','sha256'} <= set(spec), 'exact dependency spec')
        minimum=0 if name not in changed and original[name]['bytes']==0 else 1
        integer(spec['bytes'],minimum,64*1024*1024); hex256(spec['sha256'])
        require(spec.get('hardlink_count',1) == original[name].get('hardlink_count',1), 'dependency hardlink identity changed')
        if name in changed:
            path = Path(name)
            allowed = (path.parent == python and path.name in ('python.exe','python3.dll','python312.dll')) or (
                path.parent == python/'DLLs' and path.suffix.lower() in ('.dll','.pyd'))
            require(allowed and changed[name] == dict(before=original[name],after=spec),
                    'only exact separately reviewed Python PE delta permitted')
    require(review.get('schema') == 'task13_controller_dependency_review_v2' and review.get('status') == 'PASS'
            and review['candidate_sha256'] == digest(candidate) and review['changed_count'] == len(changed)
            and review['unchanged_count'] == len(runtime)-len(changed) and review['signatures_verified'] is True
            and review['python_version'] == candidate['python_version'] and review['historical_closure_unchanged'] is True
            and review['agent_runtime_changed'] is False, 'independent exact controller dependency review required')
    require(type(review['signatures']) is dict and set(review['signatures'])==set(changed),'complete per-file signature evidence required')
    for name,row in review['signatures'].items():
        require(row['bytes']==runtime[name]['bytes'] and row['sha256']==runtime[name]['sha256']
            and row['status']=='VALID' and row['signer']=='OpenAI OpCo, LLC','exact reviewed signature/file binding')


def _baseline():
    raw = ProtectedStore(Path.home()/'.codex/task-evidence'/BASELINE_NAME).read('closure.json')
    require(sha256(raw) == BASELINE_SHA, 'immutable historical dependency closure changed')
    return parse_json(raw)['runtime']


def verify_closed_revision(entries, runtime):
    require(sha256(entries[ENTRY]) == CANDIDATE_SHA and sha256(entries[REVIEW_ENTRY]) == REVIEW_SHA,
            'independently pinned dependency revision source required')
    candidate, review = parse_json(entries[ENTRY]), parse_json(entries[REVIEW_ENTRY])
    validate_revision(_baseline(), candidate, review, BASELINE_SHA)
    require(runtime == candidate['runtime'], 'execution controller dependency revision changed')


def load_reviewed_runtime():
    store = ProtectedStore(Path.home()/'.codex/task-evidence'/REVISION_NAME)
    entries = {ENTRY:store.read('candidate.json'),REVIEW_ENTRY:store.read('review.json')}
    candidate = parse_json(entries[ENTRY]); runtime = candidate['runtime']
    verify_closed_revision(entries, runtime)
    require(str(Path(sys._base_executable).absolute()) in runtime, 'exact independently reviewed root interpreter')
    from .bundle import runtime_sources
    require(runtime_sources(sys.base_prefix) <= {Path(n) for n in runtime}, 'unclosed controller runtime source')
    for name, spec in runtime.items():
        path = Path(name)
        with windows.retained(path,security=False,expected_links=spec.get('hardlink_count',1)) as handle:
            value = windows.read_handle(handle,path,expected_links=spec.get('hardlink_count',1))
        require(len(value) == spec['bytes'] and sha256(value) == spec['sha256'], 'reviewed controller dependency pin changed')
    return runtime, entries
