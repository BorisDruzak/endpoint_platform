"""Actual app-frame consent, without synthetic execution claims or user JSON."""
import importlib.util
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest

from tools.canary.task13_continuation.codec import canonical, digest, sha256

pytestmark = pytest.mark.no_db
REQUEST = ('Доработай recovery protocol, чтобы он принимал моё явное разрешение без копирования JSON. '
           'Проведи независимое ревью, подготовь свежий gate и выполниу seq 04. '
           'Исторические claims и доказательства сохрани, и дальше продолжай по плану.')
QUESTION = ('Под «дальше продолжай по плану» вы разрешаете выполнение шагов после seq 04? '
            'Ранее действовал STOP перед seq 05; пока уточняю это, продолжу доработку протокола '
            'и подготовку одной попытки seq 04.')


def module():
    assert importlib.util.find_spec('tools.canary.task13_continuation.recovery_permission_v2') is not None
    from tools.canary.task13_continuation import recovery_permission_v2
    return recovery_permission_v2


@pytest.fixture
def app(tmp_path, monkeypatch):
    home = tmp_path / 'app'
    folder = home / '.codex/sessions/2026/10/12'
    folder.mkdir(parents=True)
    thread = str(uuid4())
    path = folder / ('rollout-test-' + thread + '.jsonl')
    monkeypatch.setenv('CODEX_THREAD_ID', thread)
    monkeypatch.setattr(Path, 'home', classmethod(lambda cls: home))
    created = datetime.now(timezone.utc) - timedelta(seconds=2)

    def write(text=REQUEST, suffix=(), role='user'):
        frames = [dict(type='session_meta', payload=dict(id=thread)),
                  dict(timestamp=created.isoformat(), type='response_item',
                       payload=dict(type='message', role=role, content=[dict(type='input_text', text=text)]))]
        for extra in suffix:
            frames.append(dict(timestamp=created.isoformat(), type='response_item',
                               payload=dict(type='message', role='user', content=[dict(type='input_text', text=extra)])))
        path.write_bytes(b'\n'.join(canonical(frame) for frame in frames) + b'\n')
        return frames

    gate = dict(schema='task13_additive_recovery_gate_v1', status='READY_REQUIRES_SEPARATE_AUTHORIZATION',
                protocol_version=2, continuation_id=str(uuid4()), implementation_sha='a'*40,
                protocol_source_sha256='b'*64, checked_utc=datetime.now(timezone.utc).isoformat(),
                allowed_seq=4, seq04_authorized=False, original_binding_sha256='c'*64,
                authorization_mode='actual-natural-consent-v2.1',admission_validity_seconds=1800,
                consent_validity_seconds=21600)
    return path, write, gate


def test_actual_explicit_message_binds_reviewed_gate_without_user_json(app):
    m = module(); path, write, gate = app
    frames = write()
    before = path.read_bytes()
    consent = m.capture_consent()
    gate['consent_sha256'] = digest(consent)
    grant = m.bind_permission(consent, gate)
    assert grant['schema'] == 'task13_actual_recovery_execution_request_v2'
    assert grant['consent']['record'] == frames[1]
    assert grant['consent']['record_sha256'] == sha256(canonical(frames[1]))
    assert grant['gate_sha256'] == digest(gate) and grant['allowed_seq'] == 4
    m.verify_bound_permission(grant, gate)
    assert path.read_bytes() == before


def test_actual_request_ambient_context_and_explicit_scope_reply_are_retained(app):
    m = module(); path, write, gate = app
    reply = '<send_user_message_question_reply>\n' + canonical([dict(
        questionItemId='test', question=QUESTION, answer='Продолжить остальные шаги исходного плана')]).decode() + '\n</send_user_message_question_reply>\n'
    frames = write('<in-app-browser-context source="ambient-ui-state">\nCurrent URL: https://example.invalid\n</in-app-browser-context>\n\n## My request:\n' + REQUEST,
                   suffix=[reply])
    consent = m.capture_consent(); gate['consent_sha256'] = digest(consent)
    grant = m.bind_permission(consent, gate)
    assert consent['record'] == frames[1] and consent['suffix'][0]['record'] == frames[2]
    assert consent['continuation_requested'] is True
    assert grant['allowed_seq'] == 4  # Later plan execution requires its own reviewed path.
    m.verify_bound_permission(grant, gate)


@pytest.mark.parametrize('text', [
    '>' + REQUEST, '```text\n' + REQUEST + '\n```', 'Цитата: ' + REQUEST,
    REQUEST.replace('выполниу', 'не выполняй'), REQUEST.replace('seq 04', 'seq 05'),
    'Доработай recovery protocol, но пока seq 04 не запускай.',
    '<external_page>' + REQUEST + '</external_page>', 'TASK13_RECOVERY_EXECUTE_V1 {}',
])
def test_quotes_wrong_scope_and_implementation_only_do_not_authorize(app, text):
    m = module(); _, write, _ = app; write(text)
    with pytest.raises(ValueError): m.capture_consent()


def test_assistant_text_and_browser_evidence_do_not_authorize(app):
    m = module(); _, write, _ = app; write(REQUEST, role='assistant')
    with pytest.raises(ValueError): m.capture_consent()
    write('<in-app-browser-context source="ambient-ui-state">' + REQUEST + '</in-app-browser-context>')
    with pytest.raises(ValueError): m.capture_consent()


@pytest.mark.parametrize('suffix', ['Стоп, не запускай.', 'Подожди.', 'Что сейчас происходит?',
                                   '<send_user_message_question_reply>[]</send_user_message_question_reply>'])
def test_later_restriction_or_unrecognized_human_message_fails_closed(app, suffix):
    m = module(); _, write, gate = app; write()
    consent = m.capture_consent(); gate['consent_sha256'] = digest(consent)
    grant = m.bind_permission(consent, gate)
    write(suffix=[suffix])
    with pytest.raises(ValueError): m.verify_bound_permission(grant, gate)


@pytest.mark.parametrize('field', ['implementation_sha', 'protocol_source_sha256', 'continuation_id',
                                  'original_binding_sha256', 'consent_sha256', 'protocol_version', 'allowed_seq'])
def test_selected_gate_identity_cannot_be_replaced(app, field):
    m = module(); _, write, gate = app; write()
    consent = m.capture_consent(); gate['consent_sha256'] = digest(consent)
    grant = m.bind_permission(consent, gate)
    changed = dict(gate, **{field: 'wrong'})
    with pytest.raises(ValueError): m.verify_bound_permission(grant, changed)


def test_expired_gate_and_old_consent_fail_before_any_claim(app):
    m = module(); path, write, gate = app; write()
    consent = m.capture_consent(); gate['consent_sha256'] = digest(consent)
    old = dict(gate, checked_utc=(datetime.now(timezone.utc)-timedelta(seconds=1201)).isoformat())
    with pytest.raises(ValueError): m.bind_permission(consent, old)
    consent['record']['timestamp'] = (datetime.now(timezone.utc)-timedelta(hours=7)).isoformat()
    with pytest.raises(ValueError): m.bind_permission(consent, gate)
    assert not (path.parents[3] / 'task-evidence').exists()


def test_raw_history_edit_and_thread_replay_are_rejected(app, monkeypatch):
    m = module(); path, write, gate = app; write()
    consent = m.capture_consent(); gate['consent_sha256'] = digest(consent)
    grant = m.bind_permission(consent, gate)
    path.write_bytes(path.read_bytes().replace(b'"role":"user"', b'"role": "user"'))
    with pytest.raises(ValueError): m.verify_bound_permission(grant, gate)
    write(); monkeypatch.setenv('CODEX_THREAD_ID', str(uuid4()))
    with pytest.raises(ValueError): m.verify_bound_permission(grant, gate)


def test_v2_entry_rejects_v1_control_before_supervisor(app, tmp_path, monkeypatch):
    m = module(); _, write, gate = app; write()
    from tools.canary.task13_continuation import recovery_loader
    from tools.canary.task13_continuation.storage import ProtectedStore
    import sys
    store = ProtectedStore.create_root(tmp_path/'owned-v2-entry')
    consent = m.capture_consent(); gate['consent_sha256'] = digest(consent)
    store.create('control.json', canonical(dict(protocol_version=1, mode='execution')))
    store.create('admission-gate.json', canonical(gate))
    store.create('operator-request.json', canonical(m.bind_permission(consent, gate)))
    called = []
    monkeypatch.setattr(sys, 'argv', [str(store.root/'bootstrap.py'), '--execute-recovery-v2'])
    monkeypatch.setattr(recovery_loader, '_execute_reviewed', lambda root: called.append(root))
    with pytest.raises(ValueError): recovery_loader.bootstrap_entry(store.root)
    assert not called


def test_v2_observation_flag_cannot_select_v1_control(tmp_path, monkeypatch):
    from tools.canary.task13_continuation import recovery_loader
    from tools.canary.task13_continuation.storage import ProtectedStore
    import sys
    store = ProtectedStore.create_root(tmp_path/'owned-observation-entry')
    store.create('control.json', canonical(dict(protocol_version=1, mode='observation')))
    called = []
    monkeypatch.setattr(sys, 'argv', [str(store.root/'bootstrap.py'), '--observe-recovery-v2'])
    monkeypatch.setattr(recovery_loader, 'observe', lambda root: called.append(root))
    with pytest.raises(ValueError): recovery_loader.bootstrap_entry(store.root)
    assert not called


def test_new_readiness_interval_is_1800_seconds_without_changing_live_capsules(app):
    m = module(); _,write,gate = app; write()
    consent=m.capture_consent();gate['consent_sha256']=digest(consent)
    grant=m.bind_permission(consent,gate)
    assert (datetime.fromisoformat(grant['expires_utc'])-datetime.fromisoformat(gate['checked_utc'])).total_seconds()==1800


@pytest.mark.parametrize('fault',['old_mode','missing_policy','wrong_interval','bool_interval','wrong_consent_cap'])
def test_old_or_substituted_admission_policy_cannot_bind(app,fault):
    m=module();_,write,gate=app;write();consent=m.capture_consent();gate['consent_sha256']=digest(consent)
    if fault=='old_mode':gate['authorization_mode']='actual-natural-consent-v2'
    elif fault=='missing_policy':del gate['admission_validity_seconds']
    elif fault=='wrong_interval':gate['admission_validity_seconds']=1801
    elif fault=='bool_interval':gate['admission_validity_seconds']=True
    else:gate['consent_validity_seconds']=21601
    with pytest.raises(ValueError):m.bind_permission(consent,gate)


def test_current_task_intent_over_two_hours_is_bounded_and_clamped(app):
    m=module();path,write,gate=app;frames=write()
    created=datetime.now(timezone.utc)-timedelta(hours=5,minutes=50)
    frames[1]['timestamp']=created.isoformat()
    path.write_bytes(b'\n'.join(canonical(f) for f in frames)+b'\n')
    consent=m.capture_consent();gate['consent_sha256']=digest(consent)
    grant=m.bind_permission(consent,gate)
    assert datetime.fromisoformat(grant['expires_utc'])==created+timedelta(hours=6)
    frames[1]['timestamp']=(created-timedelta(minutes=11)).isoformat()
    path.write_bytes(b'\n'.join(canonical(f) for f in frames)+b'\n')
    with pytest.raises(ValueError):m.capture_consent()
