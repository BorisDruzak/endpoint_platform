"""Versioned actual-message consent; the strict v1 human parser stays unchanged."""
from datetime import datetime, timedelta, timezone

from .codec import canonical, digest, hex256, instant, parse_json, require, sha256, uuid
from .recovery_permission import _latest_actual_message

REQUEST = ('Доработай recovery protocol, чтобы он принимал моё явное разрешение без копирования JSON. '
           'Проведи независимое ревью, подготовь свежий gate и выполниу seq 04. '
           'Исторические claims и доказательства сохрани, и дальше продолжай по плану.')
QUESTION = ('Под «дальше продолжай по плану» вы разрешаете выполнение шагов после seq 04? '
            'Ранее действовал STOP перед seq 05; пока уточняю это, продолжу доработку протокола '
            'и подготовку одной попытки seq 04.')
MODE = 'actual-natural-consent-v2.1'
ADMISSION_SECONDS = 1800
CONSENT_SECONDS = 21600


def _direct_request(text):
    # The app's ambient wrapper is evidence, never an authorization source.
    # Only the separately delimited human request after it is recognized.
    text = text[:-2] if text.endswith('\r\n') else text[:-1] if text.endswith('\n') else text
    if text.startswith('\n<in-app-browser-context '): text = text[1:]
    marker = '</in-app-browser-context>\n\n## My request:\n'
    if text.startswith('<in-app-browser-context source="ambient-ui-state">'):
        if text.count(marker) != 1: return None
        text = text.split(marker, 1)[1]
    return text


def _clarification(text):
    start, end = '<send_user_message_question_reply>', '</send_user_message_question_reply>'
    text = text[:-2] if text.endswith('\r\n') else text[:-1] if text.endswith('\n') else text
    require(text.startswith(start) and text.endswith(end), 'later human instruction blocks consent')
    rows = parse_json(b'{"replies":'+text[len(start):-len(end)].encode('utf-8')+b'}')['replies']
    require(type(rows) is list and len(rows) == 1 and type(rows[0]) is dict
            and set(rows[0]) == {'questionItemId', 'question', 'answer'}
            and type(rows[0]['questionItemId']) is str and rows[0]['question'] == QUESTION
            and rows[0]['answer'] in ('Продолжить остальные шаги исходного плана', 'Остановиться после seq 04'),
            'exact supported human scope clarification required')
    return rows[0]['answer'] == 'Продолжить остальные шаги исходного плана'


def capture_consent():
    thread, path, _ = _latest_actual_message()
    raw = path.read_bytes()
    require(len(raw) < 64*1024*1024, 'actual consent session bound')
    frames = raw.splitlines()
    require(frames and parse_json(frames[0])['payload']['id'] == thread, 'actual consent thread identity')
    actual = []
    for index, line in enumerate(frames):
        try:
            frame = parse_json(line)
        except ValueError:
            require(index == len(frames)-1 and not raw.endswith(b'\n'), 'corrupt complete app frame')
            continue
        payload = frame.get('payload', {})
        if frame.get('type') == 'response_item' and payload.get('type') == 'message' and payload.get('role') == 'user':
            content = payload.get('content', [])
            require(type(content) is list, 'actual user content shape')
            text = ''.join(r.get('text', '') for r in content if r.get('type') == 'input_text')
            actual.append((index, line, frame, text))
    candidates = [i for i, row in enumerate(actual) if _direct_request(row[3]) in (REQUEST, REQUEST.replace('выполниу', 'выполни'))]
    require(candidates, 'explicit direct natural recovery consent required')
    selected = candidates[-1]
    index, line, frame, text = actual[selected]
    created = instant(frame['timestamp'])
    now = datetime.now(timezone.utc)
    require(created <= now < created+timedelta(seconds=CONSENT_SECONDS), 'actual natural consent expired or future dated')
    suffix = []
    continuation = True
    for next_index, next_line, next_frame, next_text in actual[selected+1:]:
        followup = _direct_request(next_text)
        # Exact continuation preserves the previously granted scope and clock.
        # The app's null Page event is context only, never a permission source.
        if followup not in ('продолжай', 'Продолжай',
                '<external_codex_apps_open_page>{"page_id":null}</external_codex_apps_open_page>'):
            continuation = _clarification(next_text)
        require(created <= instant(next_frame['timestamp']) <= now, 'scope clarification chronology')
        suffix.append(dict(frame_index=next_index, record_sha256=sha256(next_line), record=next_frame))
    return dict(schema='task13_actual_natural_consent_v2', scope='one-seq04-additive-recovery-v2',
                thread_id=thread, source=str(path), frame_index=index, record_sha256=sha256(line),
                record=frame, suffix=suffix, continuation_requested=continuation)


def bind_permission(consent, gate):
    require(consent == capture_consent(), 'actual natural consent changed or replayed')
    require(gate.get('schema') == 'task13_additive_recovery_gate_v1'
            and gate.get('status') == 'READY_REQUIRES_SEPARATE_AUTHORIZATION'
            and type(gate.get('protocol_version')) is int and gate['protocol_version'] == 2
            and gate.get('authorization_mode') == MODE and gate.get('consent_sha256') == digest(consent)
            and type(gate.get('admission_validity_seconds')) is int and gate['admission_validity_seconds']==ADMISSION_SECONDS
            and type(gate.get('consent_validity_seconds')) is int and gate['consent_validity_seconds']==CONSENT_SECONDS
            and type(gate.get('allowed_seq')) is int and gate['allowed_seq'] == 4
            and gate.get('seq04_authorized') is False, 'reviewed natural recovery gate required')
    checked = instant(gate['checked_utc']); created = instant(consent['record']['timestamp'])
    end = min(checked+timedelta(seconds=ADMISSION_SECONDS), created+timedelta(seconds=CONSENT_SECONDS))
    require(created <= checked <= datetime.now(timezone.utc) < end, 'natural recovery gate expired or unbounded')
    for key in ('protocol_source_sha256', 'original_binding_sha256', 'consent_sha256'): hex256(gate[key])
    uuid(gate['continuation_id'])
    revision = gate['implementation_sha']
    require(type(revision) is str and len(revision) == 40 and all(c in '0123456789abcdef' for c in revision),
            'exact natural recovery implementation revision')
    return dict(schema='task13_actual_recovery_execution_request_v2', scope='seq04-additive-recovery-v2',
                allowed_seq=4, continuation_id=gate['continuation_id'], expires_utc=end.isoformat(),
                gate_sha256=digest(gate), implementation_sha=revision,
                protocol_source_sha256=gate['protocol_source_sha256'], consent=consent)


def verify_bound_permission(expected, gate):
    require(expected.get('schema') == 'task13_actual_recovery_execution_request_v2'
            and expected.get('scope') == 'seq04-additive-recovery-v2', 'versioned natural execution authorization required')
    require(expected == bind_permission(expected['consent'], gate), 'natural gate/source/request binding changed or replayed')


def capture_recovery_permission(gate):
    from .recovery_gate import _root
    from .storage import ProtectedStore
    consent = parse_json(ProtectedStore(_root(gate)).read('human-consent.json'))
    return bind_permission(consent, gate)


def verify_recovery_permission(expected, gate):
    if expected.get('schema') == 'task13_actual_recovery_execution_request_v1':
        from .recovery_permission import verify_recovery_permission as strict_v1
        return strict_v1(expected, gate)
    verify_bound_permission(expected, gate)
