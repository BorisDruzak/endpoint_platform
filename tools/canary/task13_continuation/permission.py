"""Bind the real operator message from this Codex app session, not a caller quote."""
import os
from pathlib import Path

from .codec import canonical, parse_json, require, sha256, uuid

REQUEST = """Task 13 — PID Identity Guard Correction

1. Провести read-only проверку обоих текущих процессов: PID, native creation time, образ, родитель, SessionId и доступные сведения о дескрипторах. Не сохранять секретные аргументы командной строки.
2. Сопоставить каждый экземпляр с исходной проверкой по сохранённым идентификаторам, а не только по числовому PID.
3. Добавить в guard состояния `ORIGINAL_PROCESS_ACTIVE`, `PID_REUSED`, `PROCESS_ABSENT` и `IDENTITY_UNKNOWN`. При `IDENTITY_UNKNOWN` сохранять BLOCKED.
4. Написать RED→GREEN тесты повторного использования PID, отказа в чтении identity, PID reuse при живом SSH-сервисе и гонки завершения/повторного запуска процесса.
5. Независимо проверить, что исправление не ослабляет остальные условия continuation: старый plan/seal, receipts 00–03, baseline, snapshot, новый срок действия и source pins.
6. После PASS провести свежую проверку guard на VM. Seq 04 запускать отдельным шагом, только если весь continuation gate подтверждён.

Для `sshd.exe` никакого вмешательства в службу не требуется."""

READONLY_RECOVERY_REQUEST = 'Разрешаю новый recovery scope. Старую RCA оставь UNKNOWN, добавь диагностику без ослабления guards, проведи независимое ревью и свежий read-only canonical preflight. Seq 04 не запускать, consumed claim не переиспользовать. Без согласований.'


def capture_permission():
    thread = uuid(os.environ.get("CODEX_THREAD_ID"))
    sessions = Path.home()/".codex/sessions"
    paths = list(sessions.glob("*/*/*/rollout-*"+thread+".jsonl"))
    require(len(paths) == 1,"one actual app session required")
    path = paths[0]
    require(not path.is_symlink() and not path.stat().st_file_attributes & 0x400
            and path.stat().st_nlink == 1 and path.stat().st_size < 64*1024*1024,"operator session file identity")
    # The app appends while the controller is running; only complete JSONL frames
    # are examined, and the captured message is rechecked at execution.
    raw = path.read_bytes()
    frames = raw.splitlines()
    require(parse_json(frames[0])["payload"]["id"] == thread,"actual session identity")
    users = []
    for line in frames:
        try:
            frame = parse_json(line)
        except ValueError:
            require(line is frames[-1],"corrupt complete app frame")
            continue
        payload = frame.get("payload",{})
        if frame.get("type") == "response_item" and payload.get("type") == "message" and payload.get("role") == "user":
            text = "".join(row.get("text","") for row in payload.get("content",[]) if row.get("type") == "input_text")
            users.append((line,frame,text))
    require(users and users[-1][2].strip() in (REQUEST,READONLY_RECOVERY_REQUEST),"latest actual operator scope is not this PID identity request")
    line,frame,_ = users[-1]
    scope='readonly-unknown-recovery' if users[-1][2].strip()==READONLY_RECOVERY_REQUEST else 'pid-identity-readonly-guard'
    return {"schema":"task13_actual_operator_request_v1","scope":scope,"thread_id":thread,
            "source":str(path),"record_sha256":sha256(line),"record":frame}


def verify_permission(expected):
    if expected.get('scope')=='seq04-execution':
        require('gate_admission_sha256' in expected,'separate execution requires proven prior gate')
        actual=capture_execution_permission()
    else:actual=capture_permission()
    require(actual == expected,"operator permission changed or caller-supplied quote")


def capture_execution_permission(prefix=None):
    from .gate_admission import capture_gate
    from .codec import digest
    # Same actual human request explicitly conditions the separate seq04 step on
    # a full gate. The original correction bundle retains its read-only scope.
    gate=capture_gate(prefix)
    value=capture_permission()
    require(value['scope']=='pid-identity-readonly-guard','read-only recovery forbids seq04')
    value.update(scope='seq04-execution',gate_admission_sha256=digest(gate))
    return value


def require_seq04_permission(expected):
    require(expected.get('scope')=='seq04-execution','PID identity correction scope requires separate seq04 step')
    verify_permission(expected)
