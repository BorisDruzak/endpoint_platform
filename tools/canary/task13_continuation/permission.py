"""Bind the real operator message from this Codex app session, not a caller quote."""
import os
from pathlib import Path

from .codec import canonical, parse_json, require, sha256, uuid

REQUEST = "Разработай процедуру повторного запуска после UNKNOWN и выясни причину present=true без ослабления guards. После независимого PASS разрешаю повтор: только seq 04, затем остановка на resume gate. Без дополнительных согласований."


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
    require(users and users[-1][2].strip() == REQUEST,"latest actual operator scope is not this seq04 request")
    line,frame,_ = users[-1]
    return {"schema":"task13_actual_operator_request_v1","thread_id":thread,
            "source":str(path),"record_sha256":sha256(line),"record":frame}


def verify_permission(expected):
    require(capture_permission() == expected,"operator permission changed or caller-supplied quote")
