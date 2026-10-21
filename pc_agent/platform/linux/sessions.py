"""Bounded logind session metadata shared by Context and local sensor auth."""
from __future__ import annotations

from dataclasses import dataclass
import re

from pc_agent.context_profiles.probe import _execute_bounded_command

_LIMIT = 32768
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_PROPERTIES = "Id,User,Name,Type,Class,Remote,Active,State,LockedHint"


@dataclass(frozen=True, slots=True)
class LinuxSession:
    session_id: str
    uid: int
    user_login: str
    session_type: str
    active: bool
    locked: bool
    state: str


def _run(argv: tuple[str, ...]) -> str:
    raw = _execute_bounded_command(argv, 3.0, _LIMIT, check_exit=True)
    if len(raw) >= _LIMIT:
        raise ValueError("LOGIND_OUTPUT_LIMIT")
    return raw.decode("utf-8", errors="strict")


def list_sessions() -> list[LinuxSession]:
    """Return local graphical user sessions, including inactive/locked sessions.

    Name is the OS/NSS login as reported by logind; never strip a domain or
    accept a caller-supplied login. A separate identity mapping may qualify
    unqualified domain names only when the directory authority is verified.
    """
    listed = _run(("loginctl", "list-sessions", "--no-legend", "--no-pager"))
    ids = [line.split()[0] for line in listed.splitlines() if line.strip()]
    if len(ids) > 128 or any(_ID.fullmatch(value) is None for value in ids):
        raise ValueError("LOGIND_SESSION_LIST_INVALID")
    if not ids:
        return []
    output = _run(("loginctl", "show-session", *ids, "--no-pager", *(f"--property={prop}" for prop in _PROPERTIES.split(","))))
    if not output.strip():
        raise ValueError("LOGIND_SESSION_PROPERTIES_UNAVAILABLE")
    result: list[LinuxSession] = []
    for block in output.strip().split("\n\n"):
        fields = dict(line.split("=", 1) for line in block.splitlines() if "=" in line)
        if fields.get("Class") != "user" or fields.get("Type") not in {"x11", "wayland"} or fields.get("Remote") != "no":
            continue
        sid, uid, name = fields.get("Id", ""), fields.get("User", ""), fields.get("Name", "")
        if sid not in ids or not uid.isascii() or not uid.isdigit() or not 0 < int(uid) < 2**32:
            raise ValueError("LOGIND_SESSION_IDENTITY_INVALID")
        if not name or len(name) > 256 or any(ord(ch) < 32 or ord(ch) == 127 for ch in name):
            raise ValueError("LOGIND_LOGIN_INVALID")
        if fields.get("Active") not in {"yes", "no"} or fields.get("LockedHint") not in {"yes", "no"}:
            raise ValueError("LOGIND_SESSION_STATE_INVALID")
        result.append(LinuxSession(sid, int(uid), name, fields["Type"], fields["Active"] == "yes", fields["LockedHint"] == "yes", fields.get("State", "unknown")))
    return sorted(result, key=lambda session: (not session.active, session.session_id))
