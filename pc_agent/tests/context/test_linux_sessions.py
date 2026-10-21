"""Trust logind metadata rather than SSH/manager rows or user-supplied identity."""
from types import SimpleNamespace

import pytest


def test_session_context_selects_active_local_graphical_session(monkeypatch):
    from pc_agent.platform.linux import sessions

    calls = []
    def run(argv, timeout, limit, *, check_exit):
        calls.append(argv)
        if "list-sessions" in argv:
            return b"1 1000 operator -\n2 2000 user seat0\n3 2000 user -\n"
        assert "--property=Id" in argv and "--property=Name" in argv
        return b"Id=1\nUser=1000\nName=operator\nType=tty\nClass=user\nRemote=yes\nActive=yes\nState=active\nLockedHint=no\n\nId=2\nUser=2000\nName=ACME\\user\nType=wayland\nClass=user\nRemote=no\nActive=yes\nState=active\nLockedHint=yes\n\nId=3\nUser=2000\nName=user\nType=unspecified\nClass=manager\nRemote=no\nActive=yes\nState=active\n"

    monkeypatch.setattr(sessions, "_execute_bounded_command", run)
    observed = sessions.list_sessions()
    assert len(observed) == 1
    assert observed[0].user_login == "ACME\\user"
    assert observed[0].locked is True and observed[0].uid == 2000
    assert observed[0].session_id == "2" and observed[0].session_type == "wayland"
    assert len(calls) == 2 and all("who" not in call for call in calls)


def test_linux_context_uses_logind_and_preserves_domain_identity(monkeypatch):
    from pc_agent.context_profiles import probe
    from pc_agent.platform.linux import sessions

    monkeypatch.setattr(probe, "os", SimpleNamespace(name="posix"))
    monkeypatch.setattr(sessions, "list_sessions", lambda: [sessions.LinuxSession("c1", 2000, "user@domain.example", "x11", True, False, "active")])
    assert probe.SystemProbe().session_info() == {"current_user_login": "user@domain.example", "interactive_session_present": True}


@pytest.mark.parametrize("output", [b"x;injected 1000 user seat0\n", b"x" * 32768], ids=["invalid-id", "oversize"])
def test_session_list_rejects_invalid_identifiers_and_truncation(monkeypatch, output):
    from pc_agent.platform.linux import sessions

    monkeypatch.setattr(sessions, "_execute_bounded_command", lambda *a, **k: output)
    with pytest.raises(ValueError):
        sessions.list_sessions()


def test_logind_failure_is_unknown_not_a_fabricated_login(monkeypatch):
    from pc_agent.context_profiles import probe
    from pc_agent.platform.linux import sessions

    monkeypatch.setattr(probe, "os", SimpleNamespace(name="posix"))
    def failed():
        raise OSError("logind unavailable")
    monkeypatch.setattr(sessions, "list_sessions", failed)
    assert probe.SystemProbe().session_info() == {}
