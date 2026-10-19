from __future__ import annotations

from io import BytesIO
import os
from types import SimpleNamespace

import pytest

from pc_agent.context_profiles import probe as probe_module
from pc_agent.context_profiles.probe import SystemProbe, WINDOWS_QUERY_USER_COMMAND


def test_windows_session_observes_native_quser_success_without_query_dispatcher(monkeypatch) -> None:
    # On the acceptance guest query.exe user returns 1 despite forwarding a
    # successful quser.exe result. Keep strict exit checking on the actual tool.
    monkeypatch.setattr(probe_module, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(probe_module.shutil, "which", lambda name: name + ".exe")
    commands = []

    def native_command(command, timeout_seconds, limit, *, check_exit=False):
        commands.append(command)
        assert check_exit is True
        assert timeout_seconds == 2.0 and limit == 8192
        if command == ("query.exe", "user"):
            raise ValueError("native dispatcher exit 1")
        assert command == ("quser.exe",)
        return b"USERNAME SESSIONNAME ID STATE IDLE TIME LOGON TIME\noperator console 1 Active none 10/19/2026 09:12\n"

    class NativeBytes(bytes):
        def decode(self, encoding, errors="strict"):
            assert encoding == "oem" and errors == "strict"
            return super().decode("ascii", errors)

    def native_bytes(*args, **kwargs):
        return NativeBytes(native_command(*args, **kwargs))

    monkeypatch.setattr(probe_module, "_execute_bounded_command", native_bytes)
    assert SystemProbe().session_info() == {
        "current_user_login": "operator", "interactive_session_present": True,
    }
    assert commands == [("quser.exe",)]


@pytest.mark.parametrize(
    ("header", "row", "login"),
    [
        ("USERNAME SESSIONNAME ID STATE IDLE TIME LOGON TIME", ">operator console 1 Active none 10/14/2026 03:17", "operator"),
        ("ИМЯ ПОЛЬЗОВАТЕЛЯ СЕАНС ID СТАТУС ПРОСТОЙ ВРЕМЯ ВХОДА", ">тестовый console 1 Активно нет 14.10.2026 03:17", "тестовый"),
        ("BENUTZERNAME SITZUNGSNAME ID STATUS LEERLAUFZEIT ANMELDEZEIT", "operator 2 Getr. 10 14.10.2026 03:17", "operator"),
        ("NOM UTILISATEUR NOM SESSION ID ÉTAT TEMPS INACTIF HEURE OUVERTURE", "operator rdp-tcp#3 3 Actif aucun 14/10/2026 03:17", "operator"),
    ],
)
def test_windows_session_uses_a_real_session_row_not_a_localized_header(
    monkeypatch, header: str, row: str, login: str,
) -> None:
    monkeypatch.setattr(probe_module, "os", SimpleNamespace(name="nt"))

    class RecordedProbe(SystemProbe):
        def run(self, argv, timeout_seconds, max_bytes):
            assert argv == WINDOWS_QUERY_USER_COMMAND
            return header + "\n" + row + "\n"

    assert RecordedProbe().session_info() == {
        "current_user_login": login, "interactive_session_present": True,
    }


@pytest.mark.parametrize("message", ["Нет пользователей для *", "Ошибка [5]: Отказано в доступе"])
def test_failed_windows_session_query_never_turns_stderr_into_a_user(monkeypatch, message: str) -> None:
    monkeypatch.setattr(probe_module, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(probe_module.shutil, "which", lambda _: "query.exe")

    class FailedQuery:
        returncode = 1
        stdout = BytesIO(b"")
        stderr = BytesIO(message.encode("cp866"))

        def poll(self):
            return self.returncode

        def wait(self, timeout=None):
            return self.returncode

    monkeypatch.setattr(probe_module.subprocess, "Popen", lambda *args, **kwargs: FailedQuery())
    assert SystemProbe().session_info() == {}


def test_windows_header_only_has_no_interactive_user(monkeypatch) -> None:
    monkeypatch.setattr(probe_module, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(SystemProbe, "run", lambda *args: "ИМЯ ПОЛЬЗОВАТЕЛЯ СЕАНС ID СТАТУС\n")
    assert SystemProbe().session_info() == {
        "current_user_login": None, "interactive_session_present": False,
    }


def test_windows_service_session_zero_is_not_an_interactive_user(monkeypatch) -> None:
    monkeypatch.setattr(probe_module, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(SystemProbe, "run", lambda *args: "SYSTEM services 0 Disc none 14.10.2026 03:17\n")
    assert SystemProbe().session_info() == {
        "current_user_login": None, "interactive_session_present": False,
    }


@pytest.mark.skipif(os.name != "nt", reason="native Windows OEM codec")
def test_successful_windows_query_decodes_oem_user_without_replacement(monkeypatch) -> None:
    # Keep the fixture representable in the native OEM page, including English
    # Windows runners; the observed Russian guest uses CP866.
    for login in ("тестовый", "müller", "テスト", "테스트", "operator"):
        try:
            login.encode("oem")
        except UnicodeError:
            continue
        break
    output = f"USERNAME SESSIONNAME ID STATE\n>{login} console 1 Active none 14.10.2026 03:17\n"
    raw = output.encode("oem")
    monkeypatch.setattr(probe_module.shutil, "which", lambda _: "query.exe")

    def recorded_command(command, timeout_seconds, limit, **options):
        return raw

    monkeypatch.setattr(probe_module, "_execute_bounded_command", recorded_command)
    assert SystemProbe().session_info() == {
        "current_user_login": login, "interactive_session_present": True,
    }
