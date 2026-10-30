"""Installer/UI coordination must preserve main-thread transactions."""

from types import SimpleNamespace
import threading

from pc_agent.platform.windows import setup_entry
from pc_agent.setup_progress import SetupProgress


def test_interactive_work_stays_on_calling_thread_and_finishes_once(monkeypatch):
    from pc_agent.platform.windows import setup_progress_ui

    events = []

    class Window:
        def __init__(self, *_):
            events.append("create")

        def start(self):
            events.append("start")

        def update(self, event):
            events.append(event)

        def finish(self, code):
            events.append(("finish", code))

        def wait_closed(self):
            events.append("closed")

    monkeypatch.setattr(setup_progress_ui, "SetupProgressWindow", Window)
    caller = threading.get_ident()

    def install(args):
        assert threading.get_ident() == caller
        setup_entry._report_progress("MSI", "running", "STARTED")
        return 31

    monkeypatch.setattr(setup_entry, "_run_setup", install)
    assert setup_entry._run_interactive_setup(SimpleNamespace(quiet=False)) == 31
    assert events[:2] == ["create", "start"]
    assert events[-2:] == [("finish", 31), "closed"]
    assert SetupProgress("MSI", "running", "STARTED") in events


def test_no_installation_starts_when_window_cannot_open(monkeypatch):
    from pc_agent.platform.windows import setup_progress_ui

    class Window:
        def __init__(self, *_):
            pass

        def start(self):
            raise OSError("native window unavailable")

    monkeypatch.setattr(setup_progress_ui, "SetupProgressWindow", Window)
    monkeypatch.setattr(
        setup_entry,
        "_run_setup",
        lambda _: (_ for _ in ()).throw(AssertionError("must not install")),
    )
    monkeypatch.setattr(setup_entry, "_finish", lambda *a, **k: k["code"])
    shown = []
    monkeypatch.setattr(setup_entry, "_show_result_dialog", lambda *a: shown.append(a))
    assert setup_entry._run_interactive_setup(SimpleNamespace(quiet=False)) == 20
    assert shown[-1][2] == "UI_UNAVAILABLE"


def test_main_routes_quiet_preflight_and_recovery_away_from_ui(monkeypatch):
    monkeypatch.setattr(setup_entry, "_run_setup", lambda _: 7)
    monkeypatch.setattr(setup_entry, "_run_interactive_setup", lambda _: 9)
    assert setup_entry.main(["--quiet"]) == 7
    assert setup_entry.main(["--preflight"]) == 7
    assert (
        setup_entry.main(
            ["--recover-staged-update", "11111111-1111-4111-8111-111111111111"]
        )
        == 7
    )
    assert setup_entry.main([]) == 9
