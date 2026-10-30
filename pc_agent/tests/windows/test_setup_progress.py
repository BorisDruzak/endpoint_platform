"""Visible, secret-free progress from the real enrollment state machine."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

from pc_agent.windows_setup import SetupConfig, UniversalWindowsSetup


def test_manual_wait_reports_once_and_retains_timeout_reason():
    start = datetime(2026, 10, 31, tzinfo=UTC)
    clock = [start]
    events = []

    class Transport:
        def create_request(self, body):
            return {
                "request_id": "11111111-1111-4111-8111-111111111111",
                "status": "waiting_approval",
                "reason": "MANUAL_POLICY",
            }

        def request_status(self, *_):
            return {"status": "waiting_approval", "reason": "MANUAL_POLICY"}

        def request_claim(self, *_):
            raise AssertionError("Unapproved request must never obtain a claim")

    def sleep(seconds):
        clock[0] += timedelta(seconds=seconds)

    setup = UniversalWindowsSetup(
        SetupConfig(
            "https://endpoint.sosnadmin.local", Path("ca.crt"), "3.2.156", "3.2.156"
        ),
        transport=Transport(),
        provision_claim=lambda _: None,
        fingerprint_probe=lambda: "sha256:synthetic-fingerprint",
        inventory_probe=lambda: {"hostname": "test-host", "macs": []},
        clock=lambda: clock[0],
        sleep=sleep,
        progress=events.append,
    )
    result = setup.run()
    assert result.status == "timed_out" and result.reason == "WAITING_APPROVAL"
    assert [event.detail for event in events] == [
        "REQUESTING_ENROLLMENT",
        "WAITING_APPROVAL",
    ]
    assert "администратора" in events[-1].message
    assert (clock[0] - start).total_seconds() == 1800


def test_unknown_progress_reason_never_echoes_server_text():
    from pc_agent.setup_progress import SetupProgress

    event = SetupProgress(
        "ENROLLMENT", "error", "sensitive server reply ic_not-for-display"
    )
    assert event.detail == "UNKNOWN_ERROR"
    assert "sensitive" not in event.message and "ic_" not in repr(event)


def test_progress_observer_failure_does_not_change_enrollment_result():
    from pc_agent.setup_progress import emit_progress

    def broken(_):
        raise RuntimeError("view failed")

    emit_progress(broken, "MSI", "running", "STARTED")


def test_completion_and_known_failures_have_actionable_russian_messages():
    from pc_agent.setup_progress import SetupProgress

    assert (
        "установлен" in SetupProgress("SERVICE", "success", "SERVICE_RUNNING").message
    )
    assert (
        "30 минут" in SetupProgress("ENROLLMENT", "error", "WAITING_APPROVAL").message
    )
    assert (
        "версию" in SetupProgress("ENROLLMENT", "error", "NO_MATCHING_CAMPAIGN").message
    )
    assert (
        "пересечени"
        in SetupProgress("ENROLLMENT", "waiting", "AMBIGUOUS_CAMPAIGN").message
    )


def test_waiting_progress_is_persisted_without_an_interactive_window(
    monkeypatch, tmp_path
):
    from pc_agent.platform.windows import setup_entry
    from pc_agent.setup_progress import SetupProgress

    results = []
    logs = []
    monkeypatch.setattr(
        setup_entry, "_write_install_result", lambda **kw: results.append(kw)
    )
    monkeypatch.setattr(setup_entry, "_prepare_diagnostics_root", lambda: tmp_path)
    monkeypatch.setattr(
        setup_entry, "_write_install_log", lambda *a, **kw: logs.append(kw)
    )
    setup_entry._on_enrollment_progress(
        SetupProgress("ENROLLMENT", "waiting", "WAITING_APPROVAL")
    )
    assert results[-1]["status"] == "WAITING_APPROVAL"
    assert results[-1]["detail"] == "WAITING_APPROVAL"
    assert logs[-1]["step"] == "ENROLLMENT"


def test_baseline_wait_is_reported_as_context_wait_and_retained_on_timeout():
    clock = [datetime(2026, 10, 31, tzinfo=UTC)]
    events = []

    class Transport:
        def create_request(self, _):
            return {
                "request_id": "11111111-1111-4111-8111-111111111111",
                "status": "auto_approved",
            }

        def request_claim(self, *_):
            return {"claim": "ic_synthetic"}

        def request_verification(self, *_):
            return {"status": "waiting_wss", "reason": "WAITING_BASELINE"}

    def sleep(seconds):
        clock[0] += timedelta(seconds=seconds)

    setup = UniversalWindowsSetup(
        SetupConfig(
            "https://endpoint.sosnadmin.local", Path("ca.crt"), "3.2.156", "3.2.156"
        ),
        transport=Transport(),
        provision_claim=lambda _: None,
        fingerprint_probe=lambda: "sha256:synthetic-fingerprint",
        inventory_probe=lambda: {"hostname": "test-host", "macs": []},
        clock=lambda: clock[0],
        sleep=sleep,
        progress=events.append,
    )
    outcome = setup.run()
    assert outcome.reason == "WAITING_CONTEXT"
    assert [e.detail for e in events].count("WAITING_CONTEXT") == 1
    assert "сведения" in events[-1].message


def test_service_companion_warnings_explain_success_without_false_failure():
    from pc_agent.setup_progress import SetupProgress

    for detail in (
        "SERVICE_RUNNING_TRAY_START_FAILED",
        "SERVICE_RUNNING_USER_SENSOR_START_FAILED",
        "SERVICE_RUNNING_USER_COMPANIONS_START_FAILED",
    ):
        event = SetupProgress("SERVICE", "success", detail)
        assert event.detail == detail
        assert "установлен" in event.message and "вход" in event.message
