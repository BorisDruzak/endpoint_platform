"""A refusal must happen before ordinary runtime composition is invoked."""
import importlib
from pathlib import Path
import sys

import pytest


@pytest.fixture(autouse=True)
def no_operator_event_log_writes(monkeypatch):
    entry = entry_module()
    monkeypatch.setattr(entry, "report_diagnostic", lambda *args, **kwargs: None, raising=False)


def entry_module():
    assert importlib.util.find_spec("tools.canary.fixtures.legacy_entry") is not None
    return importlib.import_module("tools.canary.fixtures.legacy_entry")


@pytest.mark.parametrize("version", [None, "3.2.82", "3.2.84", "3.2.85", "3.2.88", "3.2.100", "3.2.60000"])
def test_unfrozen_or_wrong_fixture_never_starts(monkeypatch, version):
    entry = entry_module()
    monkeypatch.setattr(entry.binding, "FIXTURE_VERSION", version)
    monkeypatch.setattr(entry, "AGENT_VERSION", "3.2.83")
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(entry, "runtime_main", lambda argv: pytest.fail("runtime started"))
    assert entry.main(["--windows-service-child"]) == 75


@pytest.mark.parametrize("arguments", [
    ["--launcher-version", ""], ["--launcher-version", "3.2"],
    ["--launcher-version"], ["--launcher-version", "3.2.81", "--launcher-version=3.2.81"],
    ["--launcher-version=3.2.81", "--launcher-version", "3.2.82"],
    ["--launcher-v=3.2.81"],
])
def test_malformed_or_repeated_argument_never_starts(monkeypatch, arguments):
    entry = configured(monkeypatch)
    monkeypatch.setattr(entry, "resolve", lambda explicit: pytest.fail("native query on invalid argv"))
    monkeypatch.setattr(entry, "runtime_main", lambda argv: pytest.fail("runtime started"))
    assert entry.main(["--windows-service-child", *arguments]) == 75


def configured(monkeypatch):
    entry = entry_module()
    monkeypatch.setattr(entry.binding, "FIXTURE_VERSION", "3.2.83")
    monkeypatch.setattr(entry, "AGENT_VERSION", "3.2.83")
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    return entry


def test_failed_native_resolution_prevents_startup(monkeypatch):
    entry = configured(monkeypatch)
    def reject(explicit):
        raise entry.Rejected("process_identity")
    monkeypatch.setattr(entry, "resolve", reject)
    monkeypatch.setattr(entry, "runtime_main", lambda argv: pytest.fail("runtime started"))
    assert entry.main(["--windows-service-child"]) == 75


def test_native_refusal_emits_stage_without_starting_runtime(monkeypatch):
    entry = configured(monkeypatch)
    events = []
    monkeypatch.setattr(entry, "report_diagnostic", lambda stage, **kw: events.append((stage, kw)), raising=False)
    error = entry.Rejected("native_observation_unavailable")
    monkeypatch.setattr(entry, "resolve", lambda explicit: (_ for _ in ()).throw(error))
    monkeypatch.setattr(entry, "runtime_main", lambda argv: pytest.fail("runtime started"))
    assert entry.main(["--windows-service-child"]) == 75
    assert [stage for stage, _ in events] == ["authority_start", "authority_refused"]
    assert events[-1][1]["error"] is error


def test_resolved81_is_supplied_before_runtime_startup(monkeypatch):
    entry = configured(monkeypatch)
    from tools.canary.fixtures.legacy_authority import Authority
    monkeypatch.setattr(entry, "resolve", lambda explicit: Authority("3.2.81", "verified_legacy_fixed_image"))
    def run(argv):
        assert argv == ["--windows-service-child", "--launcher-version", "3.2.81"]
        return 42
    monkeypatch.setattr(entry, "runtime_main", run)
    assert entry.main(["--windows-service-child"]) == 42


@pytest.mark.parametrize("mode", ["closed", "invalid_handle", "missing"])
def test_service_without_usable_stderr_still_starts_resolved_runtime(monkeypatch, mode):
    entry = configured(monkeypatch)
    from io import StringIO
    from tools.canary.fixtures.legacy_authority import Authority
    stream = StringIO()
    if mode == "closed":
        stream.close()
    elif mode == "invalid_handle":
        class InvalidServiceHandle:
            def write(self, value):
                raise OSError(22, "Invalid argument")
        stream = InvalidServiceHandle()
    else:
        stream = None
    monkeypatch.setattr(sys, "stderr", stream)
    monkeypatch.setattr(entry, "resolve", lambda explicit: Authority("3.2.81", "verified_legacy_fixed_image"))
    calls = []
    monkeypatch.setattr(entry, "runtime_main", lambda args: calls.append(args) or 42)
    assert entry.main(["--windows-service-child"]) == 42
    assert calls == [["--windows-service-child", "--launcher-version", "3.2.81"]]


def test_closed_stderr_preserves_native_refusal_and_reports_console_failure(monkeypatch):
    from io import StringIO
    entry = configured(monkeypatch)
    stream = StringIO()
    stream.close()
    monkeypatch.setattr(sys, "stderr", stream)
    events = []
    monkeypatch.setattr(entry, "report_diagnostic", lambda stage, **kw: events.append(stage))
    def refuse(explicit):
        raise entry.Rejected("not_service_child")
    monkeypatch.setattr(entry, "resolve", refuse)
    monkeypatch.setattr(entry, "runtime_main", lambda args: pytest.fail("refused runtime started"))
    assert entry.main(["--windows-service-child"]) == 75
    assert events == ["authority_start", "authority_refused", "console_unavailable"]


def test_immutable81_offline_verifier_remains_network_free(monkeypatch):
    entry = configured(monkeypatch)
    arguments = ["--verify", "--data-dir", "state", "--install-root", "root", "--ca-file", "ca"]
    monkeypatch.setattr(entry, "resolve", lambda explicit: pytest.fail("offline verifier requested service authority"))
    def run(argv):
        assert entry._parser().parse_args(argv).verify
        assert argv == arguments
        return 0
    monkeypatch.setattr(entry, "runtime_main", run)
    assert entry.main(arguments) == 0


def test_fixture_spec_refuses_canonical82_before_analysis(monkeypatch):
    from pc_agent import version
    from tools.canary.fixtures import fixture_binding
    # Keep the guard test meaningful on subsequent independently frozen sources.
    monkeypatch.setattr(version, "AGENT_VERSION", "3.2.82")
    monkeypatch.setattr(fixture_binding, "FIXTURE_VERSION", None)
    root = Path(__file__).resolve().parents[2]
    path = root / "tools/canary/fixtures/legacy_core.spec"
    assert path.exists()
    with pytest.raises(ValueError, match="fixture"):
        exec(compile(path.read_text(encoding="utf-8"), str(path), "exec"), {"SPECPATH": str(path.parent)})


@pytest.mark.parametrize('version',['3.2.100','3.2.60000','3.2.60003'])
def test_equivalent_b_requires_matching_literal_before_offline_verification(monkeypatch,version):
    entry = configured(monkeypatch)
    monkeypatch.setattr(entry.binding, 'FIXTURE_VERSION', version)
    monkeypatch.setattr(entry, 'AGENT_VERSION', version)
    monkeypatch.setattr(entry, 'resolve', lambda _: pytest.fail('offline verification acquired authority'))
    calls = []
    monkeypatch.setattr(entry, 'runtime_main', lambda argv: calls.append(argv) or 0)
    assert entry.main(['--verify']) == 0
    assert calls == [['--verify']]
    monkeypatch.setattr(entry, 'AGENT_VERSION', '3.2.99')
    assert entry.main(['--verify']) == 75
    assert len(calls) == 1
