"""A refusal must happen before ordinary runtime composition is invoked."""
import importlib
from pathlib import Path
import sys

import pytest


def entry_module():
    assert importlib.util.find_spec("tools.canary.fixtures.legacy_entry") is not None
    return importlib.import_module("tools.canary.fixtures.legacy_entry")


@pytest.mark.parametrize("version", [None, "3.2.82", "3.2.84", "3.2.85", "3.2.88"])
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


def test_resolved81_is_supplied_before_runtime_startup(monkeypatch):
    entry = configured(monkeypatch)
    from tools.canary.fixtures.legacy_authority import Authority
    monkeypatch.setattr(entry, "resolve", lambda explicit: Authority("3.2.81", "verified_legacy_fixed_image"))
    def run(argv):
        assert argv == ["--windows-service-child", "--launcher-version", "3.2.81"]
        return 42
    monkeypatch.setattr(entry, "runtime_main", run)
    assert entry.main(["--windows-service-child"]) == 42


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
