import builtins
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import pc_agent.ws_agent as ws_agent_module
from pc_agent.enrollment_bootstrap import EnrollmentOutcome


def test_gui_import_failure_exits_without_headless_fallback(monkeypatch, tmp_path):
    class _FakeLock:
        def __init__(self, _path):
            self.released = False

        def acquire(self):
            return True

        def release(self):
            self.released = True

    main_async_calls = []

    async def _fake_main_async(*args, **kwargs):
        main_async_calls.append((args, kwargs))
        return 0

    original_import = builtins.__import__

    def _guarded_import(name, *args, **kwargs):
        if name == "qasync" or name == "PySide6" or name.startswith("PySide6."):
            raise ImportError("Qt runtime missing")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(ws_agent_module.runtime_paths, "resolve_data_root", lambda cli_value=None: tmp_path / "data")
    monkeypatch.setattr(ws_agent_module.runtime_paths, "resolve_install_root", lambda cli_value=None: tmp_path / "install")
    monkeypatch.setattr(ws_agent_module, "SingleInstanceLock", _FakeLock)
    monkeypatch.setattr(ws_agent_module, "init_config", lambda data_root: None)
    monkeypatch.setattr(ws_agent_module, "get_config", lambda: SimpleNamespace(ui=SimpleNamespace(autostart_gui=True)))
    monkeypatch.setattr(ws_agent_module, "main_async", _fake_main_async)
    monkeypatch.setattr(builtins, "__import__", _guarded_import)
    monkeypatch.setattr(sys, "argv", ["ws_agent.py", "--gui", "--data-dir", str(tmp_path / "data")])

    with pytest.raises(SystemExit) as exc_info:
        ws_agent_module.main()

    assert exc_info.value.code == 1
    assert main_async_calls == []


def test_systemd_enrollment_gate_stops_runtime_on_terminal_bootstrap_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _denied(**_kwargs):
        return EnrollmentOutcome("denied", None)

    monkeypatch.setattr(
        ws_agent_module,
        "systemd_runtime_paths",
        lambda: (Path("config"), Path("ca"), Path("claim")),
    )
    monkeypatch.setattr(ws_agent_module, "run_linux_enrollment_gate", _denied)

    with pytest.raises(SystemExit) as exc_info:
        ws_agent_module._run_linux_systemd_enrollment_gate()

    assert exc_info.value.code == 75


def test_systemd_enrollment_gate_allows_persisted_credential_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _already_enrolled(**_kwargs):
        return EnrollmentOutcome("already_enrolled", "device-1")

    monkeypatch.setattr(
        ws_agent_module,
        "systemd_runtime_paths",
        lambda: (Path("config"), Path("ca"), Path("claim")),
    )
    monkeypatch.setattr(ws_agent_module, "run_linux_enrollment_gate", _already_enrolled)

    ws_agent_module._run_linux_systemd_enrollment_gate()


def test_systemd_enrollment_gate_requires_credentials_when_service_contract_is_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ws_agent_module, "systemd_runtime_paths", lambda: None)
    monkeypatch.setenv("ENDPOINT_AGENT_ENROLLMENT_REQUIRED", "1")

    with pytest.raises(SystemExit) as exc_info:
        ws_agent_module._run_linux_systemd_enrollment_gate()

    assert exc_info.value.code == 75


def test_gateway_runtime_bypasses_bootstrap_gate_after_handoff(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """The post-handoff unit no longer has the one-time claim credential."""
    calls: list[Path] = []

    def _bootstrap_gate_must_not_run() -> None:
        raise AssertionError("post-handoff Gateway mode must not load bootstrap credentials")

    async def _gateway_runner(*, ca_file: Path) -> None:
        calls.append(ca_file)

    monkeypatch.setattr(ws_agent_module, "_run_linux_systemd_enrollment_gate", _bootstrap_gate_must_not_run)
    monkeypatch.setattr("pc_agent.endpoint_gateway.run_gateway_forever", _gateway_runner)
    monkeypatch.setenv("ENDPOINT_AGENT_GATEWAY_READY", "1")
    monkeypatch.setenv("ENDPOINT_AGENT_CA_FILE", str(tmp_path / "endpoint-agent-ca"))
    monkeypatch.setattr(sys, "argv", ["ws_agent.py", "--no-gui"])

    ws_agent_module.main()

    assert calls == [tmp_path / "endpoint-agent-ca"]


def test_first_boot_enters_gateway_after_successful_enrollment(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    calls: list[Path] = []

    async def _gateway_runner(*, ca_file: Path) -> None:
        calls.append(ca_file)

    monkeypatch.setattr(ws_agent_module, "_run_linux_systemd_enrollment_gate", lambda: None)
    monkeypatch.setattr("pc_agent.endpoint_gateway.run_gateway_forever", _gateway_runner)
    monkeypatch.setattr(
        ws_agent_module.runtime_paths,
        "resolve_data_root",
        lambda **_kwargs: (_ for _ in ()).throw(AssertionError("legacy runtime must not start")),
    )
    monkeypatch.setenv("ENDPOINT_AGENT_ENROLLMENT_REQUIRED", "1")
    monkeypatch.setenv("ENDPOINT_AGENT_CA_FILE", str(tmp_path / "endpoint-agent-ca"))
    monkeypatch.setattr(sys, "argv", ["ws_agent.py", "--no-gui"])

    ws_agent_module.main()

    assert calls == [tmp_path / "endpoint-agent-ca"]
