import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from pc_agent.launcher import launcher_main
from pc_agent.launcher import installer as launcher_installer
from pc_agent.version import AGENT_VERSION


def test_find_agent_binary_ignores_a_directory_named_like_the_binary(tmp_path):
    version_dir = tmp_path / "version"
    executable = "pc_agent.exe" if launcher_installer.os.name == "nt" else "pc_agent"
    (version_dir / executable).mkdir(parents=True)
    binary = version_dir / executable / executable
    binary.write_text("binary", encoding="utf-8")

    assert launcher_installer._find_agent_binary(version_dir) == binary


def test_launcher_prints_its_compiled_version_without_reading_install_state(
    monkeypatch, capsys
):
    """RPM assembly must reject a launcher rebuilt from a different release source."""
    monkeypatch.setattr(sys, "argv", ["launcher.py", "--print-version"])

    assert launcher_main.main() is None
    assert capsys.readouterr().out.strip() == AGENT_VERSION


def test_launcher_loads_current_json_with_utf8_bom(monkeypatch, tmp_path):
    install_root = tmp_path / "install"
    versions_dir = install_root / "versions"
    version_dir = versions_dir / "3.1.68"
    version_dir.mkdir(parents=True)
    current_path = install_root / "current.json"
    current_path.write_bytes(
        b"\xef\xbb\xbf"
        + json.dumps({"version": "3.1.68", "previous": "3.1.67"}).encode("utf-8")
    )

    monkeypatch.setattr(
        launcher_main, "_find_agent_binary", lambda path: path / "pc_agent"
    )

    _, version, previous, binary_path = launcher_main._load_current_state(
        current_path, versions_dir
    )

    assert version == "3.1.68"
    assert previous == "3.1.67"
    assert binary_path == version_dir / "pc_agent"


@pytest.mark.parametrize(
    ("entrypoint_kind", "expected_tail"),
    [
        (
            "headless",
            [
                "--transport-mode",
                "gateway_wss",
                "--no-migration-http-pull-fallback",
            ],
        ),
        ("legacy", ["--no-gui"]),
    ],
)
def test_alt_launcher_routes_service_flags_to_the_selected_entrypoint_only(
    monkeypatch, tmp_path, entrypoint_kind, expected_tail
):
    """Forwarding GUI flags to headless, or WSS flags to legacy, breaks migration."""
    install_root = tmp_path / "install"
    version_dir = install_root / "versions" / "3.1.77"
    if entrypoint_kind == "headless":
        binary = version_dir / "endpoint-agent" / "endpoint-agent"
    else:
        executable = (
            "pc_agent.exe" if launcher_installer.os.name == "nt" else "pc_agent"
        )
        binary = version_dir / executable
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"entrypoint")
    (install_root / "current.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "source_revision": "feedface",
                "version": "3.1.77",
            }
        ),
        encoding="utf-8",
    )
    data_root = tmp_path / "data"
    launched: list[list[str]] = []

    class _FakeProc:
        def wait(self):
            return 0

    def _fake_popen(argv, **_kwargs):
        launched.append(list(argv))
        return _FakeProc()

    monotonic_values = iter([0.0, 30.0])
    monkeypatch.setenv("ENDPOINT_AGENT_ALT_UPDATE_MODE", "1")
    monkeypatch.setattr(
        launcher_main, "resolve_data_root", lambda cli_value=None: data_root
    )
    monkeypatch.setattr(
        launcher_main, "resolve_install_root", lambda cli_value=None: install_root
    )
    monkeypatch.setattr(launcher_main.subprocess, "Popen", _fake_popen)
    monkeypatch.setattr(launcher_main.time, "monotonic", lambda: next(monotonic_values))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "launcher.py",
            "--no-gui",
            "--transport-mode",
            "gateway_wss",
            "--no-migration-http-pull-fallback",
        ],
    )

    with pytest.raises(SystemExit) as exc_info:
        launcher_main.main()

    assert exc_info.value.code == 0
    assert launched == [[str(binary), *expected_tail]]


def test_launcher_rolls_back_after_repeated_immediate_crash(monkeypatch, tmp_path):
    install_root = tmp_path / "install"
    versions_dir = install_root / "versions"
    version_bad_dir = versions_dir / "3.1.20"
    version_prev_dir = versions_dir / "3.1.19"
    version_bad_dir.mkdir(parents=True, exist_ok=True)
    version_prev_dir.mkdir(parents=True, exist_ok=True)
    current_path = install_root / "current.json"
    current_path.write_text(
        json.dumps(
            {"version": "3.1.20", "previous": "3.1.19"}, ensure_ascii=False, indent=2
        ),
        encoding="utf-8",
    )
    data_root = tmp_path / "data"

    launches = []
    launch_argvs = []
    exit_codes = iter([101, 101, 101, 0])
    monotonic_values = iter([0.0, 1.0, 2.0, 3.0, 4.0, 5.0, 10.0, 40.0])

    class _FakeProc:
        def __init__(self, code):
            self._code = code

        def wait(self):
            return self._code

    def _fake_find_agent_binary(version_dir):
        return version_dir / "pc_agent"

    def _fake_popen(argv, **kwargs):
        launches.append(Path(argv[0]).parent.name)
        launch_argvs.append(list(argv))
        return _FakeProc(next(exit_codes))

    monkeypatch.setattr(
        launcher_main, "resolve_data_root", lambda cli_value=None: data_root
    )
    monkeypatch.setattr(
        launcher_main, "resolve_install_root", lambda cli_value=None: install_root
    )
    monkeypatch.setattr(launcher_main, "_find_agent_binary", _fake_find_agent_binary)
    monkeypatch.setattr(launcher_main.subprocess, "Popen", _fake_popen)
    monkeypatch.setattr(launcher_main.time, "monotonic", lambda: next(monotonic_values))
    monkeypatch.setattr(launcher_main.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(sys, "argv", ["launcher.py", "--no-gui"])

    with pytest.raises(SystemExit) as exc_info:
        launcher_main.main()

    assert exc_info.value.code == 0
    assert json.loads(current_path.read_text(encoding="utf-8")) == {
        "version": "3.1.19",
        "previous": "3.1.20",
    }
    assert launches == ["3.1.20", "3.1.20", "3.1.20", "3.1.19"]
    assert all(argv[-1] == "--no-gui" for argv in launch_argvs)

    failed_launch = json.loads(
        (data_root / "updates" / "last_failed_launch.json").read_text(encoding="utf-8")
    )
    assert failed_launch["reason"] == "startup_crash_rollback"
    assert failed_launch["crashed_version"] == "3.1.20"
    assert failed_launch["rollback_version"] == "3.1.19"


def test_launcher_stops_after_repeated_immediate_crash_without_rollback(
    monkeypatch, tmp_path
):
    install_root = tmp_path / "install"
    versions_dir = install_root / "versions"
    version_dir = versions_dir / "3.1.61"
    version_dir.mkdir(parents=True, exist_ok=True)
    current_path = install_root / "current.json"
    current_path.write_text(
        json.dumps(
            {"version": "3.1.61", "previous": None}, ensure_ascii=False, indent=2
        ),
        encoding="utf-8",
    )
    data_root = tmp_path / "data"

    launches = []
    exit_codes = iter([101, 101, 101])
    monotonic_values = iter([0.0, 1.0, 2.0, 3.0, 4.0, 5.0])

    class _FakeProc:
        def __init__(self, code):
            self._code = code

        def wait(self):
            return self._code

    def _fake_find_agent_binary(version_dir):
        return version_dir / "pc_agent"

    def _fake_popen(argv, **kwargs):
        launches.append(Path(argv[0]).parent.name)
        if len(launches) > launcher_main.IMMEDIATE_CRASH_RETRY_LIMIT:
            raise AssertionError("launcher restarted after terminal startup crash")
        return _FakeProc(next(exit_codes))

    monkeypatch.setattr(
        launcher_main, "resolve_data_root", lambda cli_value=None: data_root
    )
    monkeypatch.setattr(
        launcher_main, "resolve_install_root", lambda cli_value=None: install_root
    )
    monkeypatch.setattr(launcher_main, "_find_agent_binary", _fake_find_agent_binary)
    monkeypatch.setattr(launcher_main.subprocess, "Popen", _fake_popen)
    monkeypatch.setattr(launcher_main.time, "monotonic", lambda: next(monotonic_values))
    monkeypatch.setattr(launcher_main.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(sys, "argv", ["launcher.py"])

    with pytest.raises(SystemExit) as exc_info:
        launcher_main.main()

    assert exc_info.value.code == 101
    assert launches == ["3.1.61", "3.1.61", "3.1.61"]

    failed_launch = json.loads(
        (data_root / "updates" / "last_failed_launch.json").read_text(encoding="utf-8")
    )
    assert failed_launch["reason"] == "startup_crash"
    assert failed_launch["crashed_version"] == "3.1.61"
    assert failed_launch["rollback_version"] is None
    assert failed_launch["attempts"] == launcher_main.IMMEDIATE_CRASH_RETRY_LIMIT
    assert "rollback is unavailable" in failed_launch["message"]
