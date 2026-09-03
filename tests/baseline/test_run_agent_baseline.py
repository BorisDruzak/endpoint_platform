import json
from pathlib import Path

from tools.baseline import run_agent_baseline as baseline_module
from tools.baseline.run_agent_baseline import build_commands, redact_text, run_baseline


def test_build_commands_uses_the_requested_python_executable() -> None:
    commands = build_commands("/opt/venv/bin/python")

    assert commands == [
        ["/opt/venv/bin/python", "-m", "pytest", "pc_agent/tests", "-m", "not manual", "-q"],
        [
            "/opt/venv/bin/python",
            "-m",
            "pytest",
            "pc_agent/tests/test_self_update_runtime.py",
            "pc_agent/tests/test_launcher_main.py",
            "-q",
        ],
        ["/opt/venv/bin/python", "-m", "compileall", "-q", "pc_agent", "shared"],
    ]


def test_redact_text_removes_tokens_bearers_and_absolute_paths() -> None:
    value = "token=abc123 path=/home/test-agent-lin/project bearer xyz C:\\Users\\admin\\secret"

    assert redact_text(value) == "token=[REDACTED] path=[REDACTED_PATH] bearer [REDACTED] [REDACTED_PATH]"


def test_run_baseline_records_a_sanitized_missing_python_failure(tmp_path: Path) -> None:
    output = tmp_path / "baseline.json"

    exit_code = run_baseline("missing-python", output)

    payload = json.loads(output.read_text(encoding="utf-8"))
    assert exit_code == 1
    assert payload["schema_version"] == "agent_baseline_v1"
    assert payload["overall_exit_code"] == 1
    assert [result["exit_code"] for result in payload["commands"]] == [127, 127, 127]
    assert str(tmp_path) not in json.dumps(payload)


def test_run_baseline_redacts_absolute_command_paths(monkeypatch, tmp_path: Path) -> None:
    """The persisted command inventory must not leak a test-host home path."""
    monkeypatch.setattr(
        baseline_module,
        "build_commands",
        lambda _python: [["/home/test-agent-lin/endpoint-platform-venv/bin/python", "-V"]],
    )
    output = tmp_path / "baseline.json"

    run_baseline("ignored", output)

    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["commands"][0]["command"] == ["[REDACTED_PATH]", "-V"]


def test_baseline_summary_matches_recorded_result() -> None:
    payload = json.loads(Path("artifacts/baseline/test-agent.json").read_text(encoding="utf-8"))
    summary = Path("artifacts/baseline/test-agent-summary.md").read_text(encoding="utf-8")

    assert f"Overall exit code: `{payload['overall_exit_code']}`" in summary
    assert payload["schema_version"] == "agent_baseline_v1"
