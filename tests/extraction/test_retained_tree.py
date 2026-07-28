from pathlib import Path

from tools.extraction.check_retained_tree import check_retained_tree, load_retained_paths


def test_reports_prohibited_helpdesk_directory(tmp_path: Path) -> None:
    """A Helpdesk server directory must not enter the Endpoint Platform tree."""
    (tmp_path / "server").mkdir()

    violations = check_retained_tree(tmp_path, {"pc_agent", "shared/tool_contracts.py"})

    assert violations == ["prohibited path present: server"]


def test_reports_server_import_in_retained_agent_file(tmp_path: Path) -> None:
    """An agent import of Helpdesk server code must block the minimal extraction."""
    agent = tmp_path / "pc_agent"
    agent.mkdir()
    (agent / "runtime.py").write_text("from server.gateway import connect\n", encoding="utf-8")

    violations = check_retained_tree(tmp_path, {"pc_agent"})

    assert violations == ["prohibited import in pc_agent/runtime.py: server.gateway"]


def test_reports_unapproved_shared_dependency(tmp_path: Path) -> None:
    """New shared dependencies must be reviewed before they enter the extraction."""
    agent = tmp_path / "pc_agent"
    agent.mkdir()
    (agent / "runtime.py").write_text("from shared.private import value\n", encoding="utf-8")

    violations = check_retained_tree(tmp_path, {"pc_agent", "shared/tool_contracts.py"})

    assert violations == ["unapproved shared import in pc_agent/runtime.py: shared.private"]


def test_load_retained_paths_normalizes_windows_separators(tmp_path: Path) -> None:
    """The allowlist must compare source paths consistently on every host OS."""
    path = tmp_path / "retained_paths.txt"
    path.write_text("pc_agent\nshared\\redaction.py\n", encoding="utf-8")

    assert load_retained_paths(path) == {"pc_agent", "shared/redaction.py"}
