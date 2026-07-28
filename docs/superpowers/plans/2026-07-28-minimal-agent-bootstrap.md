# Minimal Agent Bootstrap Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Import the existing endpoint agent as a minimal, provenance-recorded Endpoint Platform source tree and establish a repeatable baseline before changing its behavior.

**Architecture:** The repository receives the compatibility surface (`pc_agent` and its three direct `shared` dependencies) from the pinned Helpdesk snapshot. A retained-tree verifier prevents unrelated Helpdesk code from entering the project. A standard-library baseline runner runs the current agent, launcher, and compile checks and emits sanitized JSON suitable for comparison between the developer machine and `test-agent`.

**Tech Stack:** Python 3.12, pytest, pytest-asyncio, existing `pc_agent`, standard-library `subprocess` and `json`, Git sparse source snapshot.

## Global Constraints

- Source is `BorisDruzak/helpdesk`, branch `codex/helpdesk-process-model`, commit `8be364000089d70bac3ccf9aaef4f84397ca21a7`.
- Import only `pc_agent/`, `shared/tool_contracts.py`, `shared/builtin_tool_descriptors.py`, `shared/redaction.py`, `pytest.ini`, `requirements-ci.txt`, and the agent capability document.
- Preserve the `pc_agent` package name, launcher layout, and runtime behavior during this bootstrap.
- Do not import `server/`, `webapp/`, `mcp_helpdesk_server/`, ticket, Knowledge, content-pack, or Helpdesk deployment paths.
- Do not change production services or install production infrastructure in this plan.
- Run the agent baseline on the `test-agent` host before any Gateway, collector, headless-runtime, or update behavior change.
- Baseline artifacts must not contain secrets, token values, environment dumps, or absolute host paths.

---

## File structure

| Path | Responsibility |
| --- | --- |
| `pc_agent/**` | Existing endpoint agent and launcher compatibility surface copied from the pinned source. |
| `shared/tool_contracts.py` | Existing agent tool-contract dependency. |
| `shared/builtin_tool_descriptors.py` | Existing agent tool-descriptor dependency. |
| `shared/redaction.py` | Existing agent redaction dependency. |
| `docs/source/SOURCE_PROVENANCE.md` | Immutable source identity and minimal-import policy. |
| `docs/source/HELPDESK_EXTRACTION_MAP.md` | Retained source paths and explicit excluded top-level paths. |
| `tools/extraction/retained_paths.txt` | Machine-readable allowlist for the retained-tree verifier. |
| `tools/extraction/check_retained_tree.py` | Validates the repository does not contain Helpdesk server paths or server imports. |
| `tests/extraction/test_retained_tree.py` | Tests the retained-tree verifier against fixture trees. |
| `tools/baseline/run_agent_baseline.py` | Executes baseline commands and writes redacted JSON results. |
| `tests/baseline/test_run_agent_baseline.py` | Tests the runner command inventory and JSON redaction. |
| `artifacts/baseline/README.md` | Defines artifact format and retention policy. |
| `pyproject.toml` | Defines the supported Python floor and pytest test paths for the standalone source tree. |

## Task 1: Import and prove the retained source boundary

**Files:**
- Create: `pc_agent/**` from the pinned sparse source snapshot
- Create: `shared/tool_contracts.py` from the pinned sparse source snapshot
- Create: `shared/builtin_tool_descriptors.py` from the pinned sparse source snapshot
- Create: `shared/redaction.py` from the pinned sparse source snapshot
- Create: `pytest.ini` from the pinned sparse source snapshot, with `testpaths = pc_agent/tests tests`
- Create: `requirements-ci.txt` from the pinned sparse source snapshot
- Create: `docs/AGENT_CAPABILITIES_AND_REQUIREMENTS.md` from the pinned sparse source snapshot
- Create: `docs/source/SOURCE_PROVENANCE.md`
- Create: `docs/source/HELPDESK_EXTRACTION_MAP.md`
- Create: `tools/extraction/retained_paths.txt`
- Create: `tools/extraction/check_retained_tree.py`
- Test: `tests/extraction/test_retained_tree.py`

**Interfaces:**
- Consumes: sparse source at `C:\Users\admin-2\Documents\endpoint-helpdesk-agent-source`, pinned to `8be364000089d70bac3ccf9aaef4f84397ca21a7`.
- Produces: `check_retained_tree(repo_root: Path, retained_paths: set[str]) -> list[str]`; it returns sorted violation messages and never mutates the tree.

- [ ] **Step 1: Write the failing retained-tree tests**

```python
from pathlib import Path

from tools.extraction.check_retained_tree import check_retained_tree


def test_reports_prohibited_helpdesk_directory(tmp_path: Path) -> None:
    (tmp_path / "server").mkdir()

    violations = check_retained_tree(tmp_path, {"pc_agent", "shared/tool_contracts.py"})

    assert violations == ["prohibited path present: server"]


def test_reports_server_import_in_retained_agent_file(tmp_path: Path) -> None:
    agent = tmp_path / "pc_agent"
    agent.mkdir()
    (agent / "runtime.py").write_text("from server.gateway import connect\\n", encoding="utf-8")

    violations = check_retained_tree(tmp_path, {"pc_agent"})

    assert violations == ["prohibited import in pc_agent/runtime.py: server.gateway"]
```

- [ ] **Step 2: Run the tests to verify RED**

Run: `python -m pytest tests/extraction/test_retained_tree.py -q`

Expected: collection fails because `tools.extraction.check_retained_tree` does not exist.

- [ ] **Step 3: Implement the read-only verifier**

```python
PROHIBITED_TOP_LEVEL = {"server", "webapp", "mcp_helpdesk_server", "content_packs"}
PROHIBITED_IMPORT_PREFIXES = (
    "server",
    "webapp",
    "mcp_helpdesk_server",
    "content_packs",
)


def check_retained_tree(repo_root: Path, retained_paths: set[str]) -> list[str]:
    violations: list[str] = []
    for name in sorted(PROHIBITED_TOP_LEVEL):
        if (repo_root / name).exists():
            violations.append(f"prohibited path present: {name}")
    for path in sorted((repo_root / "pc_agent").rglob("*.py")):
        for imported_name in imported_modules(path):
            if imported_name in PROHIBITED_IMPORT_PREFIXES or imported_name.startswith(
                tuple(prefix + "." for prefix in PROHIBITED_IMPORT_PREFIXES)
            ):
                violations.append(
                    f"prohibited import in {path.relative_to(repo_root).as_posix()}: {imported_name}"
                )
    return sorted(violations)
```

Use `ast.parse(path.read_text(encoding="utf-8-sig"))` in `imported_modules` so original UTF-8 BOM source files are supported. Read the allowlist from `tools/extraction/retained_paths.txt`, normalize every path with POSIX separators, and report an imported top-level file that is not in the allowlist.

- [ ] **Step 4: Re-run the focused tests to verify GREEN**

Run: `python -m pytest tests/extraction/test_retained_tree.py -q`

Expected: PASS.

- [ ] **Step 5: Copy the approved subset and write provenance**

Copy only the paths in the Global Constraints from the sparse source. Write `docs/source/SOURCE_PROVENANCE.md` with the exact repository URL, branch, SHA, snapshot location, and the sentence `Extraction policy: minimal agent subset; no full Helpdesk import.` Write `tools/extraction/retained_paths.txt` with:

```text
pc_agent
shared/tool_contracts.py
shared/builtin_tool_descriptors.py
shared/redaction.py
pytest.ini
requirements-ci.txt
docs/AGENT_CAPABILITIES_AND_REQUIREMENTS.md
```

Write `docs/source/HELPDESK_EXTRACTION_MAP.md` with this explicit exclusion list: `server/`, `webapp/`, `mcp_helpdesk_server/`, `content_packs/`, `scripts/`, ticket, Knowledge, quality, problem, change, and deploy code.

- [ ] **Step 6: Verify the imported tree**

Run:

```bash
python tools/extraction/check_retained_tree.py
python -m compileall -q pc_agent shared
git diff --cached --check -- . ':(exclude)pc_agent/**'
```

Expected: all commands exit `0` and no excluded top-level directory exists. The pinned `pc_agent` source is intentionally excluded from the whitespace check because its pre-existing trailing whitespace must not be reformatted during behavior-preserving bootstrap.

- [ ] **Step 7: Commit the source boundary**

```bash
git add pc_agent shared pytest.ini requirements-ci.txt docs tools/extraction tests/extraction
git commit -m "refactor: import minimal endpoint agent source"
```

## Task 2: Define standalone test metadata and baseline artifact policy

**Files:**
- Create: `pyproject.toml`
- Create: `artifacts/baseline/README.md`
- Modify: `pytest.ini`

**Interfaces:**
- Consumes: retained source tree from Task 1.
- Produces: a Python 3.12-only test configuration where `python -m pytest pc_agent/tests` and `python -m pytest tests` discover no absent Helpdesk server test path.

- [ ] **Step 1: Write the failing metadata test**

```python
from pathlib import Path

import pytest


def test_pytest_configuration_excludes_removed_helpdesk_server() -> None:
    pytest_ini = Path("pytest.ini").read_text(encoding="utf-8")

    assert "server/tests" not in pytest_ini
    assert "pc_agent/tests" in pytest_ini
    assert "tests" in pytest_ini
```

Add this test to `tests/extraction/test_retained_tree.py`.

- [ ] **Step 2: Run the test to verify RED**

Run: `python -m pytest tests/extraction/test_retained_tree.py::test_pytest_configuration_excludes_removed_helpdesk_server -q`

Expected: FAIL because the copied source configuration still references `server/tests`.

- [ ] **Step 3: Create the minimal standalone metadata**

Create `pyproject.toml` with:

```toml
[project]
name = "endpoint-platform"
version = "0.0.0"
requires-python = ">=3.12,<3.13"

[tool.pytest.ini_options]
testpaths = ["pc_agent/tests", "tests"]
asyncio_mode = "auto"
asyncio_default_fixture_loop_scope = "session"
```

Update `pytest.ini` so its `testpaths` are only `pc_agent/tests` and `tests`. Create `artifacts/baseline/README.md` defining one JSON result per host, command exit codes, elapsed seconds, UTC timestamp, and a prohibition on secrets, environment variables, home directories, and token values.

- [ ] **Step 4: Run the metadata test to verify GREEN**

Run: `python -m pytest tests/extraction/test_retained_tree.py::test_pytest_configuration_excludes_removed_helpdesk_server -q`

Expected: PASS.

- [ ] **Step 5: Commit the standalone metadata**

```bash
git add pyproject.toml pytest.ini artifacts/baseline/README.md tests/extraction/test_retained_tree.py
git commit -m "build: define standalone agent test metadata"
```

## Task 3: Implement the sanitized baseline runner

**Files:**
- Create: `tools/baseline/run_agent_baseline.py`
- Test: `tests/baseline/test_run_agent_baseline.py`

**Interfaces:**
- Consumes: `--python` executable path and `--output` JSON path.
- Produces: `run_baseline(python_executable: str, output_path: Path) -> int` and one JSON object with `schema_version`, `generated_at`, `commands`, and `overall_exit_code`.

- [ ] **Step 1: Write the failing runner tests**

```python
from pathlib import Path

from tools.baseline.run_agent_baseline import build_commands, redact_text


def test_build_commands_uses_the_requested_python_executable() -> None:
    commands = build_commands("/opt/venv/bin/python")

    assert commands == [
        ["/opt/venv/bin/python", "-m", "pytest", "pc_agent/tests", "-m", "not manual", "-q"],
        [
            "/opt/venv/bin/python", "-m", "pytest",
            "pc_agent/tests/test_self_update_runtime.py",
            "pc_agent/tests/test_launcher_main.py",
            "pc_agent/tests/test_launcher_portable_main.py",
            "-q",
        ],
        ["/opt/venv/bin/python", "-m", "compileall", "-q", "pc_agent", "shared"],
    ]


def test_redact_text_removes_absolute_paths_and_bearer_values() -> None:
    value = "token=abc123 path=/home/test-agent-lin/project bearer xyz"

    assert redact_text(value) == "token=[REDACTED] path=[REDACTED_PATH] bearer [REDACTED]"
```

- [ ] **Step 2: Run the tests to verify RED**

Run: `python -m pytest tests/baseline/test_run_agent_baseline.py -q`

Expected: collection fails because `tools.baseline.run_agent_baseline` does not exist.

- [ ] **Step 3: Implement the runner with standard-library process execution**

```python
def build_commands(python_executable: str) -> list[list[str]]:
    return [
        [python_executable, "-m", "pytest", "pc_agent/tests", "-m", "not manual", "-q"],
        [
            python_executable, "-m", "pytest",
            "pc_agent/tests/test_self_update_runtime.py",
            "pc_agent/tests/test_launcher_main.py",
            "pc_agent/tests/test_launcher_portable_main.py",
            "-q",
        ],
        [python_executable, "-m", "compileall", "-q", "pc_agent", "shared"],
    ]


def run_baseline(python_executable: str, output_path: Path) -> int:
    results = []
    for command in build_commands(python_executable):
        try:
            completed = subprocess.run(command, text=True, capture_output=True, check=False)
            exit_code = completed.returncode
            stdout = completed.stdout
            stderr = completed.stderr
        except OSError as error:
            exit_code = 127
            stdout = ""
            stderr = str(error)
        results.append({
            "command": command,
            "exit_code": exit_code,
            "stdout": redact_text(stdout),
            "stderr": redact_text(stderr),
        })
    payload = {
        "schema_version": "agent_baseline_v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "commands": results,
        "overall_exit_code": 0 if all(item["exit_code"] == 0 for item in results) else 1,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\\n", encoding="utf-8")
    return payload["overall_exit_code"]
```

`redact_text` must replace case-insensitive `token=...`, `authorization: bearer ...`, and `bearer ...` values with `[REDACTED]`; it must replace Unix absolute paths beginning with `/home/` or `/root/` and Windows absolute paths beginning with a drive letter with `[REDACTED_PATH]`.

- [ ] **Step 4: Run focused tests to verify GREEN**

Run: `python -m pytest tests/baseline/test_run_agent_baseline.py -q`

Expected: PASS.

- [ ] **Step 5: Verify the runner in a controlled failing invocation**

Run:

```bash
python tools/baseline/run_agent_baseline.py --python missing-python --output artifacts/baseline/local.json
python -c "import json; payload=json.load(open('artifacts/baseline/local.json', encoding='utf-8')); assert payload['schema_version'] == 'agent_baseline_v1'; assert payload['overall_exit_code'] == 1"
```

Expected: runner exits `1`, writes valid JSON, and does not expose an absolute host path or credential.

- [ ] **Step 6: Commit the runner**

```bash
git add tools/baseline/run_agent_baseline.py tests/baseline/test_run_agent_baseline.py artifacts/baseline/README.md
git commit -m "test: add sanitized agent baseline runner"
```

## Task 4: Establish and record the agent baseline on the test host

**Files:**
- Create: `artifacts/baseline/test-agent-summary.md`
- Modify: `artifacts/baseline/README.md` only if the recorded artifact format changes

**Interfaces:**
- Consumes: Task 1 source boundary, Task 2 dependencies, Task 3 runner, and SSH alias `test-agent`.
- Produces: a sanitized test-host result at `artifacts/baseline/test-agent.json` and a committed human-readable summary of command status and pre-existing failures.

- [ ] **Step 1: Create the failing summary-integrity test**

```python
import json
from pathlib import Path


def test_baseline_summary_matches_recorded_result() -> None:
    payload = json.loads(Path("artifacts/baseline/test-agent.json").read_text(encoding="utf-8"))
    summary = Path("artifacts/baseline/test-agent-summary.md").read_text(encoding="utf-8")

    assert f"Overall exit code: `{payload['overall_exit_code']}`" in summary
    assert payload["schema_version"] == "agent_baseline_v1"
```

Add this to `tests/baseline/test_run_agent_baseline.py` only after `test-agent.json` and its summary are present.

- [ ] **Step 2: Copy the current branch to the test host without credentials**

Create a Git archive from the current commit and stream it through SSH:

```bash
git archive --format=tar HEAD | ssh test-agent "rm -rf ~/endpoint-platform-baseline && mkdir -p ~/endpoint-platform-baseline && tar -xf - -C ~/endpoint-platform-baseline"
```

Expected: `~/endpoint-platform-baseline` contains only tracked bootstrap files and no local SSH, Git, or environment secrets.

- [ ] **Step 3: Install the retained CI dependencies on `test-agent`**

Run through the existing passwordless SSH profile:

```bash
ssh test-agent "sudo -n apt-get update && sudo -n apt-get install -y ffmpeg kernel-headers-6.12"
ssh test-agent "python3 -m venv ~/endpoint-platform-venv && ~/endpoint-platform-venv/bin/python -m pip install --upgrade pip && ~/endpoint-platform-venv/bin/python -m pip install -r ~/endpoint-platform-baseline/requirements-ci.txt"
```

Expected: both commands exit `0`. The virtual environment remains outside the Git worktree.

- [ ] **Step 4: Run and retrieve the baseline artifact**

```bash
ssh test-agent "cd ~/endpoint-platform-baseline && ~/endpoint-platform-venv/bin/python tools/baseline/run_agent_baseline.py --python ~/endpoint-platform-venv/bin/python --output artifacts/baseline/test-agent.json"
scp test-agent:~/endpoint-platform-baseline/artifacts/baseline/test-agent.json artifacts/baseline/test-agent.json
```

Expected: the runner exits `0` or `1` with a complete JSON report. Preserve a non-zero result as a pre-existing baseline failure; do not modify agent behavior in this task to force green.

- [ ] **Step 5: Write and test the sanitized summary**

Write `artifacts/baseline/test-agent-summary.md` with the source SHA, UTC timestamp from the JSON, every command's exit status, and a line matching `Overall exit code: ` followed by the JSON `overall_exit_code` formatted as inline code; for example, `Overall exit code: `0``. Do not include test output, command paths, environment values, credentials, or raw tokens.

Run: `python -m pytest tests/baseline/test_run_agent_baseline.py -q`

Expected: PASS when the summary matches the artifact.

- [ ] **Step 6: Commit the recorded baseline**

```bash
git add artifacts/baseline/test-agent.json artifacts/baseline/test-agent-summary.md tests/baseline/test_run_agent_baseline.py
git commit -m "test: record initial agent baseline"
```

## Plan self-review

- Source-boundary, provenance, retained paths, static import checks, baseline runner, test-host baseline, and production non-goals each map to a task above.
- The plan deliberately does not add Gateway, Device Context, headless runtime, Windows service, Helpdesk client, DNS, TLS, PostgreSQL, Nginx, or production deployment behavior.
- The import verifier, test metadata, and baseline runner each begin with a test that must fail before their implementation.
- All path names, command inventories, JSON fields, source SHA, test commands, and test-host commands are defined by this document.
