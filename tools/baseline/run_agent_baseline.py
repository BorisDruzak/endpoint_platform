"""Run and record the preserved endpoint-agent baseline."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path


TOKEN_PATTERN = re.compile(r"(?i)\btoken\s*=\s*[^\s,;]+")
BEARER_PATTERN = re.compile(r"(?i)\b(?:authorization:\s*)?bearer\s+[^\s,;]+")
UNIX_PATH_PATTERN = re.compile(r"(?<![A-Za-z0-9_])/(?:home|root)/[^\s,;]+")
WINDOWS_PATH_PATTERN = re.compile(r"(?i)\b[A-Z]:\\[^\s,;]+")


def build_commands(python_executable: str) -> list[list[str]]:
    """Return the fixed compatibility checks for one Python executable."""
    return [
        [python_executable, "-m", "pytest", "pc_agent/tests", "-m", "not manual", "-q"],
        [
            python_executable,
            "-m",
            "pytest",
            "pc_agent/tests/test_self_update_runtime.py",
            "pc_agent/tests/test_launcher_main.py",
            "-q",
        ],
        [python_executable, "-m", "compileall", "-q", "pc_agent", "shared"],
    ]


def redact_text(value: str) -> str:
    """Remove known credential shapes and host-specific absolute paths."""
    value = TOKEN_PATTERN.sub("token=[REDACTED]", value)
    value = BEARER_PATTERN.sub("bearer [REDACTED]", value)
    value = UNIX_PATH_PATTERN.sub("[REDACTED_PATH]", value)
    return WINDOWS_PATH_PATTERN.sub("[REDACTED_PATH]", value)


def run_baseline(python_executable: str, output_path: Path) -> int:
    """Execute all baseline commands and write a sanitized result document."""
    results: list[dict[str, object]] = []
    for command in build_commands(python_executable):
        started = time.monotonic()
        try:
            completed = subprocess.run(command, text=True, capture_output=True, check=False)
            exit_code, stdout, stderr = completed.returncode, completed.stdout, completed.stderr
        except OSError as error:
            exit_code, stdout, stderr = 127, "", str(error)
        results.append(
            {
                "command": [redact_text(part) for part in command],
                "exit_code": exit_code,
                "elapsed_seconds": round(time.monotonic() - started, 3),
                "stdout": redact_text(stdout),
                "stderr": redact_text(stderr),
            }
        )
    payload = {
        "schema_version": "agent_baseline_v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "commands": results,
        "overall_exit_code": 0 if all(item["exit_code"] == 0 for item in results) else 1,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return int(payload["overall_exit_code"])


def main() -> int:
    """Parse CLI arguments and run the baseline."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", dest="python_executable", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    return run_baseline(args.python_executable, args.output)


if __name__ == "__main__":
    raise SystemExit(main())
