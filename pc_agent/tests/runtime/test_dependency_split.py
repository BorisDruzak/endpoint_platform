"""Contracts for the isolated Endpoint Agent core build inputs."""

from __future__ import annotations

import runpy
import subprocess
import sys
from pathlib import Path

import pytest
from packaging.requirements import Requirement


PROJECT_ROOT = Path(__file__).resolve().parents[3]
REQUIREMENTS_ROOT = PROJECT_ROOT / "requirements"
CORE_REQUIREMENTS = REQUIREMENTS_ROOT / "agent-core.txt"

CORE_LOCK = {
    "aiohttp": "3.13.3",
    "aiosqlite": "0.22.1",
    "loguru": "0.7.3",
    "psutil": "7.2.2",
    "pydantic": "2.12.5",
    "pyyaml": "6.0.2",
}
FORBIDDEN_CORE_DISTRIBUTIONS = {
    "pyside6",
    "qasync",
    "aiortc",
    "aioice",
    "av",
    "pylibsrtp",
    "mss",
    "pillow",
    "pynput",
    "imageio-ffmpeg",
}


def _locked_requirements(path: Path) -> dict[str, str]:
    requirements: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("-r "):
            continue
        requirement = Requirement(line)
        assert requirement.specifier
        assert str(requirement.specifier).startswith("==")
        requirements[requirement.name.lower()] = str(requirement.specifier)[2:]
    return requirements


def _capture_analysis(spec_path: Path) -> dict[str, object]:
    captured: dict[str, object] = {}

    def analysis(scripts: list[str], **kwargs: object) -> object:
        captured["scripts"] = scripts
        captured.update(kwargs)
        return type(
            "AnalysisResult", (), {"pure": [], "scripts": [], "binaries": [], "datas": []}
        )()

    runpy.run_path(
        str(spec_path),
        init_globals={
            "SPECPATH": str(spec_path.parent),
            "Analysis": analysis,
            "PYZ": lambda pure: pure,
            "EXE": lambda *args, **kwargs: (args, kwargs),
            "COLLECT": lambda *args, **kwargs: (args, kwargs),
        },
    )
    return captured


def test_agent_core_lock_contains_only_headless_runtime_dependencies() -> None:
    """Adding a GUI, Helpdesk, or Remote Assist dependency to core is a bug."""
    locked = _locked_requirements(CORE_REQUIREMENTS)

    assert locked == CORE_LOCK
    assert not FORBIDDEN_CORE_DISTRIBUTIONS.intersection(locked)


def test_headless_entrypoint_can_run_as_the_pyinstaller_script() -> None:
    """A core artifact must start when PyInstaller executes main.py as a script."""
    result = subprocess.run(
        [sys.executable, str(PROJECT_ROOT / "pc_agent" / "runtime" / "main.py"), "--help"],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert "Endpoint Agent headless runtime" in result.stdout


@pytest.mark.parametrize("platform", ("linux", "windows"))
def test_core_specs_build_only_the_headless_runtime(platform: str) -> None:
    """Changing a core package back to a GUI or legacy entrypoint is a bug."""
    captured = _capture_analysis(
        PROJECT_ROOT / "pc_agent" / f"pyinstaller_endpoint_core_{platform}.spec"
    )

    assert captured["scripts"] == [
        str(PROJECT_ROOT / "pc_agent" / "runtime" / "main.py")
    ]
    assert captured["datas"] == []
    assert not {
        "PySide6",
        "qasync",
        "pc_agent.ui_gui",
        "pc_agent.ui_bridge",
        "pc_agent.remote_assist",
        "pc_agent.ws_agent",
    }.intersection(captured["hiddenimports"])
    assert {
        "PySide6",
        "qasync",
        "pc_agent.ui_gui",
        "pc_agent.ui_bridge",
        "pc_agent.remote_assist",
        "pc_agent.ws_agent",
    }.issubset(captured["excludes"])
