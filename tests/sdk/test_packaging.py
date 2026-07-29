from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import venv


SDK_PROJECT = Path(__file__).resolve().parents[2] / "sdk" / "python"


def test_sdk_wheel_imports_without_endpoint_platform_source_tree(tmp_path: Path) -> None:
    wheelhouse = tmp_path / "wheelhouse"
    environment_root = tmp_path / "environment"
    wheelhouse.mkdir()

    subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            "--no-deps",
            "--no-build-isolation",
            "--wheel-dir",
            str(wheelhouse),
            str(SDK_PROJECT),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    wheel = next(wheelhouse.glob("endpoint_platform_client-*.whl"))
    venv.EnvBuilder(with_pip=True).create(environment_root)
    environment_python = environment_root / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    subprocess.run(
        [str(environment_python), "-m", "pip", "install", str(wheel)],
        check=True,
        capture_output=True,
        text=True,
    )
    result = subprocess.run(
        [str(environment_python), "-I", "-c", "import endpoint_platform_client; print(endpoint_platform_client.EndpointPlatformClient.__name__)"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "EndpointPlatformClient"
