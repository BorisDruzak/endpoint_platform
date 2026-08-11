from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tarfile

from pc_agent.build_alt_rpm_source import build_source_archive


ROOT = Path(__file__).resolve().parents[2]
BUILD_RPM = ROOT / "deploy" / "agent" / "alt" / "rpm" / "build-rpm.sh"
RPM_SPEC = ROOT / "deploy" / "agent" / "alt" / "rpm" / "endpoint-agent.spec"


def _write(path: Path, content: bytes, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    path.chmod(mode)


def _release_bundle(tmp_path: Path) -> Path:
    bundle = tmp_path / "bundle"
    _write(bundle / "launcher", b"launcher\n", 0o755)
    _write(bundle / "pc_agent" / "pc_agent", b"agent\n", 0o755)
    _write(
        bundle / "manifest.json",
        json.dumps(
            {
                "schema_version": 1,
                "version": "1.2.3",
                "source_revision": "abc123",
                "files": [],
            }
        ).encode(),
    )
    return bundle


def test_rpm_source_archive_includes_the_package_spec(tmp_path: Path) -> None:
    """Omitting the spec would make a reviewed release bundle impossible to turn into RPM."""
    archive = build_source_archive(
        _release_bundle(tmp_path),
        version="1.2.3",
        revision="abc123",
        output=tmp_path / "output",
    )

    with tarfile.open(archive, "r:gz") as source:
        names = {member.name for member in source.getmembers() if member.isfile()}

    assert "endpoint-agent-1.2.3/packaging/endpoint-agent.spec" in names


def test_build_wrapper_rejects_a_path_like_version_before_building(tmp_path: Path) -> None:
    """Passing a path-like version must never control a build or output directory."""
    result = subprocess.run(
        [
            "bash",
            BUILD_RPM.as_posix(),
            "--version",
            "../unsafe",
            "--release",
            "1",
            "--source",
            tmp_path.as_posix(),
            "--output",
            (tmp_path / "out").as_posix(),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 2
    assert "version must be a bounded RPM identifier" in result.stderr


def test_alt_linux_rpm_spec_declares_the_required_package_group() -> None:
    """ALT rpmbuild rejects package metadata without Group before an RPM is created."""
    assert "Group:          System/Monitoring" in RPM_SPEC.read_text(encoding="utf-8")


def test_alt_linux_rpm_spec_skips_autodependency_scans_of_the_frozen_payload() -> None:
    """Scanning every embedded Qt library makes the self-contained package build unbounded."""
    assert "AutoReq:        no" in RPM_SPEC.read_text(encoding="utf-8")
