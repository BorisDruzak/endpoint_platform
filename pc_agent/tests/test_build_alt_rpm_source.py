from __future__ import annotations

import json
from pathlib import Path
import tarfile

from pc_agent.build_alt_rpm_source import build_source_archive


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


def test_source_archive_contains_only_release_and_required_offline_provisioning_assets(
    tmp_path: Path,
) -> None:
    """Dropping an install asset or adding arbitrary files would make RPM builds unsafe."""
    archive = build_source_archive(
        _release_bundle(tmp_path),
        version="1.2.3",
        revision="abc123",
        output=tmp_path / "output",
    )

    assert archive == tmp_path / "output" / "endpoint-agent-1.2.3.tar.gz"
    with tarfile.open(archive, "r:gz") as source:
        names = [member.name for member in source.getmembers() if member.isfile()]

    assert names == [
        "endpoint-agent-1.2.3/agent-bundle/launcher",
        "endpoint-agent-1.2.3/agent-bundle/manifest.json",
        "endpoint-agent-1.2.3/agent-bundle/pc_agent/pc_agent",
        "endpoint-agent-1.2.3/docs/ALT_AGENT_INSTALL.md",
        "endpoint-agent-1.2.3/provision/apply-pending-alt-update.sh",
        "endpoint-agent-1.2.3/provision/default-config.yaml",
        "endpoint-agent-1.2.3/provision/endpoint-agent-update.path",
        "endpoint-agent-1.2.3/provision/endpoint-agent-update.service",
        "endpoint-agent-1.2.3/provision/endpoint-agent.service",
        "endpoint-agent-1.2.3/provision/install-endpoint-agent.sh",
    ]

