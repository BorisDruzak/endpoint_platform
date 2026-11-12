import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from tools import build_ubuntu_agent_deb as ubuntu


def _ubuntu_host(monkeypatch):
    monkeypatch.setattr(ubuntu.platform, "system", lambda: "Linux")
    monkeypatch.setattr(ubuntu.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(
        ubuntu.platform, "freedesktop_os_release",
        lambda: {"ID": "ubuntu", "VERSION_ID": "24.04"},
    )


def test_build_ubuntu_deb_keeps_runtime_and_configuration_in_distinct_paths(tmp_path, monkeypatch):
    _ubuntu_host(monkeypatch)
    core = tmp_path / "core"
    (core / "_internal").mkdir(parents=True)
    (core / "endpoint-agent").write_bytes(b"frozen-core")
    output = tmp_path / "output"
    revision = "a" * 40

    def run(args, **kwargs):
        if args == [core / "endpoint-agent", "--print-version"]:
            return SimpleNamespace(stdout="3.2.191\n")
        assert args[:3] == ["dpkg-deb", "--root-owner-group", "--build"]
        root, artifact = map(Path, args[3:])
        runtime = root / "usr/lib/endpoint-agent-ubuntu"
        assert (runtime / "endpoint-agent").read_bytes() == b"frozen-core"
        assert json.loads((runtime / "current.json").read_text()) == {
            "schema_version": 1, "source_revision": revision, "version": "3.2.191",
        }
        assert (root / "DEBIAN/conffiles").read_text().splitlines() == [
            "/etc/endpoint-agent-ubuntu/agent.conf",
        ]
        service = (root / "usr/lib/systemd/system/endpoint-agent-ubuntu.service").read_text()
        assert "User=endpoint-agent-ubuntu\n" in service
        assert "StateDirectory=endpoint-agent-ubuntu\n" in service
        assert "--transport-mode gateway_wss" in service
        assert "--package-managed-updates" in service
        assert not (root / "var/lib/endpoint-agent-ubuntu").exists()
        artifact.write_bytes(b"deb")

    monkeypatch.setattr(ubuntu.subprocess, "run", run)
    artifact = ubuntu.build(core, output, version="3.2.191", source_revision=revision)
    assert artifact.name == "endpoint-agent-ubuntu_3.2.191-1ubuntu1_amd64.deb"
    assert artifact.read_bytes() == b"deb"
    with pytest.raises(FileExistsError):
        ubuntu.build(core, output, version="3.2.191", source_revision=revision)
    assert artifact.read_bytes() == b"deb"


def test_build_ubuntu_deb_rejects_mislabeled_core(tmp_path, monkeypatch):
    _ubuntu_host(monkeypatch)
    core = tmp_path / "core"
    (core / "_internal").mkdir(parents=True)
    (core / "endpoint-agent").touch()
    monkeypatch.setattr(
        ubuntu.subprocess, "run", lambda args, **kwargs: SimpleNamespace(stdout="3.2.190\n"),
    )
    output = tmp_path / "output"

    with pytest.raises(ValueError, match="reports '3.2.190'"):
        ubuntu.build(core, output, version="3.2.191", source_revision="b" * 40)

    assert not output.exists()


def test_build_debian12_uses_independent_package_and_state(tmp_path, monkeypatch):
    _ubuntu_host(monkeypatch)
    monkeypatch.setattr(
        ubuntu.platform, "freedesktop_os_release",
        lambda: {"ID": "debian", "VERSION_ID": "12"},
    )
    core = tmp_path / "core"
    (core / "_internal").mkdir(parents=True)
    (core / "endpoint-agent").write_bytes(b"frozen-core")

    def run(args, **kwargs):
        if args == [core / "endpoint-agent", "--print-version"]:
            return SimpleNamespace(stdout="3.2.193\n")
        root, artifact = map(Path, args[3:])
        control = (root / "DEBIAN/control").read_text()
        assert "Package: endpoint-agent-debian\n" in control
        assert "Depends: libc6 (>= 2.36), systemd" in control
        assert "Conflicts: endpoint-agent-ubuntu\n" in control
        unit = (root / "usr/lib/systemd/system/endpoint-agent-debian.service").read_text()
        assert "User=endpoint-agent-debian\n" in unit
        assert "StateDirectory=endpoint-agent-debian\n" in unit
        assert "endpoint-agent-ubuntu" not in unit
        assert "endpoint-agent-debian.service" in (root / "DEBIAN/postinst").read_text()
        assert (root / "usr/lib/endpoint-agent-debian/proxmox-health.py").is_file()
        assert "ProtectSystem=strict" in (root / "usr/lib/systemd/system/endpoint-proxmox-health.service").read_text()
        assert "Wants=endpoint-proxmox-health.timer" in (
            root / "usr/lib/systemd/system/endpoint-agent-debian.service.d/proxmox-health.conf"
        ).read_text()
        artifact.write_bytes(b"deb")

    monkeypatch.setattr(ubuntu.subprocess, "run", run)
    artifact = ubuntu.build(
        core, tmp_path / "output", version="3.2.193", source_revision="c" * 40, target="debian12",
    )
    assert artifact.name == "endpoint-agent-debian_3.2.193-1deb12u1_amd64.deb"
