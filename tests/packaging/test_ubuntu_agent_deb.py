import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
from types import SimpleNamespace

import pytest

from tools import build_ubuntu_agent_deb as ubuntu


@pytest.mark.parametrize("target", ubuntu.TARGETS)
@pytest.mark.parametrize(("state", "enabled", "should_start"), [
    ("active", "enabled", True),
    ("activating", "disabled", True),
    ("failed", "enabled", True),
    ("failed", "disabled", False),
    ("inactive", "enabled", False),
    ("inactive", "masked", False),
])
def test_deb_fences_upgrade_and_resumes_only_prior_intent(tmp_path, target, state, enabled, should_start):
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("shell unavailable")
    profile = ubuntu.TARGETS[target]
    unit = f"{profile.package}.service"
    preinst = ubuntu.ROOT / "packaging/ubuntu/preinst"
    assert preinst.is_file(), "the incoming package must fence the legacy service before unpack"
    shell = """systemd-sysusers() { :; }
systemd-tmpfiles() { :; }
sync() { :; }
systemctl() {
    case "$1" in
        daemon-reload) return 0 ;;
        start) printf '%s\\n' "$*" ;;
        is-enabled) printf '%s\\n' "$UNIT_ENABLED" ;;
        show)
            case "$*" in
                *ActiveState*) cat state ;;
                *MainPID*) echo 0 ;;
                *) return 2 ;;
            esac
            ;;
        *) return 2 ;;
    esac
}
deb-systemd-invoke() {
    printf '%s %s\\n' "$1" "$2"
    if [ "$1" = stop ]; then printf 'inactive\\n' > state; fi
}
"""
    (tmp_path / "state").write_text(state + "\n")
    env = dict(os.environ, UNIT_ENABLED=enabled)
    for operation, expected in (
        ("preinst", f"stop {unit}"),
        ("postinst", f"start {unit}" if should_start else ""),
    ):
        script = profile.render(ubuntu.ROOT / "packaging/ubuntu" / operation).decode()
        script = script.replace("[ -d /run/systemd/system ]", "true")
        script = script.replace("/etc/systemd/system/", "./")
        harness = tmp_path / f"{operation}.sh"
        harness.write_text(shell + script, encoding="utf-8", newline="\n")
        result = subprocess.run(
            [bash, harness.name, "upgrade" if operation == "preinst" else "configure"],
            cwd=tmp_path, env=env, capture_output=True, text=True, check=True, timeout=15,
        )
        assert result.stdout.strip() == expected
        fence = tmp_path / f"{unit}.d/90-endpoint-package-upgrade.conf"
        assert fence.exists() == (operation == "preinst")
        if fence.exists():
            assert "ConditionPathExists=!./" in fence.read_text()
    assert not (tmp_path / f"{unit}.d/.endpoint-package-resume").exists()


@pytest.mark.parametrize("target", ubuntu.TARGETS)
@pytest.mark.parametrize(("state", "enabled", "expected"), [
    ("active", "enabled", "restart"),
    ("active", "disabled", "restart"),
    ("failed", "enabled", "restart"),
    ("failed", "enabled-runtime", "restart"),
    ("failed", "disabled", ""),
    ("failed", "masked", ""),
    ("active", "masked-runtime", ""),
    ("inactive", "enabled", ""),
])
def test_deb_postinst_recovers_only_restartable_service(
    tmp_path, target, state, enabled, expected,
):
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("shell unavailable")
    profile = ubuntu.TARGETS[target]
    script = profile.render(ubuntu.ROOT / "packaging/ubuntu/postinst").decode()
    assert "/run/systemd/system" in script
    harness = tmp_path / "postinst-test.sh"
    harness.write_text(
        """systemd-sysusers() { :; }
systemd-tmpfiles() { :; }
systemctl() {
    case "$1" in
        daemon-reload) return 0 ;;
        is-active) [ "$SERVICE_STATE" = active ] ;;
        is-failed) [ "$SERVICE_STATE" = failed ] ;;
        is-enabled) printf '%s\\n' "$ENABLED_STATE" ;;
        *) return 2 ;;
    esac
}
deb-systemd-invoke() { printf '%s %s\\n' "$1" "$2"; }
SERVICE_STATE=$2
ENABLED_STATE=$3
""" + script.replace("[ -d /run/systemd/system ]", "true"), encoding="utf-8", newline="\n",
    )
    result = subprocess.run(
        [bash, str(harness), "configure", state, enabled],
        capture_output=True, text=True, check=True, timeout=15,
    )
    assert result.stdout.strip() == (f"{expected} {profile.package}.service" if expected else "")


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
        if args == [core / "endpoint-agent", "--print-build-identity"]:
            return SimpleNamespace(stdout=json.dumps({
                "schema_version": "endpoint_linux_core_build_v2",
                "version": "3.2.191", "source_revision": revision,
                "python_version": "3.12.3", "pyinstaller_version": "6.19.0",
            }))
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
        assert "Endpoint DEB transaction fence" in (root / "DEBIAN/preinst").read_text()
        control = (root / "DEBIAN/control").read_text()
        assert f"X-Endpoint-Source-Revision: {revision}\n" in control
        assert "X-Endpoint-Python-Version: 3.12.3\n" in control
        assert "X-Endpoint-PyInstaller-Version: 6.19.0\n" in control
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


@pytest.mark.parametrize(("source_revision", "python_version", "error"), [
    ("b" * 40, "3.12.3", "source revision"),
    ("a" * 40, "3.12.3\nInjected: field", "toolchain versions"),
])
def test_build_ubuntu_deb_rejects_invalid_frozen_provenance(
    tmp_path, monkeypatch, source_revision, python_version, error,
):
    _ubuntu_host(monkeypatch)
    core = tmp_path / "core"
    (core / "_internal").mkdir(parents=True)
    (core / "endpoint-agent").touch()

    def run(args, **kwargs):
        if args[-1] == "--print-version":
            return SimpleNamespace(stdout="3.2.191\n")
        if args[-1] == "--print-build-identity":
            return SimpleNamespace(stdout=json.dumps({
                "schema_version": "endpoint_linux_core_build_v2",
                "version": "3.2.191", "source_revision": "a" * 40,
                "python_version": python_version, "pyinstaller_version": "6.19.0",
            }))
        pytest.fail("package generation must not start")

    monkeypatch.setattr(ubuntu.subprocess, "run", run)
    with pytest.raises(ValueError, match=error):
        ubuntu.build(core, tmp_path / "output", version="3.2.191", source_revision=source_revision)


def test_frozen_core_reports_source_without_enrollment(tmp_path, monkeypatch, capsys):
    import sys
    from pc_agent.runtime.main import main
    from pc_agent.version import AGENT_VERSION

    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path), raising=False)
    identity = tmp_path / "endpoint-core-build.json"
    assert main(["--print-build-identity"]) == 2
    identity.write_text(json.dumps({
        "source_revision": "a" * 40,
        "pyinstaller_version": "6.19.0",
    }), encoding="ascii")
    assert main(["--print-build-identity"]) == 0
    assert json.loads(capsys.readouterr().out) == {
        "schema_version": "endpoint_linux_core_build_v2",
        "source_revision": "a" * 40,
        "version": AGENT_VERSION,
        "python_version": ".".join(map(str, sys.version_info[:3])),
        "pyinstaller_version": "6.19.0",
    }


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
        if args == [core / "endpoint-agent", "--print-build-identity"]:
            return SimpleNamespace(stdout=json.dumps({
                "schema_version": "endpoint_linux_core_build_v2",
                "version": "3.2.193", "source_revision": "c" * 40,
                "python_version": "3.12.3", "pyinstaller_version": "6.19.0",
            }))
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


@pytest.mark.skipif(os.name != "posix" or not shutil.which("dpkg-deb"), reason="requires native dpkg")
def test_real_deb_is_readable_by_service_when_built_with_private_umask(tmp_path, monkeypatch):
    _ubuntu_host(monkeypatch)
    revision = "a" * 40
    core = tmp_path / "core"
    executable = core / "endpoint-agent"
    identity = {
        "schema_version": "endpoint_linux_core_build_v2",
        "version": "3.2.191",
        "source_revision": revision,
        "python_version": "3.12.3",
        "pyinstaller_version": "6.19.0",
    }
    old_umask = os.umask(0o077)
    try:
        (core / "_internal").mkdir(parents=True)
        (core / "_internal/build.json").write_text(json.dumps(identity))
        executable.write_text(
            "#!/bin/sh\n"
            'if [ "$1" = --print-version ]; then echo 3.2.191; else\n'
            '    cat "$(dirname "$0")/_internal/build.json"\n'
            "fi\n",
        )
        executable.chmod(0o700)
        (core / "_internal/build-link.json").symlink_to("build.json")
        artifact = ubuntu.build(
            core, tmp_path / "packages", version="3.2.191", source_revision=revision,
        )
    finally:
        os.umask(old_umask)

    extracted = tmp_path / "extracted"
    subprocess.run(["dpkg-deb", "--extract", artifact, extracted], check=True, timeout=15)
    runtime = extracted / "usr/lib/endpoint-agent-ubuntu"
    for directory in (extracted / "usr", runtime, runtime / "_internal"):
        assert stat.S_IMODE(directory.stat().st_mode) == 0o755
    for file in (runtime / "current.json", runtime / "_internal/build.json"):
        assert stat.S_IMODE(file.stat().st_mode) == 0o644
    assert stat.S_IMODE((runtime / "endpoint-agent").stat().st_mode) == 0o755
    assert (runtime / "_internal/build-link.json").readlink() == Path("build.json")
