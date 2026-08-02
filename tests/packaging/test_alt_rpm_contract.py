"""Contracts for the native ALT Endpoint Agent RPM."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile

import pytest


ROOT = Path(__file__).resolve().parents[2]
PACKAGE_ROOT = ROOT / "packaging" / "alt"
SPEC = PACKAGE_ROOT / "endpoint-agent.spec"
BUILD = PACKAGE_ROOT / "build-rpm.sh"
README = PACKAGE_ROOT / "README.md"
SOURCES = PACKAGE_ROOT / "SOURCES"
SERVICE = SOURCES / "endpoint-agent.service"
TMPFILES = SOURCES / "endpoint-agent.tmpfiles"
LOGROTATE = SOURCES / "endpoint-agent.logrotate"
LIFECYCLE_HARNESS = Path(__file__).with_name("verify_alt_rpm_lifecycle.sh")


def _text(path: Path) -> str:
    assert path.is_file(), f"missing ALT RPM artifact: {path.relative_to(ROOT)}"
    return path.read_text(encoding="utf-8")


def _write_release_fixture(root: Path) -> tuple[Path, Path, Path]:
    payload_root = root / "payload"
    executable = payload_root / "endpoint-agent" / "endpoint-agent"
    runtime = payload_root / "endpoint-agent" / "_internal" / "runtime.dat"
    runtime.parent.mkdir(parents=True)
    executable.write_bytes(b"#!/bin/sh\nexit 0\n")
    executable.chmod(0o755)
    runtime.write_bytes(b"runtime-fixture\n")
    runtime.chmod(0o644)
    inner_manifest = {
        "files": [
            {
                "mode": "0644",
                "path": "endpoint-agent/_internal/runtime.dat",
                "sha256": hashlib.sha256(runtime.read_bytes()).hexdigest(),
            },
            {
                "mode": "0755",
                "path": "endpoint-agent/endpoint-agent",
                "sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
            },
        ],
        "schema_version": 1,
        "source_revision": "967fa56",
        "version": "3.1.76",
    }
    (payload_root / "manifest.json").write_text(
        json.dumps(inner_manifest, sort_keys=True) + "\n", encoding="utf-8"
    )
    archive = root / "endpoint-agent-linux_amd64-3.1.76.tar.gz"

    def normalized_mode(info: tarfile.TarInfo) -> tarfile.TarInfo:
        info.mode = (
            0o755
            if info.isdir() or info.name == "endpoint-agent/endpoint-agent"
            else 0o644
        )
        return info

    with tarfile.open(archive, "w:gz") as bundle:
        for path in sorted(payload_root.rglob("*")):
            bundle.add(
                path,
                arcname=path.relative_to(payload_root).as_posix(),
                recursive=False,
                filter=normalized_mode,
            )
    sidecar = root / "endpoint-agent-linux_amd64-3.1.76.manifest.json"
    sidecar.write_text(
        json.dumps(
            {
                "archive_type": "tar.gz",
                "artifact_name": archive.name,
                "build_identifier": "endpoint-agent-linux_amd64-3.1.76",
                "channel": "stable",
                "platform": "linux_amd64",
                "schema_version": "endpoint_linux_agent_artifact_v1",
                "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
                "size": archive.stat().st_size,
                "source_revision": "967fa56",
                "version": "3.1.76",
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    launcher = root / "launcher"
    launcher.write_bytes(b"#!/bin/sh\nexit 0\n")
    launcher.chmod(0o755)
    return archive, sidecar, launcher


def _prepare_sources(
    tmp_path: Path, *, mutate_archive: bool = False
) -> subprocess.CompletedProcess[str]:
    archive, sidecar, launcher = _write_release_fixture(tmp_path)
    if mutate_archive:
        archive.write_bytes(archive.read_bytes() + b"tampered")
    output = tmp_path / "output"
    return subprocess.run(
        [
            "bash",
            BUILD.as_posix(),
            "--release-archive",
            archive.as_posix(),
            "--release-manifest",
            sidecar.as_posix(),
            "--launcher",
            launcher.as_posix(),
            "--output",
            output.as_posix(),
            "--prepare-only",
        ],
        cwd=ROOT,
        env={**os.environ, "PYTHON": sys.executable},
        check=False,
        capture_output=True,
        text=True,
    )


def test_prepare_only_accepts_the_task8_archive_and_rejects_changed_bytes(
    tmp_path: Path,
) -> None:
    """Skipping the Task 8 sidecar check could package substituted release bytes."""
    accepted = _prepare_sources(tmp_path / "accepted")
    rejected = _prepare_sources(tmp_path / "rejected", mutate_archive=True)

    assert accepted.returncode == 0, accepted.stderr
    assert "prepared=" in accepted.stdout
    assert rejected.returncode != 0
    assert "release archive digest mismatch" in rejected.stderr


def test_rpm_payload_is_limited_to_program_units_and_nonsecret_runtime_scaffolding() -> (
    None
):
    """Owning enrollment inputs would leak or delete device-specific state."""
    spec = _text(SPEC)

    for forbidden in (
        "/etc/endpoint-agent/config.yaml",
        "/etc/endpoint-agent/ca.crt",
        "/etc/endpoint-agent/provisioning-claim",
        "/var/lib/endpoint-agent/device-credential",
        "/var/lib/endpoint-agent/enrollment-identity.json",
        "BEGIN PRIVATE KEY",
    ):
        assert forbidden not in spec
    for required in (
        "/opt/endpoint-agent/launcher",
        "/opt/endpoint-agent/versions/%{version}/endpoint-agent/endpoint-agent",
        "/usr/lib/systemd/system/endpoint-agent.service",
        "/usr/lib/systemd/system/endpoint-agent-update.service",
        "/usr/lib/systemd/system/endpoint-agent-update.path",
        "/usr/lib/endpoint-agent/apply-pending-alt-update",
    ):
        assert required in spec


def test_service_requires_config_ca_and_durable_credential_or_loaded_claim() -> None:
    """A package install must not start an unconfigured or unauthenticated agent."""
    service = _text(SERVICE)

    assert (
        "LoadCredential=endpoint-agent-config:/etc/endpoint-agent/config.yaml"
        in service
    )
    assert "LoadCredential=endpoint-agent-ca:/etc/endpoint-agent/ca.crt" in service
    assert "LoadCredential=endpoint-enrollment-claim" in service
    assert "LoadCredential=endpoint-enrollment-claim:/" not in service
    assert "ExecCondition=/usr/lib/endpoint-agent/check-start-prerequisites" in service
    assert "ExecStart=/opt/endpoint-agent/launcher " in service
    assert "/versions/" not in service


def test_service_account_is_nonlogin_and_reused_without_password_material() -> None:
    """A login-capable or password-bearing package account widens host access."""
    spec = _text(SPEC)

    assert "getent group endpoint-agent" in spec
    assert "groupadd -r endpoint-agent" in spec
    assert "getent passwd endpoint-agent" in spec
    assert (
        "useradd -r -g endpoint-agent -d /nonexistent -s /sbin/nologin endpoint-agent"
        in spec
    )
    for password_mutation in ("chpasswd", "useradd -p", "useradd --password"):
        assert password_mutation not in spec.lower()


def test_upgrade_advances_only_an_rpm_owned_selection_before_validated_restart() -> (
    None
):
    """Erasing a selected old RPM release would leave current.json dangling."""
    spec = _text(SPEC)

    assert (
        "if [ ! -e /opt/endpoint-agent/current.json ] "
        "&& [ ! -L /opt/endpoint-agent/current.json ]; then"
    ) in spec
    assert "--print-selected-version" in spec
    assert "/usr/lib/endpoint-agent/package-releases/%{version}" in spec
    assert (
        'if [ -f "/usr/lib/endpoint-agent/package-releases/$selected_version" ]' in spec
    )
    assert "check-start-prerequisites --allow-unconfigured" in spec
    assert "systemctl try-restart endpoint-agent.service" in spec
    assert spec.index("check-start-prerequisites --allow-unconfigured") < spec.index(
        "systemctl try-restart endpoint-agent.service"
    )
    assert "LoadCredential=endpoint-enrollment-claim:/" not in _text(SERVICE)


def test_uninstall_preserves_identity_credentials_configuration_and_ca() -> None:
    """Ordinary RPM removal must never silently purge endpoint identity or trust."""
    spec = _text(SPEC)

    assert "systemctl disable --now endpoint-agent.service" in spec
    assert "systemctl disable --now endpoint-agent-update.path" in spec
    for preserved in (
        "/var/lib/endpoint-agent",
        "/etc/endpoint-agent",
    ):
        assert f"rm -rf {preserved}" not in spec
        assert f"%dir {preserved}" not in spec
    assert "%ghost /var/lib/endpoint-agent" not in spec
    assert "%ghost /etc/endpoint-agent" not in spec


def test_tmpfiles_and_logrotate_do_not_own_or_expose_device_secrets() -> None:
    """Runtime directory management must not create credential placeholders or broad modes."""
    tmpfiles = _text(TMPFILES)
    logrotate = _text(LOGROTATE)

    assert tmpfiles.splitlines() == [
        "d /etc/endpoint-agent 0755 root root - -",
        "d /var/lib/endpoint-agent 0750 endpoint-agent endpoint-agent - -",
        "d /var/log/endpoint-agent 0750 endpoint-agent endpoint-agent - -",
    ]
    assert "credential" not in tmpfiles
    assert "claim" not in tmpfiles
    assert "/var/log/endpoint-agent/*.log" in logrotate
    assert "su endpoint-agent endpoint-agent" in logrotate
    assert "create 0600 endpoint-agent endpoint-agent" in logrotate
    spec = _text(SPEC)
    assert "/usr/bin/systemd-tmpfiles" not in spec
    assert "check-start-prerequisites --prepare-directories" in spec


def test_signing_is_external_and_private_keys_are_rejected_from_sources() -> None:
    """An in-repository signing key would make every package provenance claim unsafe."""
    readme = _text(README)

    assert "rpm --addsign" in readme
    assert "external" in readme.lower()
    assert "private key" in readme.lower()
    for source in PACKAGE_ROOT.rglob("*"):
        if source.is_file():
            payload = source.read_bytes()
            assert (
                re.search(
                    rb"-----BEGIN (?:RSA )?PRIVATE KEY-----\s+"
                    rb"[A-Za-z0-9+/=\r\n]{32,}"
                    rb"-----END (?:RSA )?PRIVATE KEY-----",
                    payload,
                )
                is None
            )


def test_lifecycle_harness_uses_private_mounts_and_checks_preserved_state() -> None:
    """A lifecycle check against live fixed paths could mutate the accepted pilot."""
    harness = _text(LIFECYCLE_HARNESS)

    for required in (
        "sudo --non-interactive bwrap --unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--tmpfs /opt",
        "--tmpfs /etc/endpoint-agent",
        "--tmpfs /var/lib/endpoint-agent",
        'rpm --dbpath "$database" -Uvh --nodeps',
        'rpm --dbpath "$database" -e endpoint-agent',
        "identity-preserved-after-upgrade",
        "state-preserved-after-uninstall",
    ):
        assert required in harness


@pytest.mark.skipif(os.name == "nt", reason="RPM inspection runs on the ALT worker")
def test_built_rpm_contains_only_the_approved_absolute_paths() -> None:
    """The real RPM file list must not gain device-specific or mutable selector paths."""
    rpm_path = os.environ.get("ENDPOINT_AGENT_TEST_RPM")
    if not rpm_path:
        pytest.skip("set ENDPOINT_AGENT_TEST_RPM to inspect a built ALT RPM")
    result = subprocess.run(
        ["rpm", "-qpl", rpm_path], check=True, capture_output=True, text=True
    )
    paths = set(result.stdout.splitlines())
    assert "/opt/endpoint-agent/launcher" in paths
    assert "/opt/endpoint-agent/current.json" not in paths
    assert not {
        "/etc/endpoint-agent/config.yaml",
        "/etc/endpoint-agent/ca.crt",
        "/etc/endpoint-agent/provisioning-claim",
        "/var/lib/endpoint-agent/device-credential",
        "/var/lib/endpoint-agent/enrollment-identity.json",
    }.intersection(paths)
