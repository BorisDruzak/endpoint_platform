"""Tests for the read-only installed ALT agent canary preflight."""

from __future__ import annotations

import json
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

import tools.canary.verify_installed_alt_agent as preflight
from tools.canary.evidence_models import CanaryEvidenceError, validate_evidence_payload
from tools.canary.verify_installed_alt_agent import (
    CanaryPreflightError,
    _regular_file,
    validate_release_selector,
    validate_service_unit,
)


_GOOD_UNIT = """[Service]
User=endpoint-agent
Group=endpoint-agent
ExecStart=/opt/endpoint-agent/launcher --no-gui --transport-mode gateway_wss --no-migration-http-pull-fallback --data-dir /var/lib/endpoint-agent --install-root /opt/endpoint-agent
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict
"""

_GOOD_WRAPPER_UNIT = _GOOD_UNIT.replace(
    "/opt/endpoint-agent/launcher --no-gui --transport-mode gateway_wss --no-migration-http-pull-fallback --data-dir /var/lib/endpoint-agent --install-root /opt/endpoint-agent",
    "/usr/lib/endpoint-agent/start-endpoint-agent",
)
_GOOD_WRAPPER = """#!/usr/bin/python3
CHECKER = Path(\"/usr/lib/endpoint-agent/check-start-prerequisites\")
LAUNCHER = Path(\"/opt/endpoint-agent/launcher\")
os.execv(LAUNCHER, [str(LAUNCHER), \"--no-gui\", \"--transport-mode\", \"gateway_wss\", \"--no-migration-http-pull-fallback\", \"--data-dir\", \"/var/lib/endpoint-agent\", \"--install-root\", \"/opt/endpoint-agent\"])
"""


@pytest.mark.parametrize(
    "unsafe_fragment",
    [
        "--transport-mode gateway_http_pull",
        "--migration-http-pull-fallback",
        "pc_agent.ws_agent",
        "https://helpdesk.example.test",
    ],
)
def test_service_unit_rejects_non_headless_or_fallback_configuration(
    unsafe_fragment: str,
) -> None:
    with pytest.raises(CanaryPreflightError):
        validate_service_unit(_GOOD_UNIT.replace("--no-migration-http-pull-fallback", unsafe_fragment))


def test_service_unit_accepts_the_immutable_wss_launcher_contract() -> None:
    assert validate_service_unit(_GOOD_UNIT) == {
        "user": "endpoint-agent",
        "group": "endpoint-agent",
        "restart": "on-failure",
        "no_new_privileges": True,
        "protect_system": "strict",
    }


def test_service_unit_accepts_the_reviewed_rpm_start_wrapper(tmp_path: Path) -> None:
    wrapper = tmp_path / "start-endpoint-agent"
    wrapper.write_text(_GOOD_WRAPPER, encoding="utf-8")

    assert validate_service_unit(_GOOD_WRAPPER_UNIT, start_wrapper=wrapper) == {
        "user": "endpoint-agent",
        "group": "endpoint-agent",
        "restart": "on-failure",
        "no_new_privileges": True,
        "protect_system": "strict",
    }


def test_regular_file_reports_protected_state_without_a_traceback(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    protected = tmp_path / "device-credential"
    protected.write_text("secret", encoding="utf-8")

    def _deny(_self: Path):
        raise PermissionError("denied")

    monkeypatch.setattr(Path, "lstat", _deny)
    with pytest.raises(CanaryPreflightError, match="unreadable"):
        _regular_file(protected, name="device-credential")


def test_release_selector_requires_expected_revision_and_regular_launcher(
    tmp_path: Path,
) -> None:
    install_root = tmp_path / "opt" / "endpoint-agent"
    release = install_root / "versions" / "3.1.99"
    release.mkdir(parents=True)
    launcher = install_root / "launcher"
    launcher.write_text("#!/bin/sh\n", encoding="utf-8")
    (release / "launcher").write_text("#!/bin/sh\n", encoding="utf-8")
    (release / "manifest.json").write_text("{}", encoding="utf-8")
    (install_root / "current.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "version": "3.1.99",
                "source_revision": "a" * 40,
            }
        ),
        encoding="utf-8",
    )

    assert validate_release_selector(install_root, "a" * 40) == {
        "version": "3.1.99",
        "source_revision": "a" * 40,
    }

    with pytest.raises(CanaryPreflightError, match="source revision"):
        validate_release_selector(install_root, "b" * 40)


def test_release_selector_accepts_the_packaged_pyinstaller_executable(tmp_path: Path) -> None:
    install_root = tmp_path / "opt" / "endpoint-agent"
    release = install_root / "versions" / "3.2.30"
    executable = release / "endpoint-agent" / "endpoint-agent"
    executable.parent.mkdir(parents=True)
    (install_root / "launcher").write_text("#!/bin/sh\n", encoding="utf-8")
    executable.write_text("binary", encoding="utf-8")
    (release / "manifest.json").write_text("{}", encoding="utf-8")
    (install_root / "current.json").write_text(
        json.dumps({"schema_version": 1, "version": "3.2.30", "source_revision": "c" * 40}),
        encoding="utf-8",
    )

    assert validate_release_selector(install_root, "c" * 40) == {
        "version": "3.2.30",
        "source_revision": "c" * 40,
    }


def test_collect_preflight_projects_protected_credential_state_without_naming_it(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    data_root = tmp_path / "data"
    data_root.mkdir()
    for name in ("device-credential", "enrollment-identity.json"):
        item = data_root / name
        item.write_text("not inspected", encoding="utf-8")
        item.chmod(0o600)

    monkeypatch.setattr(preflight, "_run", lambda _command: "")
    monkeypatch.setattr(preflight, "validate_service_unit", lambda _unit: {"user": "endpoint-agent"})
    monkeypatch.setattr(
        preflight,
        "validate_release_selector",
        lambda _root, _revision: {"version": "3.2.30", "source_revision": "c" * 40},
    )
    monkeypatch.setattr(preflight, "_verify_origin", lambda _origin, _ca: {"strict_tls": "passed"})
    monkeypatch.setattr(
        Path,
        "stat",
        lambda _self: SimpleNamespace(st_mode=stat.S_IFREG | 0o600),
    )

    payload = preflight.collect_preflight(
        expected_endpoint_origin="https://endpoint-staging.sosnadmin.local",
        expected_source_revision="c" * 40,
        service_unit="endpoint-agent.service",
        install_root=tmp_path / "install",
        config_root=tmp_path / "config",
        data_root=data_root,
    )

    assert payload["local_state"] == {"data_root": "present", "state_metadata": "protected"}
    validate_evidence_payload(
        payload,
        allowed_keys=frozenset({"schema_version", "service", "release", "local_state", "network"}),
    )


def test_evidence_rejects_secrets_and_unknown_fields() -> None:
    safe = {"schema_version": "endpoint_diagnostic_canary_v1", "status": "ready"}
    validate_evidence_payload(safe, allowed_keys=frozenset(safe))

    with pytest.raises(CanaryEvidenceError, match="forbidden"):
        validate_evidence_payload(
            {"schema_version": "endpoint_diagnostic_canary_v1", "token": "secret"},
            allowed_keys=frozenset({"schema_version", "token"}),
        )
    with pytest.raises(CanaryEvidenceError, match="unexpected"):
        validate_evidence_payload(
            {"schema_version": "endpoint_diagnostic_canary_v1", "extra": True},
            allowed_keys=frozenset({"schema_version"}),
        )
