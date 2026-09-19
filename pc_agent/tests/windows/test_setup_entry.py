"""One-file Windows Setup entrypoint boundaries."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pc_agent.platform.windows import setup_entry
from pc_agent.windows_setup import SetupOutcome


def _write_public_payload(root: Path) -> None:
    (root / "EndpointAgent.msi").write_bytes(b"msi")
    (root / "endpoint-ca.crt").write_text("public CA", encoding="ascii")
    (root / "setup-config.json").write_text(
        json.dumps(
            {
                "schema_version": "endpoint_windows_setup_config_v1",
                "endpoint_origin": "https://endpoint.sosnadmin.local",
                "installer_version": "1.0.0",
                "installer_release_id": "1.0.0",
            }
        ),
        encoding="utf-8",
    )


def test_setup_entry_installs_embedded_msi_before_enrollment(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _write_public_payload(tmp_path)
    order: list[str] = []
    observed_config: list[object] = []

    monkeypatch.setattr(setup_entry, "_resource_root", lambda: tmp_path)
    monkeypatch.setattr(
        setup_entry,
        "_install_embedded_msi",
        lambda path: order.append(path.name),
    )
    monkeypatch.setattr(
        setup_entry,
        "_installed_provisioner",
        lambda: tmp_path / "endpoint-agent-provision.exe",
    )
    monkeypatch.setattr(setup_entry, "HttpsSetupTransport", lambda *_: object())

    class _Setup:
        def __init__(self, config: object, **_: object) -> None:
            observed_config.append(config)
            self.installation_id_factory = lambda: "win-test"

        def run(self) -> SetupOutcome:
            order.append("enrollment")
            return SetupOutcome("provisioned")

    monkeypatch.setattr(setup_entry, "UniversalWindowsSetup", _Setup)

    assert setup_entry.main(["--quiet"]) == 0
    assert order == ["EndpointAgent.msi", "enrollment"]
    assert observed_config[0].endpoint_origin == "https://endpoint.sosnadmin.local"


def test_setup_entry_rejects_config_that_contains_extra_material(tmp_path: Path) -> None:
    _write_public_payload(tmp_path)
    (tmp_path / "setup-config.json").write_text(
        json.dumps(
            {
                "schema_version": "endpoint_windows_setup_config_v1",
                "endpoint_origin": "https://endpoint.sosnadmin.local",
                "installer_version": "1.0.0",
                "installer_release_id": "1.0.0",
                "unexpected": "not allowed",
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="configuration is invalid"):
        setup_entry._read_public_setup_config(tmp_path / "setup-config.json")
