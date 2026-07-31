"""ALT launcher selection and rollback contracts."""

from __future__ import annotations

import json
from pathlib import Path

from pc_agent.alt_update_installer import apply_alt_update
from pc_agent.launcher import launcher_main


def test_explicit_alt_mode_selects_immutable_pending_path_and_installer(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("ENDPOINT_AGENT_ALT_UPDATE_MODE", "1")

    pending_path, installer = launcher_main.select_update_installation(
        data_root=tmp_path
    )

    assert pending_path == tmp_path / "updates" / "pending_alt_update.json"
    assert installer is apply_alt_update


def test_alt_crash_rollback_preserves_strict_selector_schema(tmp_path: Path) -> None:
    install_root = tmp_path / "install"
    current_path = install_root / "current.json"
    manifest_path = install_root / "versions" / "3.1.76" / "manifest.json"
    manifest_path.parent.mkdir(parents=True)
    manifest_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "source_revision": "deadbeef",
                "version": "3.1.76",
                "files": [],
            }
        ),
        encoding="utf-8",
    )
    current_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "source_revision": "feedface",
                "version": "3.1.77-rc.1",
            }
        ),
        encoding="utf-8",
    )

    launcher_main.rollback_alt_current_version(
        current_path, crashed_version="3.1.77-rc.1", fallback_version="3.1.76"
    )

    assert json.loads(current_path.read_text(encoding="utf-8")) == {
        "schema_version": 1,
        "source_revision": "deadbeef",
        "version": "3.1.76",
    }


def test_alt_agent_defers_a_durable_pending_update_to_the_privileged_worker(
    monkeypatch, tmp_path: Path
) -> None:
    """The service account must never try to publish into root-owned /opt."""
    monkeypatch.setenv("ENDPOINT_AGENT_ALT_UPDATE_MODE", "1")
    pending = tmp_path / "updates" / "pending_alt_update.json"
    pending.parent.mkdir(parents=True)
    pending.write_text("{}", encoding="utf-8")

    assert launcher_main.pending_update_requires_privileged_worker(
        data_root=tmp_path
    ) is True


def test_privileged_alt_worker_applies_once_without_spawning_the_agent(
    monkeypatch, tmp_path: Path
) -> None:
    """Worker mode has one responsibility: consume the durable pending record."""
    pending = tmp_path / "updates" / "pending_alt_update.json"
    pending.parent.mkdir(parents=True)
    pending.write_text("{}", encoding="utf-8")
    applied: list[tuple[Path, Path, Path]] = []

    def fake_apply(install_root: Path, data_root: Path, pending_path: Path) -> tuple[bool, str]:
        applied.append((install_root, data_root, pending_path))
        return True, "3.1.79"

    monkeypatch.setattr(launcher_main, "apply_alt_update", fake_apply)

    assert launcher_main.apply_pending_alt_update_as_worker(
        install_root=tmp_path / "install", data_root=tmp_path
    ) == (True, "3.1.79")
    assert applied == [(tmp_path / "install", tmp_path, pending)]
