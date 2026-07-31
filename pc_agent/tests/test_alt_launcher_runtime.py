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
