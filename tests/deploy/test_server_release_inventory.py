"""Inventory keeps deployment rollback and review decisions explicit."""

import json
from pathlib import Path
import subprocess
import sys

import pytest

from tools.release import inventory_deployments


CURRENT = "endpoint-platform-aabbccddeeff-setup205-observer"
PREVIOUS = "endpoint-platform-112233445566"
OTHER = "endpoint-platform-001122334455"


@pytest.fixture
def deployment(tmp_path):
    releases = tmp_path / "releases"
    for name in (CURRENT, PREVIOUS, OTHER):
        (releases / name / "nested").mkdir(parents=True)
        (releases / name / "nested" / "content").write_bytes(b"payload")
    (tmp_path / "current").symlink_to(Path("releases") / CURRENT, target_is_directory=True)
    previous = tmp_path / "previous-release"
    previous.write_text(str(releases / PREVIOUS) + "\n", encoding="utf-8", newline="\n")
    return releases, tmp_path / "current", previous


def test_inventory_protects_current_previous_and_pins(deployment):
    releases, current, previous = deployment
    (releases / "upload.tmp").write_bytes(b"upload")
    (releases / OTHER / "outside").symlink_to(previous)
    report = inventory_deployments.read_inventory(releases, current, previous, pins=[OTHER])
    assert report["unclassified_entries"] == ["upload.tmp"]
    entries = {row["name"]: row for row in report["releases"]}
    assert entries[CURRENT]["protected_by"] == ["current"]
    assert entries[PREVIOUS]["protected_by"] == ["previous"]
    assert entries[OTHER]["protected_by"] == ["pin"]
    assert entries[OTHER]["regular_file_bytes"] == 7
    assert entries[OTHER]["unmeasured_entries"] == 1
    assert 0 <= report["volume_free_bytes"] <= report["volume_total_bytes"]
    assert (releases / OTHER / "outside").is_symlink()


def test_inventory_rejects_pointer_through_release_alias(deployment):
    releases, current, previous = deployment
    alias = releases / "endpoint-platform-ffffffffffff"
    alias.symlink_to(releases / PREVIOUS, target_is_directory=True)
    previous.write_text(str(alias))
    with pytest.raises(ValueError, match="physical release directory"):
        inventory_deployments.read_inventory(releases, current, previous)


def test_initial_install_has_no_rollback_marker(deployment):
    releases, current, previous = deployment
    previous.unlink()
    report = inventory_deployments.read_inventory(releases, current, previous)
    assert report["previous"] is None
    assert {row["name"]: row["protected_by"] for row in report["releases"]} == {
        CURRENT: ["current"], PREVIOUS: [], OTHER: [],
    }


def test_inventory_fails_when_entry_budget_is_exhausted(deployment, monkeypatch):
    monkeypatch.setattr(inventory_deployments, "_MAX_ENTRIES", 2)
    with pytest.raises(ValueError, match="inventory limit"):
        inventory_deployments.read_inventory(*deployment)


def test_inventory_cli_emits_a_read_only_report(deployment):
    releases, current, previous = deployment
    command = [
        sys.executable, "-m", "tools.release.inventory_deployments",
        "--releases-root", str(releases), "--current", str(current),
        "--previous-release", str(previous), "--pin", OTHER,
    ]
    result = subprocess.run(command, check=True, capture_output=True, text=True, timeout=15)
    report = json.loads(result.stdout)
    assert report["current"] == CURRENT
    assert report["previous"] == PREVIOUS
    assert current.is_symlink()
    assert (releases / OTHER / "nested" / "content").read_bytes() == b"payload"


def test_inventory_rejects_changed_rollback_marker(deployment, monkeypatch):
    releases, current, previous = deployment
    scan = inventory_deployments._measure

    def change_marker(*args):
        previous.write_text(str(releases / OTHER))
        return scan(*args)

    monkeypatch.setattr(inventory_deployments, "_measure", change_marker)
    with pytest.raises(ValueError, match="deployment pointers changed"):
        inventory_deployments.read_inventory(releases, current, previous)


def test_inventory_protects_staged_commit_variants_and_running_processes(deployment):
    releases, current, previous = deployment
    variant = OTHER + "-candidate"
    (releases / variant).mkdir()
    staged = releases.parent / "release-commit"
    staged.write_bytes(b"001122334455\n")
    proc = releases.parent / "proc"
    process = proc / "73"
    (process / "fd").mkdir(parents=True)
    (process / "cwd").symlink_to(releases / CURRENT, target_is_directory=True)
    (process / "exe").symlink_to(releases / CURRENT / "nested/content")
    (process / "maps").write_text(f"0-1 r--p 00000000 00:00 1 {releases / variant / 'lib.so'}\n")
    (process / "fd/3").symlink_to(releases / PREVIOUS / "nested/content")
    report = inventory_deployments.read_inventory(releases, current, previous, staged=staged, proc=proc)
    assert report["process_scan_incomplete_pids"] == []
    entries = {row["name"]: row for row in report["releases"]}
    assert entries[CURRENT]["protected_by"] == ["current", "process"]
    assert entries[PREVIOUS]["protected_by"] == ["previous", "process"]
    assert entries[OTHER]["protected_by"] == ["staged"]
    assert entries[variant]["protected_by"] == ["staged", "process"]
    assert entries[variant]["process_ids"] == [73]


def test_inventory_reports_inaccessible_process_evidence(deployment, monkeypatch):
    releases, current, previous = deployment
    proc = releases.parent / "proc"
    process = proc / "73"
    process.mkdir(parents=True)
    original = Path.readlink

    def readlink(path):
        if path == process / "cwd":
            raise PermissionError(path)
        return original(path)

    monkeypatch.setattr(Path, "readlink", readlink)
    report = inventory_deployments.read_inventory(releases, current, previous, proc=proc)
    assert report["process_scan_incomplete_pids"] == [73]


def test_inventory_follows_release_dependencies_from_protected_roots(deployment):
    releases, current, previous = deployment
    library = "endpoint-platform-a1a2a3a4a5a6"
    (releases / library).mkdir()
    (releases / CURRENT / "venv").symlink_to(Path("..") / OTHER, target_is_directory=True)
    (releases / OTHER / "shared").symlink_to(releases / library, target_is_directory=True)
    (releases / library / "cycle").symlink_to(releases / OTHER, target_is_directory=True)

    report = inventory_deployments.read_inventory(releases, current, previous)
    rows = {row["name"]: row for row in report["releases"]}
    assert rows[CURRENT]["release_dependencies"] == [OTHER]
    assert rows[OTHER]["protected_by"] == ["release_dependency"]
    assert rows[library]["protected_by"] == ["release_dependency"]
    assert rows[OTHER]["unmeasured_entries"] == 1
    assert rows[PREVIOUS]["release_dependencies"] == []


def test_inventory_reports_dangling_release_target(deployment):
    releases, current, previous = deployment
    missing = "endpoint-platform-abcdefabcdef"
    (releases / PREVIOUS / "venv").symlink_to(releases / missing / "venv", target_is_directory=True)

    report = inventory_deployments.read_inventory(releases, current, previous)
    rows = {row["name"]: row for row in report["releases"]}
    assert rows[PREVIOUS]["release_dependencies"] == [missing]
    assert report["missing_release_dependencies"] == [missing]
