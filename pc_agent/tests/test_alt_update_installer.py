"""Immutable ALT update bundle application contracts."""

from __future__ import annotations

import hashlib
import io
import json
import os
import tarfile
from pathlib import Path

import pytest

from pc_agent import alt_update_installer
from pc_agent.alt_update_installer import apply_alt_update


_OPERATION_ID = "caa31a48-bf2f-4f1c-8b77-d1be77e12b4e"


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _write_bundle(
    path: Path,
    *,
    version: str = "3.1.77-rc.1",
    source_revision: str = "feedface",
    corrupt_manifest: bool = False,
    layout: str = "legacy",
    mode_overrides: dict[str, int] | None = None,
) -> None:
    if layout == "legacy":
        files = {
            "launcher": (b"launcher", 0o755),
            "pc_agent/pc_agent": (b"agent", 0o755),
        }
    elif layout == "headless":
        files = {
            "endpoint-agent/_internal/runtime.dat": (b"runtime", 0o644),
            "endpoint-agent/endpoint-agent": (b"headless", 0o755),
        }
    elif layout == "mixed":
        files = {
            "launcher": (b"launcher", 0o755),
            "pc_agent/pc_agent": (b"agent", 0o755),
            "endpoint-agent/endpoint-agent": (b"headless", 0o755),
        }
    else:
        raise AssertionError("unknown fixture layout")
    if mode_overrides:
        files = {
            name: (value, mode_overrides.get(name, mode))
            for name, (value, mode) in files.items()
        }
    manifest_files = [
        {
            "path": name,
            "sha256": "0" * 64
            if corrupt_manifest and name == "pc_agent/pc_agent"
            else _sha256(value),
            "mode": f"{mode:04o}",
        }
        for name, (value, mode) in sorted(files.items())
    ]
    manifest = json.dumps(
        {
            "schema_version": 1,
            "version": version,
            "source_revision": source_revision,
            "files": manifest_files,
        },
        separators=(",", ":"),
    ).encode()
    with tarfile.open(path, "w:gz") as archive:
        for name, (value, mode) in sorted(files.items()):
            info = tarfile.TarInfo(name)
            info.size = len(value)
            info.mode = mode
            archive.addfile(info, io.BytesIO(value))
        info = tarfile.TarInfo("manifest.json")
        info.size = len(manifest)
        info.mode = 0o644
        archive.addfile(info, io.BytesIO(manifest))


def test_headless_alt_update_selects_task8_layout_without_replacing_stable_launcher(
    tmp_path: Path,
) -> None:
    """Requiring a launcher inside every release would reject the Task 8 artifact."""
    install_root, data_root = tmp_path / "install", tmp_path / "data"
    _initial_selector(install_root)
    stable_launcher = install_root / "launcher"
    stable_launcher.write_bytes(b"stable-launcher")
    artifact = data_root / "updates" / "downloads" / "candidate.tar.gz"
    artifact.parent.mkdir(parents=True)
    _write_bundle(artifact, layout="headless")

    ok, version = apply_alt_update(
        install_root, data_root, _pending(data_root, artifact)
    )

    assert (ok, version) == (True, "3.1.77-rc.1")
    selected = install_root / "versions" / "3.1.77-rc.1"
    assert (selected / "endpoint-agent" / "endpoint-agent").read_bytes() == b"headless"
    assert stable_launcher.read_bytes() == b"stable-launcher"
    assert json.loads((install_root / "current.json").read_text(encoding="utf-8")) == {
        "schema_version": 1,
        "source_revision": "feedface",
        "version": "3.1.77-rc.1",
    }


def test_alt_update_rejects_a_mixed_legacy_and_headless_release_shape(
    tmp_path: Path,
) -> None:
    """A mixed tree must not let the launcher select an unintended entrypoint."""
    install_root, data_root = tmp_path / "install", tmp_path / "data"
    _initial_selector(install_root)
    artifact = data_root / "updates" / "downloads" / "candidate.tar.gz"
    artifact.parent.mkdir(parents=True)
    _write_bundle(artifact, layout="mixed")

    ok, _ = apply_alt_update(install_root, data_root, _pending(data_root, artifact))

    assert ok is False
    assert (
        json.loads((install_root / "current.json").read_text(encoding="utf-8"))[
            "version"
        ]
        == "3.1.76"
    )
    assert not (install_root / "versions" / "3.1.77-rc.1").exists()


def _pending(
    data_root: Path,
    artifact: Path,
    *,
    version: str = "3.1.77-rc.1",
    operation_id: str = _OPERATION_ID,
) -> Path:
    payload = {
        "archive_type": "tar.gz",
        "artifact_path": str(artifact),
        "channel": "canary",
        "operation_id": operation_id,
        "requested_by": "gateway",
        "requested_reason": "scheduled_rollout",
        "sha256": _sha256(artifact.read_bytes()),
        "size": artifact.stat().st_size,
        "target": "linux_amd64",
        "version": version,
    }
    path = data_root / "updates" / "pending_alt_update.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")
    if os.name != "nt":
        path.chmod(0o600)
    return path


@pytest.mark.parametrize(
    ("payload_path", "mode"),
    [
        ("endpoint-agent/_internal/runtime.dat", 0o666),
        ("endpoint-agent/endpoint-agent", 0o777),
        ("endpoint-agent/_internal/runtime.dat", 0o757),
        ("endpoint-agent/endpoint-agent", 0o644),
    ],
)
def test_alt_update_rejects_unsafe_or_noncanonical_payload_modes_before_publication(
    tmp_path: Path, payload_path: str, mode: int
) -> None:
    install_root, data_root = tmp_path / "install", tmp_path / "data"
    _initial_selector(install_root)
    artifact = data_root / "updates" / "downloads" / "candidate.tar.gz"
    artifact.parent.mkdir(parents=True)
    _write_bundle(
        artifact,
        layout="headless",
        mode_overrides={payload_path: mode},
    )

    ok, _ = apply_alt_update(install_root, data_root, _pending(data_root, artifact))

    assert ok is False
    assert json.loads((install_root / "current.json").read_text())["version"] == "3.1.76"
    assert not (install_root / "versions" / "3.1.77-rc.1").exists()


def test_invalid_pending_leaf_is_consumed_when_failure_destination_is_a_directory(
    tmp_path: Path,
) -> None:
    install_root, data_root = tmp_path / "install", tmp_path / "data"
    _initial_selector(install_root)
    updates = data_root / "updates"
    updates.mkdir(parents=True)
    pending = updates / "pending_alt_update.json"
    pending.mkdir()
    failure = updates / "last_failed_alt_update.json"
    failure.mkdir()

    ok, _ = apply_alt_update(install_root, data_root, pending)

    assert ok is False
    assert not pending.exists()
    assert failure.is_file() and not failure.is_symlink()
    assert json.loads(failure.read_text())["reason"] == "invalid_alt_pending_update"


def test_update_history_symlink_is_not_followed_or_incorporated(tmp_path: Path) -> None:
    install_root, data_root = tmp_path / "install", tmp_path / "data"
    _initial_selector(install_root)
    artifact = data_root / "updates" / "downloads" / "candidate.tar.gz"
    artifact.parent.mkdir(parents=True)
    _write_bundle(artifact, layout="headless")
    external = tmp_path / "external-history.json"
    external.write_text('[{"attacker":"history"}]')
    history = data_root / "updates" / "update_history.json"
    try:
        history.symlink_to(external)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")

    ok, _ = apply_alt_update(install_root, data_root, _pending(data_root, artifact))

    assert ok is True
    assert external.read_text() == '[{"attacker":"history"}]'
    assert history.is_file() and not history.is_symlink()
    assert json.loads(history.read_text()) == [
        {
            "operation_id": _OPERATION_ID,
            "previous_version": "3.1.76",
            "success": True,
            "version": "3.1.77-rc.1",
        }
    ]


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode recovery")
def test_update_recovers_a_valid_candidate_left_with_staging_directory_mode(
    tmp_path: Path,
) -> None:
    install_root, data_root = tmp_path / "install", tmp_path / "data"
    _initial_selector(install_root)
    artifact = data_root / "updates" / "downloads" / "candidate.tar.gz"
    artifact.parent.mkdir(parents=True)
    _write_bundle(artifact, layout="headless")
    target = install_root / "versions" / "3.1.77-rc.1"
    (target / "endpoint-agent" / "_internal").mkdir(parents=True)
    (target / "endpoint-agent" / "endpoint-agent").write_bytes(b"headless")
    (target / "endpoint-agent" / "endpoint-agent").chmod(0o755)
    (target / "endpoint-agent" / "_internal" / "runtime.dat").write_bytes(
        b"runtime"
    )
    (target / "endpoint-agent" / "_internal" / "runtime.dat").chmod(0o644)
    (target / "manifest.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "version": "3.1.77-rc.1",
                "source_revision": "feedface",
                "files": [
                    {
                        "path": "endpoint-agent/_internal/runtime.dat",
                        "sha256": _sha256(b"runtime"),
                        "mode": "0644",
                    },
                    {
                        "path": "endpoint-agent/endpoint-agent",
                        "sha256": _sha256(b"headless"),
                        "mode": "0755",
                    },
                ],
            },
            separators=(",", ":"),
        )
    )
    target.chmod(0o700)

    ok, version = apply_alt_update(install_root, data_root, _pending(data_root, artifact))

    assert (ok, version) == (True, "3.1.77-rc.1")
    assert json.loads((install_root / "current.json").read_text())["version"] == (
        "3.1.77-rc.1"
    )


def test_update_fsyncs_final_release_before_selector_and_retries_interruption(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    install_root, data_root = tmp_path / "install", tmp_path / "data"
    _initial_selector(install_root)
    artifact = data_root / "updates" / "downloads" / "candidate.tar.gz"
    artifact.parent.mkdir(parents=True)
    _write_bundle(artifact, layout="headless")
    pending = _pending(data_root, artifact)
    calls: list[Path] = []

    def interrupt_once(release: Path) -> None:
        calls.append(release)
        if release.name == "3.1.77-rc.1" and calls.count(release) == 1:
            raise OSError("simulated interruption after final release rename")

    monkeypatch.setattr(
        alt_update_installer, "_fsync_release_tree", interrupt_once, raising=False
    )

    assert apply_alt_update(install_root, data_root, pending)[0] is False
    assert pending.exists()
    assert json.loads((install_root / "current.json").read_text())["version"] == "3.1.76"
    assert apply_alt_update(install_root, data_root, pending) == (True, "3.1.77-rc.1")
    assert calls == [
        install_root / "versions" / "_alt_update_staging" / calls[0].name,
        install_root / "versions" / "3.1.77-rc.1",
        install_root / "versions" / "3.1.77-rc.1",
    ]


@pytest.mark.parametrize("commit_point", ["release_fsync", "parent_fsync", "selector"])
def test_durable_candidate_faults_preserve_pending_until_selector_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, commit_point: str
) -> None:
    """Each post-rename interruption must replay instead of archiving a valid request."""
    install_root, data_root = tmp_path / "install", tmp_path / "data"
    _initial_selector(install_root)
    artifact = data_root / "updates" / "downloads" / "candidate.tar.gz"
    artifact.parent.mkdir(parents=True)
    _write_bundle(artifact)
    pending = _pending(data_root, artifact)
    candidate = install_root / "versions" / "3.1.77-rc.1"
    interrupted = False

    if commit_point == "release_fsync":
        original = alt_update_installer._fsync_release_tree

        def fail_once(path: Path) -> None:
            nonlocal interrupted
            if path == candidate and not interrupted:
                interrupted = True
                raise OSError("injected release fsync failure")
            original(path)

        monkeypatch.setattr(alt_update_installer, "_fsync_release_tree", fail_once)
    elif commit_point == "parent_fsync":
        original = alt_update_installer._fsync_directory

        def fail_once(path: Path) -> None:
            nonlocal interrupted
            if path == candidate.parent and candidate.exists() and not interrupted:
                interrupted = True
                raise OSError("injected release-parent fsync failure")
            original(path)

        monkeypatch.setattr(alt_update_installer, "_fsync_directory", fail_once)
    else:
        original = alt_update_installer._write_selector

        def fail_once(path: Path, manifest: object) -> None:
            nonlocal interrupted
            if path.name == "current.json" and not interrupted:
                interrupted = True
                raise OSError("injected selector publication failure")
            original(path, manifest)

        monkeypatch.setattr(alt_update_installer, "_write_selector", fail_once)

    assert apply_alt_update(install_root, data_root, pending)[0] is False
    assert interrupted
    assert pending.exists()
    assert json.loads((install_root / "current.json").read_text()) == {
        "schema_version": 1,
        "source_revision": "deadbeef",
        "version": "3.1.76",
    }
    assert apply_alt_update(install_root, data_root, pending) == (True, "3.1.77-rc.1")


def test_staging_release_is_verified_before_rename(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    install_root, data_root = tmp_path / "install", tmp_path / "data"
    _initial_selector(install_root)
    artifact = data_root / "updates" / "downloads" / "candidate.tar.gz"
    artifact.parent.mkdir(parents=True)
    _write_bundle(artifact)
    verified_staging = False
    original_verify = alt_update_installer._verify_existing_release
    original_move = alt_update_installer.shutil.move

    def record_verified(path: Path, manifest: object) -> None:
        nonlocal verified_staging
        if "_alt_update_staging" in path.parts:
            verified_staging = True
        original_verify(path, manifest)

    def reject_unverified_move(source: str, destination: str) -> str:
        assert verified_staging
        return original_move(source, destination)

    monkeypatch.setattr(alt_update_installer, "_verify_existing_release", record_verified)
    monkeypatch.setattr(alt_update_installer.shutil, "move", reject_unverified_move)

    assert apply_alt_update(
        install_root, data_root, _pending(data_root, artifact)
    ) == (True, "3.1.77-rc.1")


def test_update_quarantines_incomplete_candidate_then_publishes_verified_bundle(
    tmp_path: Path,
) -> None:
    install_root, data_root = tmp_path / "install", tmp_path / "data"
    _initial_selector(install_root)
    artifact = data_root / "updates" / "downloads" / "candidate.tar.gz"
    artifact.parent.mkdir(parents=True)
    _write_bundle(artifact, layout="headless")
    target = install_root / "versions" / "3.1.77-rc.1"
    target.mkdir(parents=True)
    (target / "poisoned").write_text("incomplete", encoding="utf-8")

    assert apply_alt_update(
        install_root, data_root, _pending(data_root, artifact)
    ) == (True, "3.1.77-rc.1")
    assert (target / "endpoint-agent" / "endpoint-agent").read_bytes() == b"headless"
    assert any(
        candidate.is_dir() and (candidate / "poisoned").exists()
        for candidate in (install_root / "versions").glob(".rejected-3.1.77-rc.1.*")
    )


def test_pending_symlink_is_consumed_without_reading_its_target(tmp_path: Path) -> None:
    install_root, data_root = tmp_path / "install", tmp_path / "data"
    _initial_selector(install_root)
    updates = data_root / "updates"
    updates.mkdir(parents=True)
    external = tmp_path / "external-pending.json"
    external.write_text('{"attacker":true}', encoding="utf-8")
    pending = updates / "pending_alt_update.json"
    try:
        pending.symlink_to(external)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")

    ok, _ = apply_alt_update(install_root, data_root, pending)

    assert ok is False
    assert external.read_text(encoding="utf-8") == '{"attacker":true}'
    assert not pending.exists()
    assert (updates / "last_failed_alt_update.json").is_file()


def test_hostile_updates_parent_is_repaired_and_pending_is_terminal(
    tmp_path: Path,
) -> None:
    install_root, data_root = tmp_path / "install", tmp_path / "data"
    _initial_selector(install_root)
    data_root.mkdir()
    external = tmp_path / "external-updates"
    external.mkdir()
    updates = data_root / "updates"
    try:
        updates.symlink_to(external, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")

    ok, _ = apply_alt_update(install_root, data_root, updates / "pending_alt_update.json")

    assert ok is False
    assert updates.is_dir() and not updates.is_symlink()
    assert not list(external.iterdir())
    assert (updates / "last_failed_alt_update.json").is_file()


@pytest.mark.skipif(os.name == "nt", reason="POSIX FIFO semantics")
def test_history_fifo_is_quarantined_without_blocking_update(tmp_path: Path) -> None:
    install_root, data_root = tmp_path / "install", tmp_path / "data"
    _initial_selector(install_root)
    artifact = data_root / "updates" / "downloads" / "candidate.tar.gz"
    artifact.parent.mkdir(parents=True)
    _write_bundle(artifact)
    _pending(data_root, artifact)
    history = data_root / "updates" / "update_history.json"
    os.mkfifo(history)

    assert apply_alt_update(install_root, data_root, data_root / "updates" / "pending_alt_update.json") == (
        True,
        "3.1.77-rc.1",
    )
    assert history.is_file() and not history.is_symlink()


def _initial_selector(install_root: Path) -> None:
    (install_root / "versions" / "3.1.76" / "pc_agent").mkdir(parents=True)
    launcher = install_root / "versions" / "3.1.76" / "launcher"
    launcher.write_bytes(b"old-launcher")
    launcher.chmod(0o755)
    binary = install_root / "versions" / "3.1.76" / "pc_agent" / "pc_agent"
    binary.write_bytes(b"old-agent")
    binary.chmod(0o755)
    (install_root / "versions" / "3.1.76" / "manifest.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "version": "3.1.76",
                "source_revision": "deadbeef",
                "files": [
                    {
                        "path": "launcher",
                        "sha256": _sha256(b"old-launcher"),
                        "mode": "0755",
                    },
                    {
                        "path": "pc_agent/pc_agent",
                        "sha256": _sha256(b"old-agent"),
                        "mode": "0755",
                    },
                ],
            },
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    (install_root / "current.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "source_revision": "deadbeef",
                "version": "3.1.76",
            }
        ),
        encoding="utf-8",
    )


def test_valid_alt_update_preserves_selector_schema_and_prior_release(
    tmp_path: Path, monkeypatch
) -> None:
    install_root, data_root = tmp_path / "install", tmp_path / "data"
    _initial_selector(install_root)
    artifact = data_root / "updates" / "downloads" / "candidate.tar.gz"
    artifact.parent.mkdir(parents=True)
    _write_bundle(artifact)

    chmod_calls: list[tuple[Path, int]] = []
    original_chmod = alt_update_installer.os.chmod

    def capture_chmod(path: str | Path, mode: int) -> None:
        chmod_calls.append((Path(path), mode))
        original_chmod(path, mode)

    monkeypatch.setattr(alt_update_installer.os, "chmod", capture_chmod)

    ok, version = apply_alt_update(
        install_root, data_root, _pending(data_root, artifact)
    )

    assert (ok, version) == (True, "3.1.77-rc.1")
    assert json.loads((install_root / "current.json").read_text(encoding="utf-8")) == {
        "schema_version": 1,
        "source_revision": "feedface",
        "version": "3.1.77-rc.1",
    }
    assert (
        install_root / "versions" / "3.1.76" / "pc_agent" / "pc_agent"
    ).read_bytes() == b"old-agent"
    history = json.loads(
        (data_root / "updates" / "update_history.json").read_text(encoding="utf-8")
    )
    assert history == [
        {
            "operation_id": _OPERATION_ID,
            "previous_version": "3.1.76",
            "success": True,
            "version": "3.1.77-rc.1",
        }
    ]
    assert (install_root / "versions" / "3.1.77-rc.1", 0o755) in chmod_calls
    assert (
        install_root / "versions" / "3.1.77-rc.1" / "pc_agent",
        0o755,
    ) in chmod_calls
    assert json.loads((install_root / "previous.json").read_text(encoding="utf-8")) == {
        "schema_version": 1,
        "source_revision": "deadbeef",
        "version": "3.1.76",
    }


def _write_rollback_request(
    data_root: Path,
    *,
    crashed_version: str = "3.1.78",
    crashed_revision: str = "badheadless",
    rollback_version: str = "3.1.77",
    rollback_revision: str = "acceptedheadless",
) -> Path:
    request = data_root / "updates" / "rollback-request.json"
    request.parent.mkdir(parents=True, exist_ok=True)
    request.write_text(
        json.dumps(
            {
                "crashed_source_revision": crashed_revision,
                "crashed_version": crashed_version,
                "rollback_source_revision": rollback_revision,
                "rollback_version": rollback_version,
                "schema_version": "endpoint_alt_rollback_request_v1",
            },
            separators=(",", ":"),
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    request.chmod(0o600)
    return request


def _select_two_headless_releases(install_root: Path, data_root: Path) -> None:
    _initial_selector(install_root)
    for version, revision, name in (
        ("3.1.77", "acceptedheadless", "accepted.tar.gz"),
        ("3.1.78", "badheadless", "bad.tar.gz"),
    ):
        artifact = data_root / "updates" / "downloads" / name
        artifact.parent.mkdir(parents=True, exist_ok=True)
        _write_bundle(
            artifact, version=version, source_revision=revision, layout="headless"
        )
        ok, selected = apply_alt_update(
            install_root,
            data_root,
            _pending(data_root, artifact, version=version),
        )
        assert (ok, selected) == (True, version)


def test_root_worker_rolls_bad_headless_release_back_to_verified_previous_headless(
    tmp_path: Path,
) -> None:
    """A worker that trusts history or skips the release manifest can select bad code."""
    install_root, data_root = tmp_path / "install", tmp_path / "data"
    _select_two_headless_releases(install_root, data_root)
    request = _write_rollback_request(data_root)

    ok, version = alt_update_installer.apply_alt_rollback(install_root, data_root)

    assert (ok, version) == (True, "3.1.77")
    assert json.loads((install_root / "current.json").read_text(encoding="utf-8")) == {
        "schema_version": 1,
        "source_revision": "acceptedheadless",
        "version": "3.1.77",
    }
    assert not request.exists()
    assert not (install_root / "previous.json").exists()
    marker = json.loads(
        (data_root / "updates" / "last_failed_launch.json").read_text(encoding="utf-8")
    )
    assert marker == {
        "crashed_version": "3.1.78",
        "reason": "startup_crash_rollback",
        "rollback_version": "3.1.77",
    }


def test_root_worker_rejects_request_for_release_other_than_root_previous(
    tmp_path: Path,
) -> None:
    """A service-writable request must not choose an arbitrary installed release."""
    install_root, data_root = tmp_path / "install", tmp_path / "data"
    _select_two_headless_releases(install_root, data_root)
    original = (install_root / "current.json").read_bytes()
    _write_rollback_request(
        data_root,
        rollback_version="3.1.76",
        rollback_revision="deadbeef",
    )

    ok, reason = alt_update_installer.apply_alt_rollback(install_root, data_root)

    assert (ok, reason) == (False, "ValueError")
    assert (install_root / "current.json").read_bytes() == original
    assert (data_root / "updates" / "last_failed_alt_rollback_request.json").is_file()


def test_root_worker_rejects_tampered_previous_release_without_selector_change(
    tmp_path: Path,
) -> None:
    """Matching selector strings are insufficient when immutable bytes changed."""
    install_root, data_root = tmp_path / "install", tmp_path / "data"
    _select_two_headless_releases(install_root, data_root)
    original = (install_root / "current.json").read_bytes()
    previous_binary = (
        install_root / "versions" / "3.1.77" / "endpoint-agent" / "endpoint-agent"
    )
    previous_binary.write_bytes(b"tampered")
    _write_rollback_request(data_root)

    ok, reason = alt_update_installer.apply_alt_rollback(install_root, data_root)

    assert (ok, reason) == (False, "ValueError")
    assert (install_root / "current.json").read_bytes() == original


def test_committed_update_replay_preserves_distinct_previous_selector(
    tmp_path: Path, monkeypatch
) -> None:
    """A crash after current.json publication must not destroy rollback authority."""
    install_root, data_root = tmp_path / "install", tmp_path / "data"
    _initial_selector(install_root)
    artifact = data_root / "updates" / "downloads" / "candidate.tar.gz"
    artifact.parent.mkdir(parents=True)
    _write_bundle(artifact)
    pending = _pending(data_root, artifact)
    original_append = alt_update_installer._append_history
    interrupted = False

    def interrupt_after_commit(root: Path, entry: dict[str, object]) -> None:
        nonlocal interrupted
        if not interrupted and entry.get("success") is True:
            interrupted = True
            raise OSError("simulated worker death after selector commit")
        original_append(root, entry)

    monkeypatch.setattr(alt_update_installer, "_append_history", interrupt_after_commit)

    assert apply_alt_update(install_root, data_root, pending) == (
        True,
        "3.1.77-rc.1",
    )
    assert pending.exists()
    assert (
        json.loads((install_root / "previous.json").read_text())["version"] == "3.1.76"
    )

    assert apply_alt_update(install_root, data_root, pending) == (
        True,
        "3.1.77-rc.1",
    )
    assert not pending.exists()
    assert (
        json.loads((install_root / "previous.json").read_text())["version"] == "3.1.76"
    )
    history = json.loads((data_root / "updates" / "update_history.json").read_text())
    assert [entry["operation_id"] for entry in history].count(_OPERATION_ID) == 1


@pytest.mark.parametrize(
    ("invalid_previous", "expected_reason"),
    [("missing", "FileNotFoundError"), ("same_as_current", "ValueError")],
)
def test_committed_update_replay_consumes_inconsistent_previous_authority(
    tmp_path: Path, monkeypatch, invalid_previous: str, expected_reason: str
) -> None:
    install_root, data_root = tmp_path / "install", tmp_path / "data"
    _initial_selector(install_root)
    artifact = data_root / "updates" / "downloads" / "candidate.tar.gz"
    artifact.parent.mkdir(parents=True)
    _write_bundle(artifact)
    pending = _pending(data_root, artifact)
    original_append = alt_update_installer._append_history
    interrupted = False

    def interrupt_after_commit(root: Path, entry: dict[str, object]) -> None:
        nonlocal interrupted
        if not interrupted and entry.get("success") is True:
            interrupted = True
            raise OSError("simulated post-commit cleanup interruption")
        original_append(root, entry)

    monkeypatch.setattr(alt_update_installer, "_append_history", interrupt_after_commit)
    assert apply_alt_update(install_root, data_root, pending)[0] is True
    previous = install_root / "previous.json"
    if invalid_previous == "missing":
        previous.unlink()
    else:
        previous.write_bytes((install_root / "current.json").read_bytes())

    ok, reason = apply_alt_update(install_root, data_root, pending)

    assert (ok, reason) == (False, expected_reason)
    assert not pending.exists()
    assert json.loads((install_root / "current.json").read_text())["version"] == (
        "3.1.77-rc.1"
    )
    failure = data_root / "updates" / "last_failed_alt_update.json"
    assert json.loads(failure.read_text()) == {
        "operation_id": _OPERATION_ID,
        "reason": "invalid_committed_alt_update_replay",
        "version": "3.1.77-rc.1",
    }


def test_failed_current_publication_restores_prior_previous_selector(
    tmp_path: Path, monkeypatch
) -> None:
    install_root, data_root = tmp_path / "install", tmp_path / "data"
    _select_two_headless_releases(install_root, data_root)
    prior_previous = (install_root / "previous.json").read_bytes()
    artifact = data_root / "updates" / "downloads" / "next.tar.gz"
    _write_bundle(
        artifact, version="3.1.79", source_revision="nextheadless", layout="headless"
    )
    original_write = alt_update_installer._write_selector

    def fail_current(path: Path, manifest: object) -> None:
        if path.name == "current.json":
            raise OSError("simulated current selector publication failure")
        original_write(path, manifest)

    monkeypatch.setattr(alt_update_installer, "_write_selector", fail_current)

    ok, _ = apply_alt_update(
        install_root, data_root, _pending(data_root, artifact, version="3.1.79")
    )

    assert ok is False
    assert (install_root / "previous.json").read_bytes() == prior_previous
    assert (
        json.loads((install_root / "current.json").read_text())["version"] == "3.1.78"
    )


def test_committed_rollback_replay_finishes_terminal_marker_and_cleanup(
    tmp_path: Path, monkeypatch
) -> None:
    install_root, data_root = tmp_path / "install", tmp_path / "data"
    _select_two_headless_releases(install_root, data_root)
    request = _write_rollback_request(data_root)
    original_write = alt_update_installer._write_update_json
    interrupted = False

    def interrupt_marker(
        updates: Path,
        updates_fd: int | None,
        name: str,
        payload: dict[str, object],
    ) -> None:
        nonlocal interrupted
        if name == "last_failed_launch.json" and not interrupted:
            interrupted = True
            raise OSError("simulated worker death after selector commit")
        original_write(updates, updates_fd, name, payload)

    monkeypatch.setattr(alt_update_installer, "_write_update_json", interrupt_marker)

    assert alt_update_installer.apply_alt_rollback(install_root, data_root)[0] is False
    assert (
        json.loads((install_root / "current.json").read_text())["version"] == "3.1.77"
    )
    assert request.exists()

    assert alt_update_installer.apply_alt_rollback(install_root, data_root) == (
        True,
        "3.1.77",
    )
    assert not request.exists()
    assert (
        json.loads((data_root / "updates" / "last_failed_launch.json").read_text())[
            "reason"
        ]
        == "startup_crash_rollback"
    )


def test_committed_rollback_replay_after_request_cleanup_failure(
    tmp_path: Path, monkeypatch
) -> None:
    install_root, data_root = tmp_path / "install", tmp_path / "data"
    _select_two_headless_releases(install_root, data_root)
    request = _write_rollback_request(data_root)
    original_unlink = alt_update_installer._unlink_update_leaf
    interrupted = False

    def interrupt_cleanup(updates: Path, updates_fd: int | None, name: str) -> None:
        nonlocal interrupted
        if name == "rollback-request.json" and not interrupted:
            interrupted = True
            raise OSError("simulated request cleanup failure")
        original_unlink(updates, updates_fd, name)

    monkeypatch.setattr(alt_update_installer, "_unlink_update_leaf", interrupt_cleanup)

    assert alt_update_installer.apply_alt_rollback(install_root, data_root)[0] is False
    assert request.exists()
    assert (
        json.loads((data_root / "updates" / "last_failed_launch.json").read_text())[
            "reason"
        ]
        == "startup_crash_rollback"
    )
    assert alt_update_installer.apply_alt_rollback(install_root, data_root) == (
        True,
        "3.1.77",
    )
    assert not request.exists()


def test_root_worker_rejects_release_with_unmanifested_empty_directory(
    tmp_path: Path,
) -> None:
    install_root, data_root = tmp_path / "install", tmp_path / "data"
    _select_two_headless_releases(install_root, data_root)
    (install_root / "versions" / "3.1.77" / "unexpected-empty").mkdir()
    original = (install_root / "current.json").read_bytes()
    _write_rollback_request(data_root)

    assert alt_update_installer.apply_alt_rollback(install_root, data_root)[0] is False
    assert (install_root / "current.json").read_bytes() == original


def test_rejected_request_is_consumed_when_failure_destination_is_hostile_directory(
    tmp_path: Path,
) -> None:
    install_root, data_root = tmp_path / "install", tmp_path / "data"
    _select_two_headless_releases(install_root, data_root)
    request = _write_rollback_request(data_root, rollback_version="3.1.76")
    failure = data_root / "updates" / "last_failed_alt_rollback_request.json"
    failure.mkdir()

    assert alt_update_installer.apply_alt_rollback(install_root, data_root)[0] is False
    assert not request.exists()
    assert failure.is_file() and not failure.is_symlink()


def test_unsafe_request_directory_is_consumed_as_fixed_regular_failure(
    tmp_path: Path,
) -> None:
    install_root, data_root = tmp_path / "install", tmp_path / "data"
    _select_two_headless_releases(install_root, data_root)
    request = data_root / "updates" / "rollback-request.json"
    request.mkdir()
    (request / "attacker-content").write_text("x")

    assert alt_update_installer.apply_alt_rollback(install_root, data_root)[0] is False
    assert not request.exists()
    failure = data_root / "updates" / "last_failed_alt_rollback_request.json"
    assert failure.is_file() and not failure.is_symlink()


def test_symlinked_updates_parent_is_rejected_without_selector_change(
    tmp_path: Path,
) -> None:
    install_root, data_root = tmp_path / "install", tmp_path / "data"
    _select_two_headless_releases(install_root, data_root)
    updates = data_root / "updates"
    redirected = tmp_path / "redirected-updates"
    updates.rename(redirected)
    try:
        updates.symlink_to(redirected, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symlinks unavailable: {exc}")
    original = (install_root / "current.json").read_bytes()

    assert alt_update_installer.apply_alt_rollback(install_root, data_root)[0] is False
    assert (install_root / "current.json").read_bytes() == original


def test_symlinked_previous_selector_is_rejected_without_selector_change(
    tmp_path: Path,
) -> None:
    install_root, data_root = tmp_path / "install", tmp_path / "data"
    _select_two_headless_releases(install_root, data_root)
    _write_rollback_request(data_root)
    previous = install_root / "previous.json"
    redirected = install_root / "redirected-previous.json"
    previous.replace(redirected)
    try:
        previous.symlink_to(redirected)
    except OSError as exc:
        pytest.skip(f"file symlinks unavailable: {exc}")
    original = (install_root / "current.json").read_bytes()

    assert alt_update_installer.apply_alt_rollback(install_root, data_root)[0] is False
    assert (install_root / "current.json").read_bytes() == original


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode contract")
def test_group_writable_previous_selector_is_rejected(tmp_path: Path) -> None:
    install_root, data_root = tmp_path / "install", tmp_path / "data"
    _select_two_headless_releases(install_root, data_root)
    _write_rollback_request(data_root)
    previous = install_root / "previous.json"
    previous.chmod(0o664)
    original = (install_root / "current.json").read_bytes()

    assert alt_update_installer.apply_alt_rollback(install_root, data_root)[0] is False
    assert (install_root / "current.json").read_bytes() == original


@pytest.mark.skipif(os.name == "nt", reason="POSIX ownership contract")
def test_non_root_previous_selector_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    install_root, data_root = tmp_path / "install", tmp_path / "data"
    _select_two_headless_releases(install_root, data_root)
    _write_rollback_request(data_root)
    previous = install_root / "previous.json"
    if os.geteuid() == 0:
        os.chown(previous, 1, 1)
    else:
        monkeypatch.setattr(alt_update_installer.os, "geteuid", lambda: 0)
    original = (install_root / "current.json").read_bytes()

    assert alt_update_installer.apply_alt_rollback(install_root, data_root)[0] is False
    assert (install_root / "current.json").read_bytes() == original


@pytest.mark.skipif(os.name == "nt", reason="POSIX FIFO contract")
def test_fifo_rollback_request_is_consumed_without_blocking(tmp_path: Path) -> None:
    install_root, data_root = tmp_path / "install", tmp_path / "data"
    _select_two_headless_releases(install_root, data_root)
    request = data_root / "updates" / "rollback-request.json"
    os.mkfifo(request, 0o600)

    assert alt_update_installer.apply_alt_rollback(install_root, data_root)[0] is False
    assert not request.exists()
    assert (data_root / "updates" / "last_failed_alt_rollback_request.json").is_file()


def test_manifest_hash_mismatch_leaves_active_alt_selector_unchanged(
    tmp_path: Path,
) -> None:
    install_root, data_root = tmp_path / "install", tmp_path / "data"
    _initial_selector(install_root)
    artifact = data_root / "updates" / "downloads" / "candidate.tar.gz"
    artifact.parent.mkdir(parents=True)
    _write_bundle(artifact, corrupt_manifest=True)

    ok, _ = apply_alt_update(install_root, data_root, _pending(data_root, artifact))

    assert ok is False
    assert json.loads((install_root / "current.json").read_text(encoding="utf-8")) == {
        "schema_version": 1,
        "source_revision": "deadbeef",
        "version": "3.1.76",
    }
    assert not (install_root / "versions" / "3.1.77-rc.1").exists()
    assert json.loads(
        (data_root / "updates" / "update_history.json").read_text(encoding="utf-8")
    ) == [
        {
            "operation_id": _OPERATION_ID,
            "success": False,
            "version": "3.1.77-rc.1",
        }
    ]


def test_verified_existing_alt_release_can_be_selected_for_rollback(
    tmp_path: Path,
) -> None:
    install_root, data_root = tmp_path / "install", tmp_path / "data"
    _initial_selector(install_root)
    artifact = data_root / "updates" / "downloads" / "candidate.tar.gz"
    artifact.parent.mkdir(parents=True)
    _write_bundle(artifact)

    ok, version = apply_alt_update(
        install_root, data_root, _pending(data_root, artifact)
    )
    assert (ok, version) == (True, "3.1.77-rc.1")
    existing_release = install_root / "versions" / "3.1.77-rc.1"
    existing_launcher = (existing_release / "launcher").read_bytes()
    current_release = install_root / "versions" / "3.1.78"
    (current_release / "pc_agent").mkdir(parents=True)
    current_launcher = current_release / "launcher"
    current_launcher.write_bytes(b"newer-launcher")
    current_launcher.chmod(0o755)
    current_binary = current_release / "pc_agent" / "pc_agent"
    current_binary.write_bytes(b"newer-agent")
    current_binary.chmod(0o755)
    (current_release / "manifest.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "version": "3.1.78",
                "source_revision": "newerbuild",
                "files": [
                    {
                        "path": "launcher",
                        "sha256": _sha256(b"newer-launcher"),
                        "mode": "0755",
                    },
                    {
                        "path": "pc_agent/pc_agent",
                        "sha256": _sha256(b"newer-agent"),
                        "mode": "0755",
                    },
                ],
            },
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    (install_root / "current.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "source_revision": "newerbuild",
                "version": "3.1.78",
            }
        ),
        encoding="utf-8",
    )

    rollback_operation = "caa31a48-bf2f-4f1c-8b77-d1be77e12b4f"
    ok, version = apply_alt_update(
        install_root,
        data_root,
        _pending(data_root, artifact, operation_id=rollback_operation),
    )

    assert (ok, version) == (True, "3.1.77-rc.1")
    assert (existing_release / "launcher").read_bytes() == existing_launcher
    assert json.loads((install_root / "current.json").read_text(encoding="utf-8")) == {
        "schema_version": 1,
        "source_revision": "feedface",
        "version": "3.1.77-rc.1",
    }
    history = json.loads(
        (data_root / "updates" / "update_history.json").read_text(encoding="utf-8")
    )
    assert history[-1] == {
        "operation_id": rollback_operation,
        "previous_version": "3.1.78",
        "success": True,
        "version": "3.1.77-rc.1",
    }
