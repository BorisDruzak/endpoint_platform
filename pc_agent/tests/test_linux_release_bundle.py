import hashlib
import json
import os
from pathlib import Path
import stat

import pytest

from pc_agent.build_linux_release_bundle import assemble_bundle, main


def _write_payload(path: Path, content: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    path.chmod(mode)


def _valid_source(tmp_path: Path) -> Path:
    source = tmp_path / "payload"
    _write_payload(source / "launcher", b"launcher\n", 0o755)
    _write_payload(source / "pc_agent" / "pc_agent", b"agent\n", 0o755)
    _write_payload(source / "pc_agent" / "_internal" / "z.dat", b"z\n", 0o644)
    _write_payload(source / "pc_agent" / "_internal" / "a.dat", b"a\n", 0o640)
    return source


def test_assemble_bundle_writes_a_complete_sorted_schema_one_manifest(tmp_path: Path) -> None:
    """Removing, reordering, or changing a payload file must invalidate this release record."""
    source = _valid_source(tmp_path)
    source_modes = {
        relative: f"{stat.S_IMODE((source / relative).lstat().st_mode):04o}"
        for relative in (
            "launcher",
            "pc_agent/_internal/a.dat",
            "pc_agent/_internal/z.dat",
            "pc_agent/pc_agent",
        )
    }

    bundle = assemble_bundle(source, tmp_path / "output", "3.2.1", "6985dd0b89ff6626")

    assert bundle == tmp_path / "output" / "endpoint-agent-3.2.1"
    manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    assert manifest == {
        "schema_version": 1,
        "version": "3.2.1",
        "source_revision": "6985dd0b89ff6626",
        "files": [
            {
                "path": "launcher",
                "sha256": hashlib.sha256(b"launcher\n").hexdigest(),
                "mode": source_modes["launcher"],
            },
            {
                "path": "pc_agent/_internal/a.dat",
                "sha256": hashlib.sha256(b"a\n").hexdigest(),
                "mode": source_modes["pc_agent/_internal/a.dat"],
            },
            {
                "path": "pc_agent/_internal/z.dat",
                "sha256": hashlib.sha256(b"z\n").hexdigest(),
                "mode": source_modes["pc_agent/_internal/z.dat"],
            },
            {
                "path": "pc_agent/pc_agent",
                "sha256": hashlib.sha256(b"agent\n").hexdigest(),
                "mode": source_modes["pc_agent/pc_agent"],
            },
        ],
    }
    assert (bundle / "launcher").read_bytes() == b"launcher\n"
    assert (bundle / "pc_agent" / "_internal" / "a.dat").read_bytes() == b"a\n"


def test_assemble_bundle_normalizes_an_in_tree_payload_symlink(tmp_path: Path) -> None:
    """PyInstaller runtime links must become ordinary attested bundle files."""
    source = _valid_source(tmp_path)
    target = source / "pc_agent" / "_internal" / "runtime.dat"
    _write_payload(target, b"runtime\n", 0o755)
    link = source / "pc_agent" / "_internal" / "runtime-link.so"
    try:
        os.symlink("runtime.dat", link)
    except OSError as exc:
        pytest.skip(f"symlinks are not available in this test environment: {exc}")

    bundle = assemble_bundle(source, tmp_path / "output", "3.2.1", "6985dd0b89ff6626")

    copied_link = bundle / "pc_agent" / "_internal" / "runtime-link.so"
    assert not copied_link.is_symlink()
    assert copied_link.read_bytes() == b"runtime\n"
    if os.name != "nt":
        assert stat.S_IMODE(copied_link.stat().st_mode) == 0o755
    manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    assert {entry["path"] for entry in manifest["files"]} >= {
        "pc_agent/_internal/runtime-link.so"
    }


def test_assemble_bundle_rejects_an_unexpected_source_entry(tmp_path: Path) -> None:
    """A top-level file other than launcher must not become an unverified install input."""
    source = _valid_source(tmp_path)
    _write_payload(source / "not-part-of-the-bundle", b"surprise\n", 0o644)

    with pytest.raises(ValueError, match="unexpected source entry"):
        assemble_bundle(source, tmp_path / "output", "3.2.1", "6985dd0b89ff6626")


def test_assemble_bundle_rejects_an_out_of_tree_symlink_in_the_payload(tmp_path: Path) -> None:
    """A payload link may not pull bytes from outside the reviewed onedir tree."""
    source = _valid_source(tmp_path)
    outside = tmp_path / "outside.dat"
    _write_payload(outside, b"outside\n", 0o644)
    link = source / "pc_agent" / "_internal" / "linked.dat"
    try:
        os.symlink(outside, link)
    except OSError as exc:
        pytest.skip(f"symlinks are not available in this test environment: {exc}")

    with pytest.raises(ValueError, match="symbolic link"):
        assemble_bundle(source, tmp_path / "output", "3.2.1", "6985dd0b89ff6626")


def test_assemble_bundle_rejects_a_top_level_symlink(tmp_path: Path) -> None:
    """The launcher source itself must never be resolved through a link."""
    source = _valid_source(tmp_path)
    launcher = source / "launcher"
    launcher.unlink()
    try:
        os.symlink(source / "pc_agent" / "pc_agent", launcher)
    except OSError as exc:
        pytest.skip(f"symlinks are not available in this test environment: {exc}")

    with pytest.raises(ValueError, match="symbolic link"):
        assemble_bundle(source, tmp_path / "output", "3.2.1", "6985dd0b89ff6626")


@pytest.mark.parametrize(
    ("version", "revision"),
    [
        ("../3.2.1", "6985dd0b89ff6626"),
        ("3.2.1", ""),
        ("x" * 65, "6985dd0b89ff6626"),
        ("3.2.1", "x" * 129),
    ],
)
def test_assemble_bundle_rejects_unbounded_or_path_like_release_identifiers(
    tmp_path: Path, version: str, revision: str
) -> None:
    """Unchecked identifiers could escape the output directory or make ambiguous manifests."""
    with pytest.raises(ValueError, match="(version|source revision)"):
        assemble_bundle(_valid_source(tmp_path), tmp_path / "output", version, revision)


@pytest.mark.parametrize("missing", ["launcher", "pc_agent/pc_agent"])
def test_assemble_bundle_requires_both_executable_entrypoints(tmp_path: Path, missing: str) -> None:
    """A bundle without either runtime entrypoint cannot be safely installed."""
    source = _valid_source(tmp_path)
    (source / missing).unlink()

    with pytest.raises(ValueError, match="required payload file"):
        assemble_bundle(source, tmp_path / "output", "3.2.1", "6985dd0b89ff6626")


def test_cli_assembles_a_fixture_source_without_running_pyinstaller(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Non-build mode must package reviewed fixture output without a platform build dependency."""
    source = _valid_source(tmp_path)

    result = main(
        [
            "--source",
            str(source),
            "--revision",
            "6985dd0b89ff6626",
            "--version",
            "3.2.1",
            "--output",
            str(tmp_path / "output"),
        ]
    )

    assert result == 0
    assert capsys.readouterr().out.strip() == str(tmp_path / "output" / "endpoint-agent-3.2.1")
