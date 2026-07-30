"""Build a self-contained, attestable Linux Endpoint Agent release bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile


_VERSION_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}\Z")
_REVISION_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}\Z")
_EXPECTED_SOURCE_ENTRIES = {"launcher", "pc_agent"}
_REQUIRED_PAYLOAD_FILES = {"launcher", "pc_agent/pc_agent"}


def _validate_identifier(value: str, pattern: re.Pattern[str], name: str) -> None:
    if not pattern.fullmatch(value):
        raise ValueError(f"{name} must be a bounded identifier without path separators")


def _regular_source_files(source: Path) -> list[tuple[Path, str]]:
    if source.is_symlink():
        raise ValueError("source directory must not be a symbolic link")
    if not source.is_dir():
        raise ValueError("source directory does not exist")

    entries = {entry.name: entry for entry in source.iterdir()}
    for name, entry in entries.items():
        if entry.is_symlink():
            raise ValueError(f"symbolic link is not allowed: {entry}")
        if name not in _EXPECTED_SOURCE_ENTRIES:
            raise ValueError(f"unexpected source entry: {name}")

    launcher = entries.get("launcher")
    if launcher is None or not launcher.is_file() or launcher.is_symlink():
        raise ValueError("required payload file is missing or not regular: launcher")
    agent_root = entries.get("pc_agent")
    if agent_root is None or not agent_root.is_dir() or agent_root.is_symlink():
        raise ValueError("required payload file is missing or not regular: pc_agent/pc_agent")

    files: list[tuple[Path, str]] = [(launcher, "launcher")]

    def collect(directory: Path, relative: Path) -> None:
        for entry in sorted(directory.iterdir(), key=lambda item: item.name):
            entry_relative = relative / entry.name
            if entry.is_symlink():
                raise ValueError(f"symbolic link is not allowed: {entry_relative.as_posix()}")
            entry_mode = entry.lstat().st_mode
            if stat.S_ISREG(entry_mode):
                files.append((entry, entry_relative.as_posix()))
            elif stat.S_ISDIR(entry_mode):
                collect(entry, entry_relative)
            else:
                raise ValueError(f"unexpected nonregular source entry: {entry_relative.as_posix()}")

    collect(agent_root, Path("pc_agent"))
    relative_paths = {relative for _, relative in files}
    missing = sorted(_REQUIRED_PAYLOAD_FILES - relative_paths)
    if missing:
        raise ValueError(f"required payload file is missing or not regular: {missing[0]}")
    return sorted(files, key=lambda item: item[1])


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _manifest_entry(source_file: Path, relative_path: str) -> dict[str, str]:
    mode = stat.S_IMODE(source_file.lstat().st_mode)
    return {
        "path": relative_path,
        "sha256": _sha256(source_file),
        "mode": f"{mode:04o}",
    }


def _write_manifest_atomically(destination: Path, manifest: dict[str, object]) -> None:
    temporary = destination.with_name(f".{destination.name}.tmp")
    try:
        with temporary.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(manifest, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
    finally:
        if temporary.exists():
            temporary.unlink()


def assemble_bundle(source: Path, output: Path, version: str, revision: str) -> Path:
    """Copy a checked Linux build output into a manifest-attested release bundle."""
    _validate_identifier(version, _VERSION_PATTERN, "version")
    _validate_identifier(revision, _REVISION_PATTERN, "source revision")
    source = Path(source)
    output = Path(output)
    if output.resolve().is_relative_to(source.resolve()):
        raise ValueError("output directory must not be inside the source directory")

    source_files = _regular_source_files(source)
    bundle = output / f"endpoint-agent-{version}"
    if bundle.exists() or bundle.is_symlink():
        raise ValueError(f"bundle output already exists: {bundle}")
    output.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".endpoint-agent-{version}.", dir=output))
    try:
        manifest_files: list[dict[str, str]] = []
        for source_file, relative_path in source_files:
            destination = staging / Path(relative_path)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source_file, destination)
            mode = stat.S_IMODE(source_file.lstat().st_mode)
            destination.chmod(mode)
            manifest_files.append(_manifest_entry(destination, relative_path))
        _write_manifest_atomically(
            staging / "manifest.json",
            {
                "schema_version": 1,
                "version": version,
                "source_revision": revision,
                "files": manifest_files,
            },
        )
        staging.replace(bundle)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return bundle


def _project_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _source_revision(project_root: Path) -> str:
    return subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=project_root, text=True
    ).strip()


def _run_pyinstaller_build(project_root: Path) -> None:
    if not sys.platform.startswith("linux"):
        raise RuntimeError("--build is supported only on Linux")
    for spec in ("pc_agent/pyinstaller_launcher_linux.spec", "pc_agent/pyinstaller_agent_linux.spec"):
        subprocess.run(
            [sys.executable, "-m", "PyInstaller", spec, "--noconfirm"],
            cwd=project_root,
            check=True,
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True, help="bounded release version")
    parser.add_argument("--output", type=Path, required=True, help="transient bundle directory")
    parser.add_argument("--source", type=Path, help="prebuilt launcher and pc_agent/ directory")
    parser.add_argument("--revision", help="source revision recorded in the manifest")
    parser.add_argument(
        "--build",
        action="store_true",
        help="run the Linux PyInstaller specs before assembling dist/",
    )
    args = parser.parse_args(argv)
    project_root = _project_root()
    if args.build and args.source is not None:
        parser.error("--build cannot be combined with --source")
    if args.build:
        _run_pyinstaller_build(project_root)
    source = args.source or project_root / "dist"
    revision = args.revision or _source_revision(project_root)
    bundle = assemble_bundle(source, args.output, args.version, revision)
    print(bundle)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
