"""Stage the reviewed ALT agent release bundle as deterministic RPM source input."""

from __future__ import annotations

import argparse
import gzip
import io
import json
from pathlib import Path
import re
import shutil
import stat
import tarfile
import tempfile

_VERSION_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}\Z")
_REVISION_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}\Z")
_REQUIRED_BUNDLE_ENTRIES = {"launcher", "manifest.json", "pc_agent"}
_PROVISIONING_ASSETS = {
    "apply-pending-alt-update.sh": "provision/apply-pending-alt-update.sh",
    "default-config.yaml": "provision/default-config.yaml",
    "endpoint-agent-update.path": "provision/endpoint-agent-update.path",
    "endpoint-agent-update.service": "provision/endpoint-agent-update.service",
    "endpoint-agent-finalize.path": "provision/endpoint-agent-finalize.path",
    "endpoint-agent-finalize.service": "provision/endpoint-agent-finalize.service",
    "endpoint-agent.service": "provision/endpoint-agent.service",
    "install-endpoint-agent.sh": "provision/install-endpoint-agent.sh",
    "rpm-auto-provision.sh": "provision/rpm-auto-provision.sh",
}


def _project_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _validate_identifier(value: str, pattern: re.Pattern[str], name: str) -> None:
    if not pattern.fullmatch(value):
        raise ValueError(f"{name} must be a bounded identifier without path separators")


def _bundle_files(source: Path) -> list[tuple[Path, str]]:
    if source.is_symlink() or not source.is_dir():
        raise ValueError("release bundle must be a regular directory")
    entries = {entry.name: entry for entry in source.iterdir()}
    if set(entries) != _REQUIRED_BUNDLE_ENTRIES:
        raise ValueError("release bundle entries are incomplete or unexpected")
    required_agent = entries["pc_agent"] / "pc_agent"
    if (
        entries["launcher"].is_symlink()
        or not entries["launcher"].is_file()
        or entries["manifest.json"].is_symlink()
        or not entries["manifest.json"].is_file()
        or entries["pc_agent"].is_symlink()
        or not entries["pc_agent"].is_dir()
        or required_agent.is_symlink()
        or not required_agent.is_file()
    ):
        raise ValueError("release bundle is missing a regular launcher or agent binary")

    files: list[tuple[Path, str]] = []
    for entry in sorted(source.rglob("*")):
        relative = entry.relative_to(source).as_posix()
        if entry.is_symlink():
            raise ValueError(f"release bundle contains a symbolic link: {relative}")
        if entry.is_file():
            files.append((entry, f"agent-bundle/{relative}"))
        elif not entry.is_dir():
            raise ValueError(f"release bundle contains a non-regular entry: {relative}")
    return files


def _manifest_matches(bundle: Path, version: str, revision: str) -> None:
    try:
        manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("release bundle manifest is unreadable") from exc
    if (
        not isinstance(manifest, dict)
        or manifest.get("schema_version") != 1
        or manifest.get("version") != version
        or manifest.get("source_revision") != revision
    ):
        raise ValueError("release bundle manifest does not match the requested version and revision")


def _asset_files(project_root: Path) -> list[tuple[Path, str]]:
    agent_root = project_root / "deploy" / "agent" / "alt"
    assets = [
        (project_root / "docs" / "runbooks" / "ALT_AGENT_INSTALL.md", "docs/ALT_AGENT_INSTALL.md"),
        (agent_root / "rpm" / "endpoint-agent.spec", "packaging/endpoint-agent.spec"),
    ]
    assets.extend(
        (agent_root / source_name, target_name)
        for source_name, target_name in _PROVISIONING_ASSETS.items()
    )
    for source, target in assets:
        if source.is_symlink() or not source.is_file():
            raise ValueError(f"required RPM source asset is missing or unsafe: {source}")
    return sorted(assets, key=lambda item: item[1])


def _add_regular_file(archive: tarfile.TarFile, source: Path, target: str) -> None:
    info = tarfile.TarInfo(target)
    info.size = source.stat().st_size
    info.mode = stat.S_IMODE(source.stat().st_mode)
    info.mtime = 0
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    with source.open("rb") as stream:
        archive.addfile(info, stream)


def build_source_archive(source: Path, version: str, revision: str, output: Path) -> Path:
    """Create deterministic RPM source input from one attested Linux release bundle."""
    _validate_identifier(version, _VERSION_PATTERN, "version")
    _validate_identifier(revision, _REVISION_PATTERN, "source revision")
    source = Path(source)
    output = Path(output)
    _manifest_matches(source, version, revision)
    members = _bundle_files(source) + _asset_files(_project_root())
    target = output / f"endpoint-agent-{version}.tar.gz"
    if target.exists() or target.is_symlink():
        raise ValueError(f"RPM source archive already exists: {target}")
    output.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=".endpoint-agent-rpm.", dir=output))
    try:
        pending = temporary / target.name
        with pending.open("wb") as raw:
            with gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as compressed:
                with tarfile.open(fileobj=compressed, mode="w") as archive:
                    root = f"endpoint-agent-{version}"
                    for member_source, relative in sorted(members, key=lambda item: item[1]):
                        _add_regular_file(archive, member_source, f"{root}/{relative}")
        pending.replace(target)
    finally:
        shutil.rmtree(temporary, ignore_errors=True)
    return target


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    print(build_source_archive(args.source, args.version, args.revision, args.output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
