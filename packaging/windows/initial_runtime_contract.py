"""Validate the immutable initial Windows runtime before PyInstaller runs."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from pathlib import Path


_SEMVER = re.compile(r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$")
_MANIFEST_FIELDS = {"schema_version", "version", "component_guid", "source_files"}
_SOURCE_FIELDS = {"path", "sha256"}


@dataclass(frozen=True, slots=True)
class InitialRuntimeIdentity:
    version: str
    component_guid: str


def _load_manifest(
    repository_root: Path, path: Path, *, validate_sources: bool = True
) -> tuple[InitialRuntimeIdentity, list[dict[str, str]]]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError("initial runtime manifest is unreadable") from error
    if not isinstance(payload, dict) or set(payload) != _MANIFEST_FIELDS:
        raise ValueError("initial runtime manifest has an invalid schema")
    version = payload.get("version")
    guid = payload.get("component_guid")
    sources = payload.get("source_files")
    if not isinstance(version, str) or not _SEMVER.fullmatch(version):
        raise ValueError("initial runtime version is invalid")
    try:
        canonical_guid = str(uuid.UUID(str(guid))).upper()
    except (ValueError, TypeError, AttributeError) as error:
        raise ValueError("initial runtime component GUID is invalid") from error
    if canonical_guid != guid:
        raise ValueError("initial runtime component GUID must be canonical uppercase")
    if payload.get("schema_version") != 1 or not isinstance(sources, list) or not sources:
        raise ValueError("initial runtime manifest has an invalid schema")
    observed: set[str] = set()
    normalized: list[dict[str, str]] = []
    for item in sources:
        if not isinstance(item, dict) or set(item) != _SOURCE_FIELDS:
            raise ValueError("initial runtime source entry is invalid")
        relative = item.get("path")
        expected = item.get("sha256")
        if (
            not isinstance(relative, str)
            or not relative
            or "\\" in relative
            or Path(relative).is_absolute()
            or ".." in Path(relative).parts
            or relative in observed
            or not isinstance(expected, str)
            or not re.fullmatch(r"[0-9a-f]{64}", expected)
        ):
            raise ValueError("initial runtime source entry is invalid")
        observed.add(relative)
        if validate_sources:
            source = repository_root / relative
            if source.is_symlink() or not source.is_file():
                raise ValueError(f"initial runtime source is missing: {relative}")
            actual = hashlib.sha256(source.read_bytes()).hexdigest()
            if actual != expected:
                raise ValueError(f"initial runtime source hash mismatch: {relative}")
        normalized.append({"path": relative, "sha256": expected})
    if [item["path"] for item in normalized] != sorted(observed):
        raise ValueError("initial runtime source entries must be sorted")
    return InitialRuntimeIdentity(version, canonical_guid), normalized


def validate_initial_runtime(
    repository_root: Path,
    manifest_path: Path,
    baseline_path: Path,
    *,
    approve_version: bool = False,
    approve_source: bool = False,
) -> InitialRuntimeIdentity:
    """Require immutable routine inputs or a reviewed, identity-safe transition."""
    repository_root = repository_root.resolve()
    candidate, candidate_sources = _load_manifest(repository_root, manifest_path.resolve())
    baseline, baseline_sources = _load_manifest(
        repository_root, baseline_path.resolve(), validate_sources=False
    )
    transition = (
        manifest_path.resolve() != baseline_path.resolve()
        or candidate != baseline
        or candidate_sources != baseline_sources
    )
    if not transition:
        return candidate
    if not (approve_version and approve_source):
        raise ValueError("initial runtime transition requires two explicit approvals")
    if candidate.version == baseline.version or candidate.component_guid == baseline.component_guid:
        raise ValueError("initial runtime transition requires a new version and component GUID")
    return candidate


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--approve-version", action="store_true")
    parser.add_argument("--approve-source", action="store_true")
    args = parser.parse_args()
    identity = validate_initial_runtime(
        args.repository_root,
        args.manifest,
        args.baseline,
        approve_version=args.approve_version,
        approve_source=args.approve_source,
    )
    print(json.dumps({
        "version": identity.version,
        "component_guid": identity.component_guid,
    }, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
