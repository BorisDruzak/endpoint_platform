"""Validate the immutable initial Windows runtime and its staged artifact."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import re
import sysconfig
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any


_SEMVER = re.compile(r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$")
_MANIFEST_FIELDS = {
    "agent_version",
    "artifact",
    "component_guid",
    "schema_version",
    "source_files",
    "toolchain",
    "version",
}
_SOURCE_FIELDS = {"path", "sha256"}
_ARTIFACT_FIELDS = {"file_count", "tree_sha256"}
_TOOLCHAIN_FIELDS_V2 = {
    "implementation",
    "platform",
    "pyinstaller_version",
    "python_version",
    "source_date_epoch",
}
_TOOLCHAIN_FIELDS_V3 = _TOOLCHAIN_FIELDS_V2 | {"python_hash_seed"}
_TOOLCHAIN_FIELDS_V4 = _TOOLCHAIN_FIELDS_V3 | {
    "pyinstaller_hooks_contrib_version"
}


@dataclass(frozen=True, slots=True)
class InitialRuntimeIdentity:
    version: str
    component_guid: str
    baseline_version: str
    transition_approved: bool


@dataclass(frozen=True, slots=True)
class _Manifest:
    schema_version: int
    identity: tuple[str, str]
    agent_version: str
    sources: list[dict[str, str]]
    artifact: dict[str, object]
    toolchain: dict[str, object]


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def artifact_identity(root: Path) -> dict[str, object]:
    """Hash every staged runtime file with its canonical relative path and size."""
    if root.is_symlink() or not root.is_dir():
        raise ValueError("staged payload root is missing or a reparse point")
    entries = sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix())
    if any(item.is_symlink() for item in entries):
        raise ValueError("staged payload contains a reparse point")
    files = [item for item in entries if item.is_file()]
    digest = hashlib.sha256()
    for path in files:
        relative = path.relative_to(root).as_posix()
        size = path.stat().st_size
        digest.update(f"{relative}\0{size}\0{_hash_file(path)}\n".encode("utf-8"))
    return {"file_count": len(files), "tree_sha256": digest.hexdigest()}


def discover_toolchain() -> dict[str, object]:
    """Return the producer identity that materially affects frozen bytes."""
    try:
        import PyInstaller
    except ImportError as error:
        raise ValueError("PyInstaller is required to validate the toolchain") from error
    epoch = os.environ.get("SOURCE_DATE_EPOCH", "")
    if not epoch.isdigit():
        raise ValueError("SOURCE_DATE_EPOCH is required for the pinned toolchain")
    hash_seed = os.environ.get("PYTHONHASHSEED", "")
    if hash_seed != "0":
        raise ValueError("PYTHONHASHSEED=0 is required for the pinned toolchain")
    return {
        "implementation": platform.python_implementation(),
        "platform": sysconfig.get_platform(),
        "pyinstaller_version": PyInstaller.__version__,
        "python_version": platform.python_version(),
        "source_date_epoch": int(epoch),
        "python_hash_seed": hash_seed,
        "pyinstaller_hooks_contrib_version": importlib.metadata.version(
            "pyinstaller-hooks-contrib"
        ),
    }


def _read_agent_version(repository_root: Path) -> str:
    version_path = repository_root / "pc_agent" / "version.py"
    try:
        text = version_path.read_text(encoding="utf-8")
    except OSError as error:
        raise ValueError("pc_agent/version.py is unreadable") from error
    match = re.search(r'^AGENT_VERSION\s*=\s*"([^"]+)"\s*$', text, re.MULTILINE)
    if match is None:
        raise ValueError("AGENT_VERSION is missing")
    return match.group(1)


def _load_manifest(
    repository_root: Path,
    path: Path,
    *,
    validate_inputs: bool,
    artifact_root: Path | None = None,
    observed_toolchain: dict[str, object] | None = None,
) -> _Manifest:
    try:
        payload: Any = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError("initial runtime manifest is unreadable") from error
    if not isinstance(payload, dict) or set(payload) != _MANIFEST_FIELDS:
        raise ValueError("initial runtime manifest has an invalid schema")
    version = payload.get("version")
    agent_version = payload.get("agent_version")
    guid = payload.get("component_guid")
    sources = payload.get("source_files")
    artifact = payload.get("artifact")
    toolchain = payload.get("toolchain")
    schema_version = payload.get("schema_version")
    if (
        schema_version not in {2, 3, 4}
        or not isinstance(version, str)
        or not _SEMVER.fullmatch(version)
        or agent_version != version
    ):
        raise ValueError("initial runtime version or agent_version is invalid")
    try:
        canonical_guid = str(uuid.UUID(str(guid))).upper()
    except (ValueError, TypeError, AttributeError) as error:
        raise ValueError("initial runtime component GUID is invalid") from error
    if canonical_guid != guid:
        raise ValueError("initial runtime component GUID must be canonical uppercase")
    if not isinstance(sources, list) or not sources:
        raise ValueError("initial runtime manifest has an invalid source list")
    if (
        not isinstance(artifact, dict)
        or set(artifact) != _ARTIFACT_FIELDS
        or not isinstance(artifact.get("file_count"), int)
        or isinstance(artifact.get("file_count"), bool)
        or artifact.get("file_count", 0) <= 0
        or not isinstance(artifact.get("tree_sha256"), str)
        or not re.fullmatch(r"[0-9a-f]{64}", artifact["tree_sha256"])
    ):
        raise ValueError("initial runtime artifact identity is invalid")
    toolchain_fields = {
        2: _TOOLCHAIN_FIELDS_V2,
        3: _TOOLCHAIN_FIELDS_V3,
        4: _TOOLCHAIN_FIELDS_V4,
    }[schema_version]
    if (
        not isinstance(toolchain, dict)
        or set(toolchain) != toolchain_fields
        or not all(
            isinstance(toolchain.get(field), str) and toolchain[field]
            for field in toolchain_fields - {"source_date_epoch"}
        )
        or not isinstance(toolchain.get("source_date_epoch"), int)
        or isinstance(toolchain.get("source_date_epoch"), bool)
        or toolchain["source_date_epoch"] <= 0
        or (schema_version >= 3 and toolchain.get("python_hash_seed") != "0")
    ):
        raise ValueError("initial runtime toolchain identity is invalid")

    observed: set[str] = set()
    normalized: list[dict[str, str]] = []
    if validate_inputs and _read_agent_version(repository_root) != agent_version:
        raise ValueError("manifest version does not match AGENT_VERSION")
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
        if validate_inputs:
            source = repository_root / relative
            if source.is_symlink() or not source.is_file():
                raise ValueError(f"initial runtime source is missing: {relative}")
            if _hash_file(source) != expected:
                raise ValueError(f"initial runtime source hash mismatch: {relative}")
        normalized.append({"path": relative, "sha256": expected})
    if [item["path"] for item in normalized] != sorted(observed):
        raise ValueError("initial runtime source entries must be sorted")

    if validate_inputs:
        actual_toolchain = observed_toolchain or discover_toolchain()
        observed_fields = {field: actual_toolchain.get(field) for field in toolchain_fields}
        if observed_fields != toolchain:
            raise ValueError("initial runtime toolchain mismatch")
        if artifact_root is not None and artifact_identity(artifact_root) != artifact:
            raise ValueError("initial runtime staged payload mismatch")
    return _Manifest(
        schema_version,
        (version, canonical_guid),
        agent_version,
        normalized,
        dict(artifact),
        dict(toolchain),
    )


def validate_initial_runtime(
    repository_root: Path,
    manifest_path: Path,
    baseline_path: Path,
    *,
    approve_version: bool = False,
    approve_source: bool = False,
    artifact_root: Path | None = None,
    observed_toolchain: dict[str, object] | None = None,
) -> InitialRuntimeIdentity:
    """Require exact routine bytes or a reviewed, identity-safe transition."""
    repository_root = repository_root.resolve()
    candidate = _load_manifest(
        repository_root,
        manifest_path.resolve(),
        validate_inputs=True,
        artifact_root=artifact_root,
        observed_toolchain=observed_toolchain,
    )
    baseline = _load_manifest(
        repository_root, baseline_path.resolve(), validate_inputs=False
    )
    transition = (
        manifest_path.resolve() != baseline_path.resolve()
        or candidate != baseline
    )
    if transition:
        if not (approve_version and approve_source):
            raise ValueError("initial runtime transition requires two explicit approvals")
        if (
            candidate.identity[0] == baseline.identity[0]
            or candidate.identity[1] == baseline.identity[1]
        ):
            raise ValueError(
                "initial runtime transition requires a new version and component GUID"
            )
    return InitialRuntimeIdentity(
        candidate.identity[0],
        candidate.identity[1],
        baseline.identity[0],
        transition,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository-root", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--artifact-root", type=Path)
    parser.add_argument("--print-artifact", type=Path)
    parser.add_argument("--approve-version", action="store_true")
    parser.add_argument("--approve-source", action="store_true")
    args = parser.parse_args()
    if args.print_artifact is not None:
        print(json.dumps(artifact_identity(args.print_artifact), separators=(",", ":")))
        return 0
    if args.repository_root is None or args.manifest is None or args.baseline is None:
        parser.error("--repository-root, --manifest, and --baseline are required")
    identity = validate_initial_runtime(
        args.repository_root,
        args.manifest,
        args.baseline,
        approve_version=args.approve_version,
        approve_source=args.approve_source,
        artifact_root=args.artifact_root,
    )
    print(json.dumps({
        "baseline_version": identity.baseline_version,
        "component_guid": identity.component_guid,
        "transition_approved": identity.transition_approved,
        "version": identity.version,
    }, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
