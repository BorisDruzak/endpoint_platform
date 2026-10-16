"""Keep build-tool runtime hooks out of fixed privileged Windows programs."""
from __future__ import annotations

from collections.abc import Iterable
import argparse
import hashlib
import json
from pathlib import Path


BUILD_ONLY_MODULES = ("setuptools", "pkg_resources", "_distutils_hack")
_BUILD_RUNTIME_HOOKS = ("pyi_rth_setuptools", "pyi_rth_pkgres")


def assert_no_build_modules(names: Iterable[str]) -> None:
    blocked = set()
    for name in names:
        components = name.replace("\\", "/").replace("/", ".").lower().split(".")
        if any(part in (*BUILD_ONLY_MODULES, *_BUILD_RUNTIME_HOOKS) for part in components):
            blocked.add(name)
    if blocked:
        raise ValueError("Build tools in privileged Windows runtime: " + ", ".join(sorted(blocked)))


def _sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def inspect_archive(path: Path) -> dict[str, object]:
    from PyInstaller.archive.readers import CArchiveReader

    digest = _sha256(path)
    archive = CArchiveReader(str(path))
    members = list(archive.toc)
    modules = []
    for name in members:
        if name.endswith(".pyz"):
            modules.extend(archive.open_embedded_archive(name).toc)
    if not modules:
        raise ValueError("Privileged Windows executable has no inspectable Python archive")
    assert_no_build_modules([*members, *modules])
    if _sha256(path) != digest:
        raise ValueError("Artifact changed during bootstrap inspection")
    return {"sha256": digest, "build_tools_absent": True,
            "python_module_count": len(modules), "archive_member_count": len(members)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("executables", nargs="+", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = {"schema_version": 1, "executables": [inspect_archive(path) for path in args.executables]}
    serialized = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.write_text(serialized, encoding="utf-8")
    else:
        print(serialized, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
