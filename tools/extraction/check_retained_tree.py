"""Validate that the Endpoint Platform tree retains no Helpdesk server code."""

from __future__ import annotations

import ast
import argparse
from pathlib import Path


PROHIBITED_TOP_LEVEL = {"server", "webapp", "mcp_helpdesk_server", "content_packs"}
PROHIBITED_IMPORT_PREFIXES = (
    "server",
    "webapp",
    "mcp_helpdesk_server",
    "content_packs",
)


def load_retained_paths(path: Path) -> set[str]:
    """Load non-empty retained paths with platform-neutral separators."""
    return {
        line.strip().replace("\\", "/")
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }


def imported_modules(path: Path) -> set[str]:
    """Return absolute module names imported by one Python source file."""
    tree = ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module)
    return modules


def check_retained_tree(repo_root: Path, retained_paths: set[str]) -> list[str]:
    """Return sorted source-boundary violations without changing *repo_root*."""
    violations: list[str] = []
    for name in sorted(PROHIBITED_TOP_LEVEL):
        if (repo_root / name).exists():
            violations.append(f"prohibited path present: {name}")

    agent_root = repo_root / "pc_agent"
    if not agent_root.exists():
        return violations

    approved_shared_modules = {
        path.removeprefix("shared/").removesuffix(".py").replace("/", ".")
        for path in retained_paths
        if path.startswith("shared/") and path.endswith(".py")
    }
    for path in sorted(agent_root.rglob("*.py")):
        relative_path = path.relative_to(repo_root).as_posix()
        for imported_name in sorted(imported_modules(path)):
            if imported_name in PROHIBITED_IMPORT_PREFIXES or imported_name.startswith(
                tuple(prefix + "." for prefix in PROHIBITED_IMPORT_PREFIXES)
            ):
                violations.append(f"prohibited import in {relative_path}: {imported_name}")
            elif imported_name.startswith("shared."):
                module_name = imported_name.removeprefix("shared.").split(".", 1)[0]
                if module_name not in approved_shared_modules:
                    violations.append(f"unapproved shared import in {relative_path}: {imported_name}")
    return sorted(violations)


def main() -> int:
    """Run the source-boundary check for the repository containing this tool."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument(
        "--retained-paths",
        type=Path,
        default=Path(__file__).resolve().with_name("retained_paths.txt"),
    )
    args = parser.parse_args()
    violations = check_retained_tree(args.repo_root, load_retained_paths(args.retained_paths))
    for violation in violations:
        print(violation)
    return 1 if violations else 0


if __name__ == "__main__":
    raise SystemExit(main())
