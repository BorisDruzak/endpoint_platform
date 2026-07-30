# Linux Bundle Symlink Normalization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Allow the Linux release builder to turn safe PyInstaller onedir file links into regular, attestable bundle files.

**Architecture:** The builder will validate each source symlink before copying: its resolved target must be a regular file below the source `pc_agent/` directory. It copies target bytes to the link's logical destination, preserving the resolved target's POSIX mode. The resulting manifest and bundle tree contain only regular files; all unsafe links remain rejected.

**Tech Stack:** Python 3.12, pathlib, POSIX lstat/resolve, pytest, SHA-256.

## Global Constraints

- Final bundles contain only `launcher`, `pc_agent/`, and `manifest.json`; no symlink is ever emitted.
- A normalized symlink must resolve to a regular file inside source `pc_agent/`; top-level, dangling, directory, cyclic, and out-of-tree links fail closed.
- The manifest records the destination logical path, copied bytes, and resolved-file mode.
- No CA, claim, credential, endpoint, installer, service, or deployment behaviour changes.

---

### Task 1: Normalize safe PyInstaller onedir links

**Files:**
- Modify: `pc_agent/build_linux_release_bundle.py`
- Modify: `pc_agent/tests/test_linux_release_bundle.py`
- Modify: `pc_agent/docs/BUILD_AND_RUN_LINUX.md`

**Interfaces:** `assemble_bundle(source: Path, output: Path, version: str, revision: str) -> Path` continues to produce the same manifest schema 1 and directory layout.

- [ ] Write a failing test with `pc_agent/_internal/runtime-link.so` pointing to an in-tree regular runtime file; assert the resulting destination is non-symlink, has the target bytes/mode, and is attested.
- [ ] Run `python -m pytest pc_agent/tests/test_linux_release_bundle.py::test_assemble_bundle_normalizes_an_in_tree_payload_symlink -q`; expect failure because source symlinks are rejected.
- [ ] Change source collection/copying to resolve a payload link strictly beneath `source/pc_agent`, reject every other link class, and copy the resolved regular target without emitting a link.
- [ ] Add failing tests for an out-of-tree and top-level symlink; retain rejection coverage for unsafe links.
- [ ] Run `python -m pytest pc_agent/tests/test_linux_release_bundle.py pc_agent/tests/test_linux_packaging.py -q`; expect PASS.
- [ ] Update the Linux build documentation to distinguish transient PyInstaller source links from the all-regular final bundle.
- [ ] Commit: `fix: normalize PyInstaller bundle links`.
