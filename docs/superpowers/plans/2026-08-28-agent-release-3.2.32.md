# Endpoint Agent 3.2.32 Release Transition Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce reviewable, unsigned, immutable ALT RPM and Windows MSI evidence for the headless Endpoint Agent at version 3.2.32.

**Architecture:** A dedicated branch advances only the immutable runtime identity. The Windows initial-runtime manifest is generated from an actual isolated PyInstaller staging tree and source hashes; the clean committed branch is then used for the documented MSI build. The ALT RPM is built only in a `mktemp` workspace on the explicitly authorized staging build host, then copied to a local isolated evidence directory and removed remotely.

**Tech Stack:** Python 3.14.3, PyInstaller 6.19.0, WiX 4, ALT rpm-build, SHA-256, Git source revision.

**Spec:** Delegated immutable artifact release-preparation stage authorized by the user on 2026-08-28.

## Global Constraints

- Start from `origin/main` commit `0b0a19c6b8c0bb3aba6b17396f069ffbc505f066`; never commit directly to `main`.
- Advance `AGENT_VERSION` monotonically to `3.2.32` and use a newly generated canonical Windows component GUID.
- Generate every source hash and artifact-tree fingerprint from the actual isolated build; do not invent values.
- Use `osn-admin@192.168.101.70` only for temporary unsigned RPM build files under `mktemp`; do not install, start, stop, configure, deploy, publish, sign, or access secrets.
- Build the Windows MSI in dedicated local staging roots, preserve the fixed stable UpgradeCode and upgrade transition behavior, and do not run the canary installer.
- Package only the headless runtime: no Helpdesk modules, Qt, GUI, or legacy `ws_agent` runtime.
- Do not upload, publish, sign, or expose credentials/private keys.

---

### Task 1: Immutable Windows identity

**Files:**
- Modify: `pc_agent/version.py`
- Create: `packaging/windows/initial-runtime-3.2.32.json`
- Modify: `tests/packaging/test_initial_runtime_contract.py`

- [ ] Write and run a failing test requiring the checked-in current transition to be 3.2.32 with an approved source transition.
- [ ] Build the headless Windows core in a dedicated temporary staging tree and calculate its exact artifact identity.
- [ ] Generate the new manifest from the build tree, current source hashes, pinned toolchain identity, and a fresh canonical GUID.
- [ ] Re-run the manifest contract tests and verify the clean committed source can drive the documented MSI builder.

### Task 2: Isolated unsigned artifacts

**Files:**
- Verify only; no source changes.

- [ ] Build the documented MSI from clean committed source into a dedicated local WiX root and record its redacted SHA-256/release sidecar.
- [ ] Transfer a Git archive of the same committed source to a `mktemp` directory on the authorized ALT build host and run the documented RPM build.
- [ ] Inspect RPM metadata/file list and retrieve only the unsigned RPM plus safe manifest evidence into a dedicated local output directory.
- [ ] Remove the exact remote temporary workspace and record cleanup.

### Task 3: Release gates and delivery

**Files:**
- Verify only; no source changes.

- [ ] Run headless/import-boundary, Windows component/upgrade, ALT manifest, selector/upgrader, contract-generation, lint, and diff checks.
- [ ] Inspect the complete diff and local artifact hashes; do not stage binary artifacts.
- [ ] Commit the source-only transition atomically, push normally, and create a draft PR against `main`.
