# ALT Linux Agent Bundle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development task-by-task. Steps use checkbox syntax.

**Goal:** Deliver the existing Linux launcher plus onedir agent as a verified ALT offline bundle and validate it on `test-agent-lin`.

**Architecture:** A Linux builder invokes the existing PyInstaller specs, assembles `launcher`, `pc_agent/`, and `manifest.json`, then writes a transient artifact. The ALT installer verifies this manifest before mutation and atomically selects a complete launcher/onedir version under `/opt/endpoint-agent`; systemd starts the launcher.

**Tech Stack:** Python 3.12, PyInstaller, Bash, systemd, pytest, SHA-256.

## Global Constraints

- Bundle is exactly `launcher`, `pc_agent/pc_agent`, its required onedir contents, and `manifest.json`; no CA, claim, token, URL, or configuration.
- Manifest schema 1 contains bounded release version, source revision, and sorted `{path, sha256, mode}` for every regular payload file.
- Symlinks, traversal, unexpected paths, missing leaves and digest mismatch fail before user or host mutation.
- `endpoint-agent.service` starts `/opt/endpoint-agent/launcher`, never a raw payload executable.
- Failed activation restores complete prior selection and `current.json`.
- Artifacts are transient and never committed. First live install is only on `test-agent-lin` after all task reviews pass.

---

### Task 1: Linux release-bundle builder

**Files:**
- Create: `pc_agent/build_linux_release_bundle.py`
- Create: `pc_agent/tests/test_linux_release_bundle.py`
- Modify: `pc_agent/docs/BUILD_AND_RUN_LINUX.md`

**Interfaces:** `python -m pc_agent.build_linux_release_bundle --version VERSION --output DIRECTORY` produces `endpoint-agent-VERSION/{launcher,pc_agent/,manifest.json}`.

- [ ] Write failing tests for a sorted complete manifest and rejected symlink/unexpected source entry.
- [ ] Run `python -m pytest pc_agent/tests/test_linux_release_bundle.py -q`; expect import failure for `pc_agent.build_linux_release_bundle`.
- [ ] Implement `assemble_bundle(source, output, version, revision) -> Path`: validate bounded version/revision, copy only regular files, require launcher and `pc_agent/pc_agent`, calculate SHA-256 and atomically write sorted manifest.
- [ ] Add CLI that invokes existing `pyinstaller_launcher_linux.spec` and `pyinstaller_agent_linux.spec` only in explicit build mode; tests use fixture payloads only.
- [ ] Run `python -m pytest pc_agent/tests/test_linux_release_bundle.py pc_agent/tests/test_linux_packaging.py -q`; expect PASS.
- [ ] Document Linux build inputs, transient output, manifest inspection and no-secret rule.
- [ ] Commit: `build: add Linux agent release bundle`.

### Task 2: Verified bundle installer and launcher service

**Files:**
- Modify: `deploy/agent/alt/install-endpoint-agent.sh`
- Modify: `deploy/agent/alt/endpoint-agent.service`
- Modify: `docs/runbooks/ALT_AGENT_INSTALL.md`
- Create: `tests/deploy/test_alt_agent_bundle_install.py`
- Modify: `tests/deploy/test_alt_agent_package.py`

**Interfaces:** Replace `--agent-binary FILE` with `--agent-bundle DIRECTORY`. Install `/opt/endpoint-agent/launcher`, `/opt/endpoint-agent/versions/VERSION/pc_agent/`, and `current.json`.

- [ ] Write failing tests: a digest mismatch fails before `useradd`; symlink/incomplete onedir fail; service `ExecStart` contains launcher; restart failure restores previous launcher, version directory, and `current.json`.
- [ ] Run `python -m pytest tests/deploy/test_alt_agent_bundle_install.py tests/deploy/test_alt_agent_package.py -q`; expect RED for absent bundle input/launcher contract.
- [ ] Implement manifest parser/verifier: exact path set, all regular source files, hash/mode checks, no links/traversal/unexpected paths; invoke it before account, directory, or systemd mutation.
- [ ] Stage and re-verify complete bundle, fsync and atomically select launcher/version/current JSON; retain and restore prior complete selection on service activation failure.
- [ ] Keep config/CA/claim and permanent-credential ownership contracts unchanged; update runbook dry-run/install commands to `--agent-bundle`.
- [ ] Run `python -m pytest tests/deploy/test_alt_agent_bundle_install.py tests/deploy/test_alt_agent_package.py tests/deploy/test_alt_agent_finalizer_protocol.py -q`; expect PASS.
- [ ] Commit: `feat: install verified ALT agent bundles`.

### Task 3: Isolated Linux harness

**Files:**
- Create: `tests/deploy/verify_alt_agent_bundle_linux_harness.sh`
- Modify: `tests/deploy/test_alt_agent_bundle_install.py`

**Interfaces:** Harness runs rewritten installer under `mktemp -d`, stubbed `systemctl` and `useradd`; it never touches actual `/etc`, `/opt`, systemd or accounts.

- [ ] Write a failing wrapper test for missing `_internal`, digest mismatch, symlink, restart failure rollback and idempotent second install.
- [ ] Run the wrapper test and verify RED because the harness is absent.
- [ ] Implement the harness with a valid fixture bundle and scenarios above; emit only status/digests, never claim or permanent credential values.
- [ ] Run `python -m pytest tests/deploy/test_alt_agent_bundle_install.py tests/deploy/test_alt_agent_package.py -q`; expect PASS. Run the harness on Linux before remote installation.
- [ ] Commit: `test: verify ALT bundle installation on Linux`.

### Task 4: Reviewed test-host acceptance

**Files:**
- Modify: `docs/runbooks/ALT_AGENT_INSTALL.md`
- Create: `docs/runbooks/evidence/2026-07-30-alt-bundle-test-host.md`

- [ ] Re-run local gates: `python -m pytest tests/deploy/test_alt_agent_bundle_install.py tests/deploy/test_alt_agent_package.py tests/deploy/test_alt_agent_finalizer_protocol.py pc_agent/tests/test_linux_release_bundle.py pc_agent/tests/test_enrollment_bootstrap.py -q`.
- [ ] Read-only verify `test-agent-lin` OS, free disk, systemd and absence of unexpected existing pilot installation; abort if unsafe.
- [ ] Build/attest a Task 1 release bundle in the Linux test environment; record revision/version and manifest/archive SHA-256 only.
- [ ] Use approved web controller for one-time claim source then run installer with explicit HTTPS CA and `--agent-bundle`; verify redacted service/enrollment/finalizer evidence.
- [ ] Restart service, verify stable identity, baseline collection, controlled update and rollback using a second reviewed bundle.
- [ ] Commit evidence only after success: `docs: record ALT bundle test-host acceptance`.
