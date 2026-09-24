# Windows Release and Module Contract Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Release a coherent Agent 3.2.65 and verify Setup provenance plus live ZIP update and rollback without local fixtures.

**Architecture:** The canonical module DTO defines the one input policy for Console and service clients. Setup and the canary wrapper record the same protected MSI evidence. The updater compares verified runtime payloads independent of transport metadata. Preflight validates installer and selected runtime as distinct identities.

**Tech Stack:** Python 3.14, Pydantic, PowerShell, WiX, PyInstaller, Windows services, pytest, React tests.

**Spec:** `docs/superpowers/specs/2026-09-24-windows-release-and-module-contract.md`

## Review Focus

- A ZIP rollback to an identical MSI runtime succeeds while extra or changed runtime files fail.
- Existing ZIP runtime manifests with conflicting source identity fail.
- Setup never reports `UPDATED` with stale or missing installer provenance.
- Preflight accepts a valid selected ZIP runtime without equating it to MSI version.
- A zero-input module operation works through the canonical API and Console.

## Task 1: Canonical zero-input module contract

**Files:** `endpoint_contracts/modules.py`, `endpoint_server/console/modules.py`, relevant contract and Console tests.

- [ ] Add a canonical DTO test that validates `inputs={}` for both operation types and rejects malformed input values.
- [ ] Run the new test and confirm its failure is the `min_length=1` constraint.
- [ ] Remove that constraint and replace Console-specific DTO subclasses with canonical DTOs.
- [ ] Run contract, Console, service-client, and module operation tests; inspect API schema impact.

## Task 2: Russian Windows tray

**Files:** `pc_agent/platform/windows/tray.py`, `pc_agent/tests/windows/test_tray.py`.

- [ ] Test all agent, endpoint, and update states for Russian status labels while keeping wire values unchanged.
- [ ] Confirm the new assertions fail against the English tray.
- [ ] Map validated enum values to Russian display text; localize menu actions and detail labels.
- [ ] Run focused tray tests and inspect the built tray on the local Windows desktop.

## Task 3: Existing MSI runtime rollback

**Files:** `pc_agent/platform/windows/updater_service.py`, `pc_agent/tests/windows/test_updater_service.py`.

- [ ] Test reuse of an existing MSI directory whose files equal the verified ZIP payload but which lacks the ZIP manifest.
- [ ] Confirm rejection remains for changed, extra, or missing files and incompatible existing ZIP metadata.
- [ ] Implement exact payload comparison with explicit metadata handling; preserve path and ACL guards.
- [ ] Run focused updater tests, then test a real rollback without a temporary manifest.

## Task 4: Universal Setup installer evidence

**Files:** `packaging/windows/build-setup.ps1`, `pc_agent/pyinstaller_windows_setup.spec`, `pc_agent/platform/windows/setup_entry.py`, a focused provenance helper, and setup/packaging tests.

- [ ] Test that Setup embeds a release manifest matching the signed embedded MSI SHA-256.
- [ ] Test successful new install, repair, and upgrade record protected MSI cache and provenance before success is reported.
- [ ] Test mismatched hash, product code, selector, or failed evidence write produce a bounded failure or repair outcome.
- [ ] Implement a fixed-path provenance writer shared in contract with the canary wrapper; retain previous verified evidence on failed staging.
- [ ] Build and inspect a signed 3.2.65 Setup and MSI from committed source.

## Task 5: MSI and ZIP diagnostic preflight

**Files:** `tools/canary/Collect-WindowsAgentPreflight.ps1`, `tools/canary/verify_installed_windows_agent.py`, focused tests.

- [ ] Test MSI-selected and ZIP-selected runtime projections, including a newer ZIP above the installed MSI.
- [ ] Test forged or missing updater receipt, bundle manifest, source revision, or protected ACL is rejected.
- [ ] Update the projection schema and validation so MSI provenance and active runtime are checked independently.
- [ ] Run focused verifier tests and collect live local preflight after each runtime transition.

## Task 6: Coherent server rollback and live acceptance

**Files:** production deployment assets and release records only after source and artifact verification.

- [ ] Preserve verified production release `758043d02f3b` as the rollback target for the next server deployment. Older `590e1ea` is incompatible with already published zero-input module data, and `a49cd5a` is code-incoherent.
- [ ] Back up the production database and release marker, deploy the new coherent release, verify the selected rollback artifact and marker, then run HTTPS and Console acceptance checks.
- [ ] Run full repository checks, review the complete diff, and create atomic Conventional Commits.
- [ ] Verify signed Setup 3.2.65 on the local Agent and `READY` with new provenance.
- [ ] Register a newer ZIP canary, use Console for one-device update and rollback to 3.2.65 without local fixtures, and confirm both targets `applied` plus local service/TLS/WSS evidence.
- [ ] Verify remote `main`, artifact hashes, rollback readiness, and clean working tree.
