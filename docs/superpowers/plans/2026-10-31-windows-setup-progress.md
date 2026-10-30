# Windows Setup progress implementation plan

**Goal:** Automatic156 admission and a visible, explanatory Windows installer.
**Architecture:** Existing state machine emits bounded progress; a native Win32
window consumes it on its own thread. Installation remains on the main thread.
**Tech stack:** Python, ctypes/Win32, existing PowerShell/PyInstaller builder.
**Spec:** ../specs/2026-10-31-windows-setup-progress-design.md

## Constraints and review focus

- Preserve native transactions, elevated-token semantics and protected identity.
- Quiet/preflight/recovery must never create UI; UI failure must be explicit.
- No secret or arbitrary server text enters progress, logs or labels.
- Timeout and failure messages must name the failed stage and next action.
- New installer identity must not overwrite immutable156 or158 bytes.

## Tasks

- [x] Validate and apply one audited AUTO mode correction using the deployed
  selector for all254 source addresses, preserving other campaigns.
- [x] RED/GREEN bounded progress/state-change and timeout tests in
  pc_agent/tests/windows/test_setup_progress.py; implement pc_agent/setup_progress.py
  and observer integration in pc_agent/windows_setup.py.
- [x] RED/GREEN window lifecycle and headless tests; implement
  pc_agent/platform/windows/setup_progress_ui.py and setup_entry.py integration.
- [x] Add explicit installer-only revision support to packaging/windows/build-setup.ps1;
  exercise release/payload identity and immutable MSI rules in packaging tests.
- [x] Update CODEMAP and packaging documentation; run focused agent/packaging
  suites and inspect native UI. Commit reviewed task files to bind build source.
- [x] Build and sign the distinct156+setup.1 artifact from exact156 payloads.
  Verify signatures, hashes, embedded identities and bootstrap closure.
- [x] Qualify the artifact on domain Windows; publish immutable release and add
  its exact release ID to the same campaign only after qualification; verify
  unique AUTO selection again and preserve rollback evidence.

## Execution ledger

Ruling: use an installer-only revision, preserving runtime versions, because the
requested change concerns Setup and the user explicitly needs156 enrollment.
Ruling: execute inline; request one independent whole-change review at completion.

Qualification ruling: signed domain existing-device and native UI lifecycle checks passed; B2 fresh enrollment and pixel visual acceptance remain explicitly unverified in the report.
