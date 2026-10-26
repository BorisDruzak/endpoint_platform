# Windows installer owner and recovery implementation plan

> Execute inline using superpowers:executing-plans; use TDD for the correction.

**Goal:** Correct elevated Setup installation and verify recovery on A2-INFAN-N.
**Architecture:** Scoped effective-token privilege for exact owner preservation;
diagnostics outside the protected enrollment data tree; existing recovery authority.
**Tech stack:** Python 3.12, pywin32, PowerShell, WiX 4, signed MSI/PyInstaller EXE.
**Spec:** docs/superpowers/specs/2026-10-26-installer-owner-recovery-design.md

## Global constraints

Preserve owner/DACL and private data. Restore privilege attributes. Never clear a
fence or weaken fresh-root checks. Same-PC installation is authorized; fleet
publication, GPO expansion and server deployment are outside this change.

## Review focus

Missing privilege; an impersonating caller; failed SetNamedSecurityInfo; a privilege
already enabled; diagnostic writes after a fresh-root failure.

## Task 1: Correct ownership transfer and diagnostics

- [ ] Add failing native NTFS privilege/owner regressions and failure/retry log tests.
- [ ] Implement scoped effective-token privilege and isolated Installer diagnostics.
- [ ] Run affected Windows, selector, provenance, Setup and packaging tests.
- [ ] Update CODEMAP/runbook, review the diff and commit the correction.

## Task 2: Build and accept on the original machine

- [ ] Produce source-bound signed candidate MSI/Setup with existing build tooling.
- [ ] Capture original machine state and preserve all diagnostic evidence.
- [ ] Recover exact interrupted 149 without bypassing original authority checks.
- [ ] Install corrected candidate; verify versions, services, result and enrollment/WSS.
- [ ] Repeat Setup and verify the successful rerun, or report the exact remaining gate.
- [ ] Record exact commands, artifact hashes and observed outcomes; independent review.
