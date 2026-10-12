# Task 13 UNKNOWN Recovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Admit only a proven pre-dispatch recovery and diagnose occupied known PIDs without weakening guards.

**Architecture:** A protected recovery record binds the failed attempt to a fresh
reviewed closure. The existing loader performs all unchanged live gates and dispatches
at most seq04. Read-only RCA evidence is retained independently of acceptance.

**Tech Stack:** Existing Python 3.12 tooling, PowerShell, native Windows protected storage and strict SSH.

**Spec:** `docs/superpowers/specs/2026-10-11-task-13-unknown-recovery-design.md`

## Global Constraints

- Exact original guards and historical bytes; only seq04 then STOP_BEFORE_SEQ05.
- No automatic retry, process cleanup, service restart, reboot or VM configuration change.
- Independent exact-source PASS before a repeat; runtime predicate PASS also required.
- No private process identities, command lines, topology or credentials in tracked files.

## Review Focus

- Failed root still running or raw terminal proof inconsistent: reject recovery.
- Partial watchdog/workload attempt or global original claim present: reject recovery.
- Retained failure evidence changes after review: reject before launch.
- PID reuse mistaken for permission to bypass absence: preserve original refusal.
- Source/procedure PASS mistaken for canonical receipt: report runtime gate separately.

### Task 1: Read-only RCA and recovery admission

**Files:** new `tools/canary/task13_continuation/recovery.py`, new
`tests/tools/test_task13_continuation_recovery.py`; modify `bundle.py`, `loader.py`,
`permission.py`, `supervisor.py` in that package.

- [x] Retain bounded read-only identity observations and compare historical births.
- [x] Write negative tests for phase contamination, bad terminal proof, changed evidence and global claim.
- [x] Implement exact prior-attempt verification and protected manifest binding/holding.
- [x] Bind latest actual human authorization; preserve existing live predicates.
- [x] Run focused tests, full relevant suite and diff checks; commit scoped changes.

### Task 2: Independent review and bounded operational decision

**Files:** new sanitized recovery report; protected private closure/evidence only.

- [x] Build fresh offline bundle; obtain independent review of exact closure and RCA.
- [x] If original known-PID guard is still false, stop BLOCKED without workload or process termination.
- [ ] Otherwise execute one reviewed root, require full existing acceptance and stop before seq05.
  BLOCKED: fresh original current guard still refuses two occupied known PID numbers;
  no recovery-root launch or seq04 dispatch occurred. Resume gate not reached.
- [x] Record review, exact SHAs, tests, retained evidence and actual gate outcome.
