# Task13 Additive Recovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Admit exactly one separately authorized recovery attempt without restoring consumed claims.

**Architecture:** Add a separate versioned admission/permission/ledger path and
separate bundle, creator, supervisor and receipt interfaces. Reuse unchanged
historical verification, sealed stdin transport, reconciliation and watchdog.

**Tech Stack:** Python3.12, Windows PowerShell5.1, native restrictive NTFS storage.

**Spec:** `docs/superpowers/specs/2026-10-12-task13-additive-recovery.md`

## Global Constraints

- Baseline47b688c; original plan/seal/deadlines/receipts/claims/Facts unchanged.
- No seq04, real execution claims, runtime/MSI/Setup changes, marker, restore or rollout.
- New slot uniqueness independent of CID/request/revision/deadline.
- All post-transition ambiguity is permanently fail-closed; no automatic retry.

## Review Focus

- Empty/truncated slot occupancy after process death; refuse permanent reuse.
- Parallel claim issuance from separate native processes; exactly one winner.
- Permission capture versus implementation-only/latest-message/replay/deadline.
- Source/packet/command or state substitution between preclaim and launch.
- Genuine recovery receipt cannot accept fabricated legacy dispatch authority.

## Tasks

1. [x] RED: missing recovery path; historic global-claim refusal remains RED.
2. [x] Implement pinned historical admission and native durable two-phase ledger;
   GREEN for normal consumed state, concurrency, restart, replay and malformed occupancy.
3. [x] Implement separate actual permission, offline packet/source/runtime preclaim
   checks and versioned bundle/creator/supervisor; negative guards before claims.
4. [x] Implement recovery receipt schema retaining genuine comparator/watchdog/root
   predicates; reject legacy authority projection and incomplete settlement.
5. [x] Run focused and existing Task13 regressions on Python3.12/PowerShell5.1;
   record exact failures separately from state-dependent historical permission cases.
6. [x] Independent security/source review; fix findings and repeat affected checks.
7. [ ] Commit exact scoped changes, produce read-only gate with preservation and
   readiness hashes; STOP without execution authorization or claims.

## Verification ledger

Tasks 1-6 complete: new recovery tests 73/73 PASS on Python 3.12; true native process contention and crash occupancy were exercised. Independent whole-source review closed canonical-root and child-cleanup P1 findings with RED-to-GREEN regressions. Ordinary tracked guards remain unchanged. Task 7 awaits committed closure and independently reviewed native read-only admission. Historical permission/state cases are reported separately; they are not weakened.
