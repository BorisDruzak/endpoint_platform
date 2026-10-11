# Task 13 Identity Root Cause and Guard Recovery

> **For agentic workers:** Use superpowers:executing-plans, systematic-debugging and test-driven-development. Independent review precedes target observations.

**Goal:** Establish the single native identity failure before changing guard behavior;
prepare a new independently reviewed read-only canonical preflight if evidence
supports a minimal correction.

**Architecture:** Preserve failed bundle and consumed claim. A distinct diagnostic
procedure pins its source/runtime and the actual new human request. It performs
one read-only SSH identity probe with additional error/context evidence. Diagnostic
results grant no continuation or comparator authority.

**Tech stack:** Existing Python3.12, Windows PowerShell5.1, native Windows APIs,
strict pinned SSH transport. No dependency/version change.

**Spec:** The human Task13 IDENTITY_UNKNOWN Root Cause & Guard Recovery request,
stages A–D. Historical anchors and prior UNKNOWN remain immutable.

## Constraints

- No seq04, receipt04, foreign-process stop, service intervention or consumed claim reuse.
- An API failure or incomplete identity always stays UNKNOWN. Names and numeric
  PIDs alone never provide an exemption.
- Preserve plan/seal, receipts00–03, baseline/snapshot, native double-handle checks,
  observer/current/provider/checkpoint guards, validity duration and exact source pins.
- Do not infer a historical exception's exact cause from a later healthy probe.
- Diagnostics retain no command lines, TargetObject, invocation text or unrestricted messages.
- Stop target preflight work on UNKNOWN. Do not repeat the diagnostic probe.

## Stage A — Diagnostic evidence

- [x] Verify baseline and independently identify the failed classifier predicate.
- [x] Establish missing historical fields and separate proven facts from hypotheses.
- [x] Prepare and independently inspect one source/runtime-pinned diagnostic probe.
- [x] Run once through the unchanged SSH selector/security context; retain native raw evidence.
- [x] Record available API/error/context and determine whether the root cause is proven.

**Stage A outcome: exact historical RCA remains UNKNOWN.** The single new probe
completed without exceptions; the failed slot is now native/CIM absent twice.
The prior catch retained neither API stage nor ErrorRecord. An owned exited-process
experiment reproduces QueryFullProcessImageName error31 and RuntimeException,
but does not prove that this caused the historical VM failure. No speculative
guard change, further probe or canonical preflight is justified by that evidence.

## Stage B — Conditional minimal correction

- [ ] Only after cause determination, write its RED regression and minimal guard correction.
- [ ] Reject API failures, incomplete data, original-active, reuse/race ambiguity.
- [ ] Preserve historical bytes and every non-PID continuation invariant.

## Stage C — Verification

- [ ] GREEN actual-cause regression and repeat PID reuse/access/race/absence checks.
- [ ] Inspect complete diff, run relevant suite and commit scoped files.
- [ ] Obtain independent exact-source PASS.

## Stage D — Separate read-only preflight

- [ ] Prepare a fresh read-only package using the new request and immutable failed-attempt evidence.
- [ ] Do not use execution recovery admission or touch any consumed launch claim.
- [ ] Independently review package/source/runtime; reconcile all canonical constituents once.
- [ ] STOP on UNKNOWN. Report preflight evidence and seq04 eligibility YES/NO;
  execute no comparator and create no receipt04.

Stages B–D are **BLOCKED**, not completed. Existing guard regressions: 24 PASS.
There is no actual-cause RED→GREEN claim and no new full canonical preflight PASS.
Separate seq04 eligibility: **NO**. See the root-cause report for evidence bounds.
