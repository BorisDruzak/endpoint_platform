# Task 13 read-only recovery with retained UNKNOWN

> **For agentic workers:** Use superpowers:executing-plans and test-driven-development. Exact-source independent review precedes target contact.

**Goal:** Add bounded identity failure diagnostics and run one fresh independently
reviewed canonical read-only preflight while preserving historical RCA UNKNOWN.

**Spec:** Actual human authorization: new recovery scope, no guard weakening,
independent review, fresh read-only canonical preflight, no seq04 and no consumed
claim reuse. No routine permission pause is needed.

**Architecture:** Diagnostic metadata is separate from unchanged native identity
rows. A distinct read-only recovery record holds the failed execution bytes and
consumed claim as immutable evidence. It creates no execution recovery admission.
The actual new request binds only the read-only entry; both execution entries deny
this scope before mutations. Canonical reconciliation still requires all eight
constituents and all historical/source/runtime/clock predicates.

**Tech stack:** Existing Python3.12, PowerShell5.1, native APIs, strict pinned SSH.

## Review focus

- Missing/denied API, race, original-active and malformed identity remain blocking.
- Diagnostic state or message can never override the controller's classifier.
- Keep plan/seal/receipts00–03/baseline/snapshot byte-identical.
- Keep old UNKNOWN and consumed claim byte-identical; refuse receipt/dispatch evidence.
- Only the new actual human request permits this scope; no caller quote or conversion to execution.
- Preserve 1200-second duration, runtime/source pins, native identities and full raw envelopes.
- No command lines, TargetObject, invocation text or unrestricted exception messages in diagnostics.
- STOP on any UNKNOWN; no probe/preflight retry and no receipt04.

## Tasks

- [x] RED tests for error31 diagnostic retention and unchanged UNKNOWN classification.
- [x] Add bounded per-call stage/native error/ErrorRecord/partial sample metadata.
- [x] RED tests for read-only scope, consumed-claim preservation, changed evidence and execution refusal.
- [x] Add read-only recovery capture/retention and actual new permission binding.
- [x] GREEN regressions plus full relevant suite, complete diff/check and atomic commit.
- [x] Prepare a new offline protected package and obtain independent exact-source/runtime PASS.
- [x] Run one fixed reviewed read-only canonical preflight; retain all eight transports.
- [x] Independently validate current results, historical bytes and unchanged claims.
- [x] Report full preflight status, evidence hashes, historical RCA UNKNOWN and seq04 NO.

Completed: implementation `7b4bebc4b5af67770f5a0bcdd6de8bc81c1a7f71`,246 tests PASS, independent source and runtime review PASS, one fresh canonical preflight PASS. Historical RCA UNKNOWN; consumed claim unchanged; seq04 NO. See `docs/superpowers/reports/2026-10-11-task-13-readonly-recovery.md`.
