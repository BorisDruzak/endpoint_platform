# Task 13 PID Identity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans task by task.

**Goal:** Distinguish original process instances from PID reuse without weakening continuation invariants.

**Architecture:** Pinned historical reference registry, native repeated read-only
observer, pure controller classifier and narrow original-predicate substitution.
An additional raw constituent participates in every current gate and receipt check.

**Tech Stack:** Existing Python3.12, PowerShell/native Windows APIs and strict SSH.

**Spec:** `docs/superpowers/specs/2026-10-11-task-13-pid-identity-design.md`.

## Constraints and review focus

- Immutable original artifacts and all non-PID predicates; unknown always BLOCKED.
- Missing saved birth is never reconstructed; pinned absence proof may establish reuse.
- Retained-handle race checks, errors and native/CIM agreement are mandatory.
- No plaintext command arguments, SSH service changes or seq04 execution in this stage.
- Independent exact-source PASS precedes final fresh VM guard reconciliation.

### Task 1: References, native observer and classifier

Files: new `tools/canary/task13_continuation/process_identity.py`, new
`tools/canary/Observe-Task13ProcessIdentity.ps1`, new identity tests.

- [ ] Inspect historical coverage and both live process identities read-only.
- [ ] RED tests: original instance, absent/reused PID, access denial, live SSH reuse,
  missing proof and exit/restart race.
- [ ] Implement pinned registry and repeated native observer; run GREEN tests.

### Task 2: Continuation integration and guard-only entry

Files: modify `reconciliation.py`, `operations.py`, `loader.py`, `bundle.py`,
`permission.py`, `supervisor.py`; add read-only gate entry and regression tests.

- [ ] RED invariant tests; add eighth constituent and exactly scoped AST substitution.
- [ ] Bind guard-only human permission and reject seq04 launch under that scope.
- [ ] Run complete relevant suite and inspect full diff; atomic source commit.

### Task 3: Independent review and fresh VM gate

- [ ] Create fresh offline protected package; independent exact source/registry review PASS.
- [ ] Run one fixed read-only reconciliation on VM after PASS; retain all raw results.
- [ ] Independently validate raw results and actual gate verdict.
- [ ] Report readiness/blockers and stop; seq04 remains a separate step.

### Task 4: Already authorized separate seq04 step after complete guard PASS

Ruling: the human already authorized one seq04 repeat and requires it as a separate
step after the full guard. Preserve the correction package's guard-only permission;
create a distinct execution package whose scope binds the same actual human message
and pinned prior gate admission. No additional approval is required. An independent
review of the new exact bytes and a fresh canonical preflight remain mandatory.

- [ ] RED -> GREEN prior gate admission and changed-evidence/scope refusal tests.
- [ ] Full suite, source/diff inspection and atomic execution-admission commit.
- [ ] New protected execution package and independent exact-source PASS.
- [ ] Execute only seq04 once with fresh canonical guard; preserve UNKNOWN if it fails.
- [ ] Verify real publication/root exit and stop before seq05 at the resume gate.
