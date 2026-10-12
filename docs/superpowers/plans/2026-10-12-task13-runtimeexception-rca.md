# Task13 RuntimeException investigation and fix

**Goal:** Identify the failed operation after FACTS.CACHE_FINAL and correct a
proven implementation defect without another seq04 dispatch.

**Architecture:** Preserve the exact F source/outcome and occupied recovery
slots. Use separately reviewed, bounded read-only field observations and owned
Windows PowerShell 5.1 reproductions. Any diagnostic output remains incapable
of creating a receipt or admitting forward execution.

**Spec:** Current user request: find the exact cause, fix it, preserve claims,
historical evidence and guards, and do not repeat seq04.

## Constraints

- Original claims, the two occupied recovery slots and historical evidence
  remain byte-for-byte intact. No reset, reissue, replacement or retry.
- Original plan/seal/deadlines/00–03/Facts/baseline/snapshot stay immutable.
- No marker, restore, MSI/Setup invocation, Agent change or rollout.
- No weakening of identity, source, transport, baseline or watchdog predicates.
- Recorded F failure remains UNKNOWN unless evidence identifies its operation.
  A current diagnostic failure alone does not invent missing historical detail.
- Probe sources and exact sealed stdin/argv must receive independent review
  before target observation. Private values and hashes stay out of stdout/docs.

## Steps

- [x] Verify exact failed source and retained native outcome.
- [x] Independently review a short baseline/cache/private-state probe that
      excludes Facts, PublicProof and every execution dispatcher.
- [x] Observe only reviewed fields; verify unchanged history and occupied slots.
- [ ] Follow the evidence with the smallest separately reviewed observation or
      local reproduction needed to identify the failing operation.
- [ ] Write a native regression that fails for that specific defect.
- [ ] Apply one minimal fix with all original safety predicates retained.
- [ ] Run native regression and affected Task13 suites; independent source review.
- [ ] Commit code/tests/report and report proven cause, limits and exact SHA.

## Review focus

Diagnostic probes must not become an alternate execution route around consumed
claims. Raw baseline/private state must not leak. Retained source/history handles
and exact argv/packet pins must prevent substitution. An actual baseline/state
change must continue to fail closed rather than be normalized away.
