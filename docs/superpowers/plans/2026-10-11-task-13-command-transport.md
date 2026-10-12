# Task 13 command transport implementation plan

> **For agentic workers:** Use superpowers:executing-plans for inline implementation and superpowers:requesting-code-review for independent review.

**Goal:** Deliver sealed execution through stdin, reject oversized commands before claims, and stop before seq04.

**Architecture:** Reuse the historical controller's exact-count gzip/base64 JSON packet factory. A compact verifier preserves its wire/body/source/parameter predicates and requires EOF before invocation. Seal the generated bootstrap and packet in the new source closure. When needed, the fully verified delivery script supplies the unchanged inner wire through a StringReader; the comparator wrapper and watchdog remain unchanged.

**Tech stack:** Python 3.12, Windows PowerShell 5.1, direct subprocess/OpenSSH.

**Spec:** User's Task 13 Command Transport Hardening request of 2026-10-11.

## Constraints

- Baseline `0f747edee76bd29fb38d0462a790a4b5fcfcdbcc`; no runtime 3.2.82 change, mass rollout, seq04, marker, restore or new execution authorization.
- Original continuation bundles, Facts, plan, receipts00-03, baseline, snapshot and consumed claims stay immutable.
- Full quoted UTF-16 command with NUL and remote shell command must be below 8192 units. No cmd.exe invocation or policy change.
- Read-only preflight uses an independent observation closure; it must not issue a seq04 capsule or admit execution through prior consumed authority.

## Review focus

- Non-BMP characters and quoting must count UTF-16 units, including NUL.
- Truncated, appended, wrong-size/hash/source/parameter packets must never invoke their script.
- Command mutation at the last dispatch guard must prevent Popen.
- Every generated command must be checked before either claim; no recovery of existing claims.
- Nested wire must remain byte-identical and keep existing continuation/identity/watchdog validation.

## Task 1: Delivery and command admission

- [x] Add `test_task13_command_transport.py`; prove historical 34172 command fails admission and existing delivery cannot satisfy short-bootstrap behavior (RED).
- [x] Add compact sealed-packet verifier and source factory in `sources.py`, reusing `prefix.controller.guest_transport`; retain generated delivery entries in `operations.py`.
- [x] Add `validate_command`, `powershell_argv`, `validate_command_plan` in `transport.py`; check before claims in supervisor/loader and again just before Popen.
- [x] Route entry operations through their sealed delivery bootstrap/packet without changing wrapper, wire, authority, identity, watchdog or receipt predicates.
- [x] Run packet negatives and claim-boundary tests on PowerShell 5.1/Python 3.12 (GREEN), then relevant continuation suite and `git diff --check`.

## Task 2: Independent acceptance, STOP

- [x] Review implementation and exact transport closure in a fresh reviewer context; resolve material findings.
- [x] Run only synthetic delivery payload on the dedicated Windows VM; retain native exits, exact command sizes and packet failures.
- [x] Independently review a read-only preflight harness; verify historical four checkpoints and current guest/provider/snapshot/baseline, with before/after preservation hashes.
- [x] Commit scoped implementation/tests and acceptance report; report full SHA, tests, command size and review evidence. Explicitly stop before seq04; a future attempt needs separate authority and existing replay guards still apply.
