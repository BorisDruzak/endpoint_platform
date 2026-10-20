# Local changes reconciliation implementation plan

> **For agentic workers:** Execute the bounded reconciliation in this session; use independent source review before publication.

**Goal:** Reconcile the 32 commits not reachable from origin refs and every registered worktree, then publish only still-applicable changes to main.

**Architecture:** Start from origin/main, preserve all existing working copies, use patch identity and source/history comparisons, and port missing behavior without replaying obsolete versions or environment-specific settings.

**Tech stack:** Python 3.12, pytest, Windows provisioning, ALT RPM/systemd packaging.

**Spec:** User request to inspect the 32 commits and uncommitted changes in all working copies and push all current changes to main.

## Constraints

- Preserve pre-existing worktree contents, branches, claims, receipts and artifacts.
- Do not execute installers, provisioning controllers, acceptance sequences or deployments.
- Keep current runtime versions, fixed pilot targeting and fail-closed validation.
- Preserve both the legacy offline ALT handoff and the native headless RPM credential path.
- Never publish local WiX dependencies, line-ending churn or temporary checkout deletions.

## Review focus

- Patch-equivalent changes must not be counted as missing because SHAs differ.
- Older release pins must not replace the current runtime or fixture authority.
- Windows origin persistence must complete before service start and claim removal.
- ALT package validation must reject tampered, mixed or unexpected payloads before SSH.
- ALT claim delivery must select the path required by the corresponding service layout.

## Tasks

- [x] Snapshot all 72 registered worktrees and map exact patch equivalents for 32 local commits.
- [x] Verify remaining commits against current source/history; record one disposition per SHA.
- [x] Recover Windows origin persistence with a failing regression followed by the minimal existing atomic-write implementation.
- [x] Recover headless ALT pilot input support and layout-specific credential delivery, retaining the offline flow; verify failures before implementation.
- [x] Restore the ALT prebuilt-payload RPM protection without obsolete release pins.
- [x] Update the stale cancellation and agent module boundary documentation.
- [x] Run focused tests, generated-contract verification, compile checks and complete diff/secret review.
- [x] Obtain independent review and fix the staging traversal finding with a failing regression followed by the green affected suite.
- [x] Prepare atomic commits and the 32-row reconciliation report.

Publication receipt: after the final documentation commit, fast-forward push to
main and verify the remote SHA plus preservation of original worktrees. Record
that final receipt in the task response; this plan does not predict the remote
result before the push.

## Execution rulings

- User authorization covers publishing current adaptations; historical branches are retained rather than merged wholesale.
- GitNexus MCP was attempted twice but its configured endpoint timed out. Source, tests and Git history provide the fallback evidence; no index synchronization is requested.
- Context7 was attempted for Python/systemd/RPM documentation but its monthly quota was exhausted. Official documentation and installed toolchain behavior are used where applicable.
- Final review identified a real staging traversal failure inherited by the new headless path. Move only the public bundle outside the root-only input directory, retain service-user fingerprint execution and private input protection, and stop staging on the first filesystem failure. The regression failed before this fix and the affected suite then passed 256 tests with one platform skip.
