# Setup target recovery client implementation plan

> **For agentic workers:** Use superpowers:executing-plans for inline implementation. Use the existing canonical recovered-target contract; do not invent a successful native outcome.

**Goal:** Close a failed native21 assignment automatically after its exact target
has completed native recovery, preserving the original error and source history.

**Architecture:** Extend the existing signed PowerShell observer as1.0.7, keeping
server/native ownership and proof requirements. Admit only the exact qualified
observer versions1.0.6/1.0.7 on the already deployed recovered-target server route.
No ordinary Core bridge is used to recover an assignment that requires its
original MSI-owned Core version. Existing clients need separately authorized
client-only installation; future full Setup packages include the new observer.

**Tech stack:** Windows PowerShell5.1, existing Python3.12 server, canonical
SetupProgressV1 and existing Authenticode packaging. No dependency or schema change.

**Spec:** `docs/verification/2026-11-06-setup169-187-readonly.md` and
`endpoint_contracts/setup_updates.py` recovered-target proof contract.

## Constraints

- Preserve native_exit21, attempt, source, timestamps, private baseline and source
  companions. Only ordinary observer phase/report/observation data may advance.
- Require exact target Core/Foundation/version/source/MSI-origin and preflight
  verification, accepted stage matching original native execution interval,
  original source Foundation, bound finished-continuation receipt and no active
  native/Core hold. Reject unknown exits or unrelated transactions.
- Fresh180second/six-sample observation must contain an active real Sensor,
  stable services/companions, fresh connection and unchanged private material.
- Emit failed/native_failed_target_recovered, never APPLIED/native0. Preserve
  missing/unhealthy evidence as recovery_required/native_exit_requires_recovery.
- No SSH writes on187 before explicit narrow client-only approval. Original
  signed169 artifacts remain immutable; source qualification remains distinct.

## Tasks

- [x] Add RED PowerShell observer tests for the exact recovered target and every
  authority/private/soak/retry rejection. Implement strict client1.0.7 branch;
  preserve1.0.6 source-failure behavior. Capture target companions separately
  from the source history and force a fresh observation epoch.
- [x] Add server RED compatibility tests for107 and explicit rejection of
  unqualified versions. Admit106/107 only; retain all native/telemetry guards.
- [x] Review source diffs independently and run observer/native/server contracts.
  Sign a new immutable107 payload; do not overwrite106. Prepare a narrow187
  install proposal that preserves Core169/Foundation169/job/attempt/native21.
- [x] After the client-only exception is authorized, install107 through the
  reviewed scoped task-action/metadata replacement, observe the original assignment and user telemetry,
  and preserve FAILED history. No hand-edited job/native receipt or MSI replay.
- [ ] Build a distinct full-Setup candidate with Tray fix and diagnostic fields
  plus107; qualify exact sources through Endpoint before enabling max2 waves.

## Review focus

- An old/unrelated accepted transaction must not close the current assignment.
- A stale target soak or absent logged-on user must not release the slot.
- A companion context must not replace preserved source-companion history.
- Lost report acknowledgements must retry the report without native replay.
- Delivery must preserve the MSI169 selection required by the original proof.

## Execution evidence

Client commit411b19625e97fd196d84bd1f4cdda28a16c0b614, server qualification
commit3b91c7a8f485d3ed747c91feaaca6db8ea13df04. Server Setup/contract checks:
280passed/19disposable-PostgreSQL skips. Final packaging/native/bootstrap checks:
209passed. Contract artifacts --check passed. Independent review findings in
canonical array/control serialization, initial/mid-soak user loss and fresh
post-soak hello were corrected and regression-tested before signing.

Signed10777427bytes SHA256
8a1a30e7d208fbb431e2f715967d8a21eb82eac43edbfb4e97433a83049a6247,
timestamped Valid, same pinned publisher. Native packaged-payload/source binding
was checked. The scoped helper is prepared, reviewed and signed. Six isolated
integration fixtures and13namespace fixtures passed, including independent
metadata rollback after task rollback failure. At the signing checkpoint neither
script had been uploaded/executed on187. The later explicit client-only
authorization has now been executed and verified; see the recovery proposal's
execution section.

Ruling: do not use ordinary Core170/return ZIP169 delivery. Active Setup ownership
blocks it, and changing the MSI-owned169 Core would invalidate the original
recovered-target proof. This case needs a separately authorized client-only
replacement, with no fake pending assignment or native receipt. The normal
Core bootstrap Install mode remains gated by a genuine Core assignment.

After power returned, the retained native AtStartup task completed original
continuation at2026-11-06T05:55:22Z. Original169 stage is accepted, hold absent,
finished receipt present; jobnative_exit21 remains. UserSensor/Activity were
fresh again at06:25Z after ordinary login. This is recovery, not source158
unattended qualification or APPLIED. The earlier Foundation invariant cause is
still unknown; source9aade90 adds safe detail for the next full Setup candidate.

Final107 evidence: original job closed FAILED/native_failed_target_recovered at
2026-11-06T07:04:07Z with native21 preserved,183.588seconds/6samples/1Sensor,
maxCPU0.0128%, all private/native/service/companion checks verified. Exactly one
failed audit; active chains0. New full Setup170 remains the next independent
qualification stage; no fleet policy or enrollment promotion occurred.
