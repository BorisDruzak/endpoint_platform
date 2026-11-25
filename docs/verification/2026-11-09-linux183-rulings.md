# Controller rulings for Linux support and lifecycle

These decisions resolve implementation and test-plan details within the approved
scope. The [acceptance report](2026-11-09-linux183-native-canary.md) distinguishes
successful results from retained failures. Original detailed reasoning and
receipts remain in the plan evidence workspace. No ruling replaces enrollment
authority, native recovery ownership or strict host verification.

1. **Historical Linux claim compatibility.** Re-derive fresh hardware proof in
   the original Claim HMAC context under explicit administrator approval, with a
   consumed claim on the same confirmed removed Device. Never invent a missing
   EnrollmentRequest or relax Windows checks. The actual legacy29a8 comparison
   failed and was preserved; the relationship was not forced.

2. **Lease continuity.** Ordinary Linux native rebind may resume only the original
   unchanged, positively authorized lease deadline. Expired or absent authority
   remains disabled; manual disable, revoke and reset take precedence. Only a
   pristine new registration can receive one initial grant of at most eight hours.

3. **Bootstrap before Core.** A source-qualified enrolled request, consumed claim
   and permanent credential can authorize initial Linux bootstrap before the
   first Core/WSS/Context report. A conflicting canonical Context still refuses.
   This removes an inventory dependency without admitting unbound legacy devices.

4. **Gateway boundary.** Permit the protected production gateway or the explicitly
   opted-in same-origin staging gateway only. Keep the three staging client gates
   and exact hostname/port pin. Do not modify ordinary SSH or Windows behavior.

5. **Tunnel status.** Support owns a bounded native OpenSSH forwarding-success
   acknowledgement correlated to its child process and expected socket tuple.
   Clear it on child death or policy change. A tunnel acknowledgement is separate
   from an actual administrator command and from the operator's attestation.

6. **Staging integration.** Preserve Stage Worktime through a separate staging-only
   integration branch in the existing isolated worktree. Use a genuine merge
   migration for its original schema heads. Never promote that overlay as the
   canonical production provider or modify another user worktree.

7. **Verification split.** Split the slow broad verification into the Windows
   non-PostgreSQL suite and guarded same-host disposable PostgreSQL checks, with
   exact source closure and explicit skips. Preserve the interrupted partial run;
   do not present it as a completed green suite or repeat global migrations.

8. **Authentication timing defect.** Correct the confirmed shared-auth clock race
   in an atomic fix: use one aware issuance instant for bounded token lifetime and
   strict deadline validation. An elapsed deadline rejects authorization; it does
   not create a longer session or a fabricated administrator. Verify RED/GREEN and
   existing consumers because this touches shared authentication.

9. **Immutable182 candidate.** Build a distinct182 after the session-property fix;
   preserve all signed181 bytes. Archive and verify completed public SDK/source
   caches off-host before removing only those owned copies. Do not purge product
   identity, ownership markers, native journals or private history.

10. **Bounded build scratch.** Use an explicitly owned Root0700 tmpfs of at most
    1024MiB with nodev/nosuid and bounded build resources after measuring available
    memory. Keep private product identity and signing keys outside scratch. Its
    removal requires retained inputs, off-host media and no process references.

11. **Actual rollback/return repetition.** Repeat the real retained-identity156
    rollback and182 return after session restoration changed. Use measured package,
    cache and executor footprint rather than an obsolete blanket free-space
    threshold. Preserve disk-failure evidence and unknown-native recovery guards.

12. **Positive full-wipe parent test.** Approve freshA independently after the
    legacy fingerprint refusal, then test the positive full-wipe relationship
    against that genuine canonical identity. Preserve the legacy card separately;
    never edit fingerprints or credentials to make a test pass. Remove an abandoned
    public extraction only after exact signed-entry verification and archival.

13. **Mixed disabled-policy provenance.** Extend the narrow provider correction
    to authenticated online unregister followed by offline native rebind when the
    independent reviewer reproduced that composition failure. Bind exact audited
    intent, credential, revision, generation and native ticket; refuse missing or
    unmarked history. This required a reviewed provider-only patch and repeated
    real online8/9 plus offline10/11 tests; signed183 bytes stayed unchanged.

14. **Evidence retention.** Preserve the plan evidence directory and active
    app-managed worktree after completion. The user's history/recovery requirements
    take precedence over generic skill cleanup. Stop owned temporary resources and
    remove verified redundant inputs; retain private receipts, archives and backups.
    The cost is retained local evidence, with no continuing temporary test worker.
