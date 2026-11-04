# Clean156 to full158 and enrollment/telemetry defaults

> Execute inline with superpowers:executing-plans. User explicitly authorized full
> agent removal and clean signed156 installation to establish the source. Then
>156→158 must use Endpoint alone, with no preparatory ACL/client intervention.

**Goal:** Prove real Core/Foundation156→158 on test120; enable supported telemetry
by default; consolidate Windows auto-enrollment and default new release inclusion.

**Architecture:** Preserve native MSI/Setup ownership, authenticated Core/Setup
protocols and audit history. Keep baseline creation separate from update acceptance.
Use canonical policy assignments and a single Windows enrollment campaign. Reuse
typed release publication and append new releases in its transaction.

**Tech Stack:** Existing SQLAlchemy2/PostgreSQL, Pydantic2, signed Windows
PowerShell5.1/TaskScheduler, frozen signed156/158 installers; no dependency upgrade.

## Constraints

- Only101.120 may be removed/reinstalled or receive the canary upgrade.
- Preserve domain, ordinary-user/GPO state and historical server receipts.
- Remove old observer1.0.4 and previous owner workaround from the source baseline.
- A156 Core-only selector with Foundation158 is not the required source.
- Do not change an immutable MSI/Setup/Core artifact or fabricate terminal reports.
- Exactly one active Windows auto campaign; preserve CIDRs,expiry,quota counters
  and historical claims. Add all available trusted non-retired installer releases.
- Telemetry defaults cover supported activity/browser/DLP audit and WorkTime;
  unsupported removable-write capture remains outside the contract.
- Global defaults must be distinguished from actual APPLIED/fresh sensor evidence.

## Steps

- [ ] Native158 uninstall,absence proof and exact four-root purge. Retire/revoke
  only its confirmed server registration after uninstall;retain historical records.
- [ ] Install original signed156. If historical identity guard intervenes,approve
  only the fresh exact-host request on server while Setup waits. Prove native156,
  Core156,new authentication,no observer and untouched updater-root permissions.
- [ ] Tests first: telemetry config defaults with explicit-disable compatibility;
  transactional signed-release inclusion in the unique configured auto campaign,
  idempotency,missing/ambiguous/retired campaign and immutable digest refusal.
- [ ] Implement defaults in `endpoint_server/config.py`; new canonical enrollment
  helper plus `tools/register_windows_setup_release.py` publication hook. Update
  AGENTS/runbook and relevant tests. Pin libraries;test actual PostgreSQL behavior.
- [ ] Consolidate existing Windows campaigns to09e62472-a6ae-49ab-aaaa-6613836b4423
  with canonical audit/revocation and all available trusted versions. Preserve its
  existing network/expiry/quota;no campaign token is printed or persisted anew.
- [ ] Enable production telemetry gates and assign full supported audit defaults,
  updating existing limited overrides without resetting retention or user state.
  Verify delivered policy and advancing telemetry on live devices,test120 first.
- [ ] Assign the full158 preparation/update through Endpoint. No workstation SSH,
  owner/DACL repair,or observer installation after156 source acceptance. If it
  fails,record the actual gate and retain native ownership;do not mask it.
- [ ] Only after genuine156→158 acceptance,write the requested server auto-update
  implementation plan with qualification,rollout,hold/rollback,telemetry and
  publication/campaign gates. Otherwise record the specific blocker and required fix.
