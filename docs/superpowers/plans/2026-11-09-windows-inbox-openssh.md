# Windows in-box OpenSSH implementation plan

> **For agentic workers:** Use superpowers:executing-plans inline, with one fresh
> whole-branch review before native publication. Checkbox steps track completion.

**Goal:** Qualify Windows177→185 on120 with OS-supported OpenSSH, independent
reserve access and proven forward-update recovery.

**Architecture:** Keep existing signed Setup/native owner and separate Support.
Provision Windows FoD before touching active Support; migrate to a validated OS
dependency profile and revalidate legitimate servicing changes independently.

**Tech Stack:** Python3.12, pywin32, fixed system PowerShell5.1, Windows servicing,
OpenSSH FoD, PyInstaller/WiX4, existing Endpoint HTTPS/gateway and PostgreSQL.

**Spec:** [Approved direction and implementation decisions](../specs/2026-11-09-windows-inbox-openssh.md).

## Global constraints

- Only test120 and exact177/client107 forward source; no older-source admission.
- Preserve old media/identity/history/unknown-native ownership and manual policy.
- No global SSH/GPO/WSUS change, LAN listener, password/new administrator or TLS bypass.
- No fleet/primary promotion or Linux/Helpdesk change merely to run this canary.
- No fabricated sessions, installation results, telemetry or operator attestation.

## Review focus

- FoD reboot, partial completion or source unavailability retains old working channel.
- OS signature replacement cannot authorize writable/reparse paths or extend a lease.
- Slow signature checks never block main-loop expiry/revoke enforcement.
- Failed Support activation restores exact old dependency configuration and image.
- Native unknown/recovery state is retained despite updater/service restart.

## Task1 — baseline and fixed FoD installer boundary

Files: new `pc_agent/platform/windows/support_access_os.py` and corresponding
`pc_agent/tests/windows/test_support_access_os.py`; integrate WindowsSupportOps.

- [x] Capture fresh120 baseline through existing approved six-hour diagnostic
  renewal and strict pinned SSH; record actual capability/source availability.
- [x] RED tests for a pure capability/servicing result validator and transition:
  existing components require no install; missing components use only fixed FoD
  names; failure/reboot/conflicting firewall preserves old Support before stop.
- [x] Implement fixed bounded provisioning and complete OS dependency validation,
  with protected owned servicing receipt and no blind replay of unknown servicing.
- [x] GREEN focused tests and existing independent Support baseline; commit scoped.

## Task2 — dependency migration, refresh and compensation

Files: support_access.py, support_access_native.py, support_access_service.py,
new OS module and focused service/native fixture tests.

- [x] RED migration177 bundled→FoD with unchanged keys/credential/grant; reject
  tamper/profile conflict; restore old config if activation raises.
- [x] RED refresh on valid signed OS replacement, invalid/partial replacement,
  stable files avoiding repeated signature work, and stalled checker past expiry.
- [x] Implement fixed OS profile, worker-bound revalidation and locked snapshot
  persistence; preserve main-loop expiry/revoke and actual dependency error report.
- [x] GREEN focused/broader Windows Support, native/Setup and lifecycle tests.
  Review whole branch for trust, dynamic calls, races and irreversible outcomes.

## Task3 — immutable186 build and candidate publication

Files: Windows support build spec/resource helper, component/runtime version,
new186 runtime binding/release record, existing canonical publishing procedures.

- [x] RED build contract proves new Support omits the Preview archive/executables
  while retaining exact metadata required for old owned cleanup.
- [x] Implement build input distinction; use Support1.1.1 and agent186, author
  runtime contract before freeze; include signed108 and retain all old packages.
- [x] Build/sign immutable new media with trusted timestamped publisher. Inspect
  exact sources, resources, signatures and frozen independent import closure.
- [x] Run relevant tests/build/contract checks; publish hidden candidate with
  canonical immutable source and transactional default campaign authority.

## Task4 — actual177 forward update and recovery acceptance

Files: scoped verification receipt, runbook/rules/release records only.

- [x] Install via real canonical177→186 assignment on120; capture native0, private4,
  exact versions,180s stable services/WSS and accepted genuine user telemetry.
- [x] Prove in-box binary selection and real strict SSH with Core/updater/observer
  stopped; restore them and prove fresh accepted activity afterward.
- [x] Exercise bounded child/service/network/updater failures and normal reboot;
  retain all receipts, do not replay an unknown native operation.
- [x] Record actual limits and preserve primary/fleet scope. Commit/push exact
  source/docs; remove only owned test scratch and leave operational services ready.

## Confirmed185 follow-up — recapture and modern source recovery

185 failed before MSI and canonically restored177. Its actual signed108 report
closed the original job FAILED21 at2026-11-09T21:15:11.785449Z after185.12seconds
of genuine source observation. Build a distinct186;
184/185 media and failure history remain immutable.

- RED/GREEN ordinary native reinstall recapture of a published retained archive,
  including partial dual-location residue and crashes. Validate current exact native
  package/source and immutable capture before creating payload; journal materialization
  none→copying→complete without changing the old receipt/operation/history.
- Add read-only observer108 attestation for this attempt's terminal rolled-back,
  preparation_cancelled stage, protected binding/inputs/owner, dead owners, absent
  native/reboot attempt, exact original selectors and healthy source/private4.
- Add typed native_failed_source_restored proof. Server must retain known21,
  original assignment/attempt/frozen source, exact trusted source catalog, fresh108,
  source WSS and genuine active-user telemetry after native start; keep legacy paths.
- Test rejection of mismatches/unknown holds and stable180s source recovery, deploy
  the narrow verified server contract, then let actual signed108 settle185 FAILED.
- Rebaseline canonically and prove the new186 release from177 without treating
  an administratively prepared recovery as unattended source qualification.

## Task5 — fleet optional-origin notification correction

Production fleet186 exposed valid retained177 enrollments without optional
endpoint-origin: native/Core186 accepted but lifecycle delivery stayed pending,
blocking Support activation. Policy14 paused new work without cancelling native
chains. No protected files/journals are to be repaired manually.

- [x] Reproduce with genuine protected Windows bootstrap files and real ordered
  outbox; transport-only fake. RED missing-origin; existing-origin control passed.
- [x] Accept only proven absent leaf under a real accessible parent; preserve
  exact fixed lifecycle authority and all existing file/ACL/link checks.
- [x] Independent read-only source/design review; no blockers.
- [x] Freeze distinct187/Support1.1.2, new immutable signed media; keep observer108.
- [x] Console canary actual affected186 and untouched177; native0/private4/fresh
  user telemetry/180seconds AND ordered retained facts delivered/new Support/SSH.
- [x] Qualify both exact sources; preview/save all_active/max2 and observe actual
  assignments. Preserve the second pause16 for the real missing-FoD failure on
  ADMIN-2.187 was not primary-promoted; all five native chains completed.

## Task6 — real PowerShell5.1 missing-FoD provisioning

- [x] Diagnose actual ADMIN-2/source187 with Server FoD absent/old Preview. Preserve
  known failed receipt, private identity, approved account/keys and native history.
- [x] Reproduce production script under actual System32 WindowsPS5.1 with every
  native service/firewall/servicing call isolated and AST safety checks. RED nested
  Name binding; GREEN direct JSON assignment for one/two names. Reject invalid,
  empty/nested inputs before PowerShell. Keep existing failure/reboot/unknown gates.
- [x] Full Windows tests2611passed/4skipped and independent source/design review.
- [ ] Freeze/build/sign distinct188/Support1.1.3, exact observer108, previous187 binding.
- [ ] First actual missing-FoD/Preview migration on ADMIN-2/source187, no manual
  FoD preparation; genuine native0/private identity/user telemetry and real SSH.
- [ ] Native-source177 and186 canaries, exact qualifications, renewed all_active/max2,
  observed cohort and same-row primary promotion with actual downloaded-byte proof.
