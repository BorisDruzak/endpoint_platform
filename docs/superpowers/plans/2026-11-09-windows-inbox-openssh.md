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

## Task3 — immutable185 build and candidate publication

Files: Windows support build spec/resource helper, component/runtime version,
new185 runtime binding/release record, existing canonical publishing procedures.

- [x] RED build contract proves new Support omits the Preview archive/executables
  while retaining exact metadata required for old owned cleanup.
- [ ] Implement build input distinction; bump Support1.1.1 and agent185, author
  runtime contract before freeze; retain observer107 and all old packages.
- [ ] Build/sign immutable new media with trusted timestamped publisher. Inspect
  exact sources, resources, signatures and frozen independent import closure.
- [ ] Run relevant tests/build/contract checks; publish hidden candidate with
  canonical immutable source and transactional default campaign authority.

## Task4 — actual177 forward update and recovery acceptance

Files: scoped verification receipt, runbook/rules/release records only.

- [ ] Install via real canonical177→185 assignment on120; capture native0, private4,
  exact versions,180s stable services/WSS and accepted genuine user telemetry.
- [ ] Prove in-box binary selection and real strict SSH with Core/updater/observer
  stopped; restore them and prove fresh accepted activity afterward.
- [ ] Exercise bounded child/service/network/updater failures and normal reboot;
  retain all receipts, do not replay an unknown native operation.
- [ ] Record actual limits and preserve primary/fleet scope. Commit/push exact
  source/docs; remove only owned test scratch and leave operational services ready.
