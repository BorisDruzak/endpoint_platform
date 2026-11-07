# Full Setup165 release and Console workflow plan

**Spec:** ../specs/2026-11-05-setup165-release-workflow.md
**Workspace:** reuse clean linked worktree full-setup-autoupdate on
codex/full-setup-autoupdate-production. User has authorized publication, deployment
and persistent all-active Windows rollout/max2, subject to existing proof gates.

## Global constraints

- Keep historical156/158/163/164 packages and native outcomes immutable.
- No workstation preparation/SSH update delivery, reboots or unrelated GPO edits.
- Preserve TLS hostname/CA, private files, enrollment authority, quotas and CIDRs.
- Existing Foundation source qualification, recovery ownership and failure pause
  remain enforced. No version-only or heartbeat-only acceptance.

### Task 1: Immutable native165 candidate

Files: pc_agent/version.py; Windows context golden fixture;
packaging/windows/initial-runtime-3.2.165.json; release records at acceptance.
Interface: signed EXE/MSI, exact runtime source/artifact binding, canonical
SetupReleaseManifestV1 and WindowsSetupRelease publication metadata for Task3.

- [x] Bump Core version165 and fixture; run fallback/context regressions, commit.
- [x] Freeze Core from that exact commit; produce native runtime contract/evidence.
- [x] Build/sign MSI and Setup with canonical scripts; verify signatures, version,
  embedded payload, hashes and secret-free publication inputs. Preserve all older bytes.

### Task 2: Unified Console steps and qualification action

Files: webapp/src/FullSetupPage.tsx, SetupFleetPolicy.tsx, their tests/styles;
endpoint_server/setup_updates/fleet_routes.py and API tests.
Interface: POST /api/admin/setup-updates/fleet/qualifications with exact release_id
and evidence_assignment_id calls qualify_release inside mutate_admin. Existing
GET fleet returns qualification state; existing policy PUT persists all-active/max2.

- [x] Add failing tests for legitimate qualification versus missing/foreign/stale
  proof, write role/CSRF/revalidation/audit, and single-target numbered UI process.
- [x] Implement minimum endpoint and reusable UI; preserve manual canary access,
  read-only views, failed operation ownership, stale draft/preview protection.
- [x] Run focused server/UI suites, full web tests/typecheck/build, and browser
  desktop/mobile interaction checks. Review code before production deployment.

### Task 3: Native canary, persistent rollout and rules

Files: AGENTS.md; docs/runbooks/FULL_SETUP_FLEET_POLICY.md;
docs/releases/current-agent-release.json and new165 record; verification report.
Consumes Tasks1/2's exact immutable release and deployed Console interface.

- [x] Deploy tested Console/server through canonical release procedure without
  replacing unrelated state. Register signed165 and include default AUTO campaign.
- [x] Use Console to assign101.120; verify real native165/165 acceptance, stable
 180-second observation, private continuity and fresh active-user/power telemetry.
- [x] Qualify actual canary in Console, preview and save all-active/max_parallel2;
  verify persistence/reload, server audit and actual bounded assignments/results.
- [x] Prove later registration/reconnection scheduling in tests, enumerate blocked
  sources honestly, and record remaining live acceptance limits.
- [ ] Promote verified Windows download165, document the single release process
  and mandatory future-release inclusion rule; retain Linux metadata separately.
- [ ] Commit exact acceptance, verification and review evidence. No push/PR requested.

## Current live gate

120 and144 passed native165 acceptance.146 is held with
`native_observation_unavailable`, native proof unavailable and stale UserSensor.
The real failure circuit automatically paused policy revision3, retaining
all-active scope and max_parallel2. Published enrollment165 bytes/signatures
are verified, but general fleet acceptance and stable-primary declaration are
withheld. See `docs/verification/2026-11-05-setup165-web-fleet.md`.

- [ ] Obtain146 protected observer stage/line and establish the actual cause.
- [ ] Recover the original attempt without MSI replay or loss of native ownership.
- [ ] Prove fresh active-user telemetry, then resume through Console and observe
  the remaining bounded waves.

## Review focus

Qualification must derive solely from real server-held native evidence; stale
browser fields, wrong release, read-only sessions and revoked admin identities
must fail. A changed target cannot reuse canary/preview proof for another EXE.
Future/offline devices must not be frozen out of all-active scope. Global slots
include manual/recovery chains, failures pause new work, and immutable artifact
or source bindings cannot be weakened to make a canary pass.
