# Linux support and installation lifecycle implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans task by task. Steps use checkbox syntax.

**Goal:** Publish a natively qualified ALT client with independent bounded SSH
support and truthful removal/reinstallation facts, preserving ordinary identity.

**Architecture:** Extend the existing provider/gateway through strict Linux
HTTPS adapters; preserve Windows wire shapes and authority. A separate root-owned
systemd component supervises private loopback sshd and a pinned reverse tunnel.
A signed native coordinator settles RPM before bounded causal notification.

**Tech stack:** Python3.12/Pydantic2.12/SQLAlchemy2/FastAPI, PostgreSQL/Alembic,
ALT11 x86_64 RPM, OpenSSH9.6p1-alt7/systemd258.9, PyInstaller, React/TypeScript.

**Spec:** `docs/superpowers/specs/2026-11-07-linux-support-lifecycle-design.md`;
user explicitly approved it. Continue the existing reviewed implementation
workflow in the current isolated worktree; do not request approval per task.

## Global constraints

- Existing Windows177 bytes, legacy wire JSON, qualifications, grants and policy12
  remain unchanged. Linux primary156 remains until new native/live acceptance.
- Work only in endpoint_platform; Helpdesk is read-only. GitNexus unavailable:
  verify committed/local source and contracts; do not sync or invent graph links.
- New immutable Linux3.2.178, separate Linux Support1.0.0, no same-version repack.
- Use existing Endpoint HTTPS/gateway, strict CA/host keys, no new Agent WSS.
- Preserve native unknown outcomes, current selectors, private identity/history,
  AD/SSSD and active user sessions; no replay, synthetic native0 or guessed login.
- Canary is Proxmoxpve1/VM107, product_uuid
  `db12fb5c-3732-487f-911f-80e31f79b29b`, MAC`BC:24:11:B6:B5:C1`.
  Current DHCP191 replaces stale162. Do not retarget legacy fixed162 controllers.
- Confirmed canary ALT11.4, Core/UserSensor156, SSHosn-admin UID1000 works but no
  sudo; existing trusted root guest-agent channel is available. Do not edit
  accounts/sudoers. Administrator principal for actual Support remains an explicit
  configuration decision, not an inference from wheel membership.
- Initial access at most8hours, no automatic renewal on polling/retry;
  disable/revoke/reset wins, keys distinct, independent expiry kills sessions.
- No plaintext secret in source/Git, arguments, durable queue, logs or receipts.
  Received login password stays only in interactive process memory/stdin.
- Commit task-local files only after complete diff/check and meaningful tests.
  Native/server publication is root's responsibility after independent review.

## Review focus

1. Linux routes must reject Windows/unknown identity even with an invented
   client platform; use persisted consumed enrollment plus canonical inventory.
2. A changed UID/name, locked/nonadministrative account, injected SSH option or
   unsafe filesystem node must fail closed, with existing keys/config preserved.
3. RPM erase scriptlets cannot prove process exit0; crashed/concurrent/direct RPM
   operations retain truthful pending state and cannot trigger a replay.
4. Legacy Linux claims may lack EnrollmentRequest FK. Historical matching must
   compare digests computed in the same original HMAC domain; never copy a digest
   across domains or fabricate an old request/FK to make a test pass.
5. Disabled policy/revocation, expiry and stale native source cannot be bypassed
   by offline reinstall, key rotation, heartbeat or concurrent enrollment.

---

### Task 1: Linux contracts, exact native source and support provider

**Files:** Create `endpoint_contracts/linux_support_access.py`,
`endpoint_contracts/linux_installation_lifecycle.py`,
`endpoint_server/support_access/linux_routes.py`,
`endpoint_server/support_access/platforms.py`,
`endpoint_server/installation_lifecycle/linux_routes.py`,
`endpoint_server/installation_lifecycle/linux_sources.py`,
`endpoint_server/db/migrations/versions/0049_linux_support_lifecycle.py`.
Modify shared support service/installation/rebind/models/config/main and
installation service/models only where needed for platform dispatch. Update
canonical OpenAPI/schema generator/exports. Add focused contract, server and
migration tests under existing test directories.

**Consumes:** Existing DeviceBearer, Support token, key-role lock, append-only
InstallationEvent/State, broker lease exporter and native rebind authority.

**Produces:** Strict LinuxSupportRegistration/Policy/PolicyUpdate/StatusReport/
RegistrationResult and LinuxInstallationEventV1 classes. LinuxSupportPolicy has
existing gateway/key/lease fields plus `platform='linux_amd64'`,
`linux_admin_username`, `linux_admin_uid`; no windows_admin_username.
Linux native proof binds `version`, `source_revision`, `core_nevra`,
`core_rpm_sha256`, optional paired `user_sensor_nevra/user_sensor_rpm_sha256`,
`exit_code=0`. Events retain existing causal UUID/sequence/predecessor semantics,
with `schema_version='endpoint_linux_installation_event_v1'`.
Agent support prefix `/agent/v1/support-access/linux` with register, policy,
status and unregister; admin prefix `/api/admin/support-access/linux` with the
existing device action suffixes. Events POST `/agent/v1/installation/linux/events`
return the existing acknowledgement model. Exact route suffixes and schemas are
frozen in a task interface report before later client implementation.

- [x] RED: Linux strict DTOs/unsafe inputs, cross-platform/unknown device refusal,
  old Windows round-trip JSON unchanged; exact-source and causal replay failures.
- [x] Implement explicit persisted platform/Linux principal binding with legacy
  Windows defaults, immutable LinuxNativeRelease source registry and additive0049.
  Native publish helper requires exact reviewed signed bytes/signer/source;
  no native admission from a version string or arbitrary device-supplied digest.
- [x] Implement Linux adapters through shared source/key/token/rebind/audit locks;
  fresh reported Linux1.0.0 capability required before access. Add separately
  configured Linux automatic defaults, preserving all existing Windows defaults.
  Default Linux account/UID absent means unavailable, not guessed or inherited.
- [x] Extract injectable native-source resolution for shared accept_event;
  Linux events extend the same projection while Windows source checks stay exact.
- [x] GREEN focused tests, relevant old Windows support/lifecycle tests and
  migration checks. Do not run real PostgreSQL until root supplies isolated URL.
- [x] Commit atomic provider change; report interfaces, exact RED/GREEN commands,
  files/SHAs, security assumptions and outstanding real-PG gates for review.

### Task 2: Linux fresh enrollment and historical identity relation

**Files:** Create Linux-specific enrollment DTO/service/routes in
`endpoint_contracts/linux_enrollment.py`,
`endpoint_server/enrollment/linux_requests.py`; extend additive schema only via
a new0050 migration if0049 has already been committed. Add native-source-bound
Linux request client in `pc_agent/platform/linux/enrollment_requests.py`.
Modify canonical OpenAPI/exports/main and parent verification through an explicit
Linux adapter. Test real digest builders and enrollment API/state races.

**Consumes:** Task1 exact LinuxNativeRelease and authenticated source helpers;
existing one-use claims, CIDR/expiry/budget/admin approval, fingerprint builders.
**Produces:** Authenticated/bounded fresh Linux request flow and durable request
capability/status exchange; a source-qualified claim/permanent identity bootstrap
for the native coordinator. Preserved identity reinstall never consumes a claim.

- [x] RED: real existing Linux156 claimed identity without requestFK; correctly
  re-derived same-domain fingerprint matches; changed hardware/consumed authority,
  another device or nonremoved parent refuses. Windows missing-request gate stays.
- [x] Define strict Linux DTOs and actual endpoint signatures in the interface
  report before native client work. Reuse source-qualified Linux campaign authority;
  never enlarge networks/quotas or alter the default Windows AUTO campaign.
- [x] Implement request-bound digest derivation in original Claim/Request domains.
  Historical legacy link requires explicit admin approval, consumed claim on the
  same removed/nonretired device and matching canonical hardware proof. No fake
  old EnrollmentRequest or FK edits. Record this compatibility ruling in spec.
- [x] GREEN actual public-builder tests, claim/idempotency/revalidation tests;
  commit scoped changes and report exact wire examples without any secrets.

### Task 3: Independent Linux support service

**Files:** Create `pc_agent/platform/linux/support_access.py`,
`support_access_native.py`, `support_access_service.py`,
`pc_agent/pyinstaller_linux_support_access.spec`; add unit/native harness tests
under `pc_agent/tests/linux` and `tests/packaging`.

**Consumes:** Task1 frozen Linux support HTTPS DTOs/routes.
**Produces:** `install_from_enrollment(...)`, bounded `uninstall(...)`,
`run_service(...)` entrypoints documented in an interface report; standalone
frozen Support1.0.0 package for RPM staging, with no Core/updater imports.

- [x] RED parsing/host pins/key roles/unsafe paths; exact NSS UID/account/admin
  validation; monotonic expiry under API failure/clock rollback; child group death.
- [x] Implement separate private credential/config/keys outside Core paths; native
  bootstrap reads current credential only during registration. Service uses only
  its own support token/CA and bounded HTTPS; no shell/string interpolation.
- [x] Implement loopback22222 native sshd and reverse tunnel, explicit key-only
  existing user authorization, no global sshd/PAM/authorized_keys edits. Verify
  sshd config using installed supported9.6 options before child start.
- [x] Implement independent auto-start supervision, safe process tree stop,
  lease revision/expiry/revocation and bounded error codes with no raw exceptions.
- [x] GREEN unit and actual Linux descendant/sshd harness; commit and report.

### Task 4: Signed native coordinator, offline queue and RPM ownership

**Files:** Create `pc_agent/platform/linux/installation_lifecycle.py`,
`installation_coordinator.py`, `installation_notification.py`; add packaged fixed
setup/support entrypoints and systemd unit in `packaging/alt/SOURCES`.
Modify RPM spec/build script, existing ALT updater only where package-owned
boundary requires it, artifact build and kit builder. Add focused/native tests.

**Consumes:** Task1 event/source contract, Task2 bootstrap and Task3 support
entrypoints. **Produces:** documented root-only `endpoint-agent-setup install`,
`upgrade`, `remove`, `reconcile` commands with exact native operation receipts;
known successful settlement emits one ordered event after owner/lock release.

- [x] RED exact native input/signature verification, uncertain RPM/no replay,
  concurrent owner denial, genuine known0, final package state, symlink/owner races.
- [x] Implement canonical coordinator and retained verified execution snapshot
  outside removed payload. Stage intent from ordinary RPM hooks, no fake native0;
  make unsupported direct RPM state visibly pending until sufficient reconciliation.
- [x] Implement protected causal outbox retaining UUID/credential/history, no raw
  bearer records, bounded notifier after native owner exits, offline removal
  delivered before reinstall; exact Support/browser cleanup before marker removal.
- [x] Package independent Support/privileged helpers with native code ownership,
  boot/start enablement, normal uninstall cleanup, no background sender leftovers.
  Preserve package-owned code against Core OTA. Freeze new source before builds.
- [x] GREEN native RPM upgrade/removal/failure/rollback harness on isolated test
  paths; commit scoped source/packaging changes and report actual limits.

### Task 5: Console Linux adapter and integration review

**Files:** Modify `webapp/src/SupportAccess.tsx` or actual existing support
component, enrollment/history UI and tests, generated contracts, current runbooks.
**Consumes:** Frozen provider DTOs; **Produces:** platform-correct support/admin
identity controls and existing-device removal/history views without Windows UI
regression, plus documented canonical native Linux setup/uninstall commands.

- [x] RED Linux administrator/UID input, disabled projection, platform switching,
  history/parent and native pending messages; old Windows interactions unchanged.
- [x] Implement narrow Console adapter using server-verified platform; no private
  credential exposure, no client attestation falsely called actual SSH success.
- [x] GREEN UI/typecheck/build; review the combined source, contracts and native
  closure; run appropriate full/real-PG suites in a guarded disposable database.
- [x] Commit integration only after task and whole-branch review findings resolved.

### Task 6: Root deployment, immutable Linux build and live acceptance

- [x] Capture baseline proofs, native package/OS/host identity and available space.
  APT archive cleanup preserved credential/identity/config/CA hashes and CorePID;
  only690MB remained, so measure build footprint/storage before staging.
- [x] Resolve explicit existing Linux administrative principal for actual reserve
  SSH without adding sudo/accounts. Preserve current domain/graphical state.
- [x] Back up provider/database/config/policies; deploy compatible additive schema
  and exact source after checks; prove existing Windows support/native continuity.
- [x] Build/sign new source-bound ALT183 Core/UserSensor/Support and kit, verify
  actual signature/digests/closure/ownership, publish candidate only as needed.
- [x] Execute all spec native/ordinary/offline/clean/rebind/expiry gates on VM107;
  genuinely accepted active-user samples before/after stopped-Core/updater test,
  two real admin SSH commands90seconds apart, restore original states and180second
  plus longer quiet stability proof. No unrelated production workstation changes.
- [x] Publish only after qualified live acceptance; verify actual served bytes;
  update Linux canonical records/AGENTS/runbooks and leave Windows177 policy intact.
- [x] Preserve failure receipts, clean only owned temporary sessions/jobs/keys,
  commit/push evidence and report exact acceptance vs outstanding fleet limits.


## Final Task6 outcome

Completed2026-11-09: native183 accepted on dedicated Stage VM107, production
providerfd196e78/schema50 deployed, actual HTTPS native183 bytes/signatures verified.
Stage0b8ea913 separately preserves Worktime51. Historical178-182 failures and the
original disabled-rebind bootstrap refusal are retained. See
[final acceptance and limits](../../verification/2026-11-09-linux183-native-canary.md).
Linux fleet rollout/global enrollment authority was not enabled. Windows177/policy12
and original media remain unchanged. Owned temporary-resource cleanup and final
release documentation are recorded with the final verification.
