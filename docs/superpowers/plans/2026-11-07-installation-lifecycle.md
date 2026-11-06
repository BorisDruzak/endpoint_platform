# Windows installation lifecycle implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development; execute continuously in this existing isolated worktree and review each task.

**Goal:** Fix the120 cause and build committed removal/reinstall visibility into the canonical Windows installer.

**Architecture:** Existing strict owned-browser cleanup; protected causal native-event outbox, authenticated additive provider projection, same-card retained-identity repair and scoped independent Support rebind. No retirement/credential resurrection or background agent after uninstall.

**Tech Stack:** Existing Python3.12/Pydantic2/SQLAlchemy2/PostgreSQL16, Windows PowerShell5.1, signed WiX/native PyInstaller pipeline.

**Spec:** ../specs/2026-11-07-installation-lifecycle.md

## Global constraints

- Existing codex/pilot-support-channel at e13080dd5da91ac399d0e0a76635b636023fe284; preserve176, ALT156, other PCs and all native history.
- GitNexus unavailable; source/committed diff verification instead. Context7 external APIs only, never proprietary source/config.
- Worker scopes do not overlap; root owns live operations, signing, release bindings/version freeze and final integration. No worker subagents, commits, deployments or production DB actions.
- Manual revoke/retirement and Support policy decisions win. Unknown native states are never erased/replayed. No automatic authority based solely on hostname/fingerprint.

## Task 1: Existing176 cause proof and corrected clean test (root)

- [x] Prove archived ownership marker vs orphan policies/current POLICY_CONFLICT.
- [x] Restore only exact known markers; verify same UserSensor PID now accepted under APPLIED policy.
- [x] Repeat uninstall, strict owned-policy cleanup before metadata purge, empty baseline, fresh176 install and native/user/SSH acceptance. See `docs/verification/2026-11-07-test120-usersensor-cause-clean176.md`.

## Task 2: Provider/contracts/lifecycle and scoped Support rebind

Read the full binding spec first. Ownership: `endpoint_contracts/installation_lifecycle.py`,
contract exports/fixtures/OpenAPI provider definitions; `endpoint_server` lifecycle
models/services/routes, additive0048 migration and existing affected auth-revalidation,
Console/enrollment/automatic-dispatch/Support integration; `webapp/src` lifecycle
status/history and relevant server/contract/frontend tests. Do not touch Windows
client/packaging/version/release bindings. Define and send the shared contract file
path/signatures to the Task3 implementer before developing the rest. Current
migration head is0047; use0048 with no backfill. Root owns production and all
Git/signing/deployment. Do not spawn subagents, commit, push or use production DB.
Verifier `C:/Users/admin-2/Documents/endpoint/.venv-device-binding/Scripts/python.exe`;
run this worktree's source only. Actual supported dependency versions must be
checked and Context7 used for changed external APIs. Existing GitNexus unavailable.

The minimal API uses strict DeviceBearer event/ack plus per-device event history
and projection. Agree exact names with Task3 via messages; preserve the spec's
data/authority semantics. Retained-identity repair never issues new enrollment
credentials. Full-wipe parent linking is optional explicit `previous_device_id`
on canonical admin approval, with exact prior removed-state/fingerprint checks;
no credential/history merge or automatic identity approval. Existing approval
clients without a body remain valid. Avoid using retired_at for ordinary removal.
Legacy unknown still works. Removed card remains visible and cannot receive new
automatic work. Manual support decisions invalidate native rebind authority; one
fresh genuine reinstall may grant a new bounded intent only after a prior purely
automatic access grant. No expiry extension from replay or ordinary polling.

Report to `.superpowers/sdd/2026-11-07-installation-lifecycle/task-2-report.md`:
changed files, exact tests/red-green, contract decisions, limitations and review
risks. Freeze source before handoff. Coordinate shared contract; no overlapping
Windows edits. Request permission from root before starting real PG tests; root
can provide a guarded disposable URL. Do not run competing full project suites.

- [ ] RED tests; define strict shared contract first and notify Windows worker.
- [ ] Add immutable events/projection and0048 migration; DeviceBearer/CIDR/revocation/exact-release validation, causal ordering/idempotency and audit.
- [ ] Keep removed card/history visible, exclude new work, add Console fields/UI and history without letting heartbeat resurrect state.
- [ ] Bind one native reinstall rebind/optional automatic access intent to exact source and removed->installed stream; manual changes cancel it.
- [ ] Relevant tests + isolated real PostgreSQL races/migration. Independent task review and fixes.

## Task 3: Native producer, owned cleanup and durable delivery

Read the full binding spec first. Ownership: `pc_agent/platform/windows` lifecycle
producer/client/outbox modules, canonical installer-host/owner/Setup entry hooks;
`packaging/windows/Install-EndpointAgentCanary.ps1`, the installer-host/Setup
PyInstaller resource specs and relevant native/packaging tests. Do not change
agent version, immutable177 source binding, existing released176 artifacts,
provider/contracts/frontend files. Root owns version freeze/build/signing/live
devices/Git/deploy. Do not spawn subagents, commit, push or touch production/test120.
Verifier `C:/Users/admin-2/Documents/endpoint/.venv-device-binding/Scripts/python.exe`;
same source-only worktree rule. Coordinate names with Task2 shared contract;
wait for it or agree signatures before divergent local wire definitions.

Known-native0 finish is the producer; no network failure can strand native fence.
Bundle direct BrowserPolicyApplicator and immutable extension-id resource in the
onefile installer host, not the removed onedir service. Use existing owner/capability
and exclusion gates. Native/cleanup/delivery facts remain distinct; failure to send
is pending, not MSI UNKNOWN. No extra background agent/service or copied raw bearer
in receipts. Protected outbox uses stable transaction-derived event IDs and local
causal generation/sequence/predecessor; pending removal is delivered before a new
installed event, preserving ordering through lost responses. Missing/unsafe state
is not silently replaced. Standard Setup repairable path preserves existing UUID;
fresh native install binds its installed receipt only after durable enrollment.
Deliver installed before independent Support reinstall/rebind, so the provider's
one-time native authority is available to the unchanged1.0.1 wire. Support source
code/version stays unchanged unless a demonstrated dependency requires root ruling.

Offline ordinary uninstall retains credential needed to retry on future Setup.
Full purge without authentic retained authority cannot guarantee delivery: record
undeliverable, never guess/reconstruct authority. Do not create an ARP elevation
broker as an incidental feature. Root's currently running clean176 test is separate
and must not be affected by your source edits or test processes.

Report to `.superpowers/sdd/2026-11-07-installation-lifecycle/task-3-report.md`:
changed files, native trust/ordering/resource decisions, exact red-green/tests,
packaging closure and remaining concerns. Freeze source before handoff; do not
start a competing full-project suite or artifact build. New immutable177 is built
by root only after combined review and source freeze.

- [ ] RED tests; use Task2 shared contract.
- [ ] Native ordinary0 cleanup/receipt under current authenticated owner, strict exclusions and independent warnings; embed pinned browser identity.
- [ ] Protected idempotent per-device outbox/causal stream, bounded strict HTTPS delivery; retained identity repair and first-enrollment binding.
- [ ] Durable local pending if offline, no raw bearer in outbox/no residual sender; preserve all native recovery gates.
- [ ] Native/Setup/packaging tests, independent task review and fixes.

## Task 4: Integration, deployment and actual177 acceptance (root)

- [ ] Add trusted-candidate publication state in additive0048: legacy defaultTrue, active catalog filter, exact native-proof acceptance independent of download visibility, transactional audited one-way promotion and no immutable metadata changes.
- [ ] Verify candidate-only default inclusion in the same AUTO campaign without CIDR/expiry/quota/use changes; preserve explicit diagnostic no-AUTO exception, failed-promotion rollback and concurrent retry behavior.
- [ ] Whole-branch review, source checks/tests/build gates, committed immutable source and177 compatibility binding/newGUID.
- [ ] Verified provider archive/backup/additive migration, atomic deploy and preserved independent gateway.
- [ ] Signed177 artifact verification and candidate-only registration with inspected MSI/ProductCode/expected publisher; preserve176 primary download while authorizing177 through existing default AUTO, source176 Console canary as qualified, ordinary uninstall and retained identity reinstall.
- [ ] Clean177 install, fresh user samples, automatic Support/domain SSH with Core/updater/observer stopped and after restore; event/ordering/offline checks.
- [ ] Canonical release/rules/receipts and scopes, campaign authority preserved; root decides exact-row primary promotion from actual gates via ordinary canonical publication.
- [ ] Preserve rollback boundary: automatic old-server rollback only before hidden candidate registration; later rollback must retain filtering or explicitly retire candidates under operator authority, never blindly expose them or remove publication state.
