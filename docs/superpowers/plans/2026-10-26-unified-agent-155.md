# Unified Windows and Linux Agent 3.2.155 Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans for integration; independent release preparation and final review may run in parallel.

**Goal:** Publish one source-coherent Windows and ALT Linux agent release, including installer ownership recovery, nonfatal telemetry, native power history/replay and TCP reconnect, and record the canonical version and artifact paths in repository rules.

**Architecture:** Integrate the reviewed telemetry branch into the existing isolated installer correction worktree. Freeze a fresh immutable runtime identity after source verification; build both platforms from that identity, deploy the compatible provider migration/UI, qualify native clients, and publish signed installation and update artifacts through existing mechanisms.

**Tech Stack:** Python 3.12, aiohttp, FastAPI/SQLAlchemy/Alembic, PostgreSQL, PyInstaller, WiX/Authenticode, ALT RPM/OpenPGP.

**Spec:** User authorization on 2026-10-26 plus the existing installer-owner-recovery and telemetry-power-history reports/specifications. Integration excludes incomplete Yandex/Opera, obsolete Ansible/runtime API, unrelated WorkTime and unrelated dirty checkouts.

## Global Constraints

- Preserve historical artifacts, credentials, identities, recovery authorities and unrelated work. No immutable package rewrite.
- Verified DNS/TLS and existing signing identities; no credentials or private keys in Git/output.
- Do not waive historical149 rollback or unsupported S3/physical-power gates; qualify upgrade paths before assigning targets.
- Release records identify source commit, digest, platform and package, not version text alone.
- User explicitly authorized integration, publication/deployment, Linux parity and rules updates; continue execution without a repeated plan/permission handoff.

## Review Focus

- Scoped restore privilege must survive the power branch's separate protected-origin ACL fix.
- Source-bound frozen helpers and Core must contain both lineages, including Setup log isolation.
- Provider migration and nonfatal telemetry negotiation must remain compatible with existing149/150 agents.
- Old149 rollback helper cannot be repaired by replacing immutable old bytes; blocked paths require explicit release restrictions.
- Public UI/download and ALT installation/update artifacts must agree on155/source/digests; rules must point to verified files.

### Task 1: Integrate and verify source

- [x] Merge pinned power8bb0c4c into installer1dc7b0f; resolve shared version/docs/manifest metadata, retain both ACL fixes.
- [x] Set version155 and matching fixture. Integration gate:3968 passed,163 skipped,1 current-manifest test deferred until binding; contracts/diff check and UI56/typecheck/build passed.
- [x] Independent integration review found no material merge defect; follow-up confirmed ordinary uninstall defect and supplied a minimal authenticated-authority correction. RED1 failure/4 passed -> GREEN186 passed across rollback/provenance/bridge tests.

### Task 2: Freeze and qualify both native packages

- [ ] Build canonical Windows Core, source pin, MSI and Setup; verify exact source closures, digests and timestamped signatures.
- [ ] Build Linux native bundle/RPM/user sensor and signed operator kit from the same runtime source; verify source pin and signatures.
- [ ] Run platform regression gates on Windows/Linux; native fresh install, repeat install, upgrade/rollback and reconnect/power replay acceptance on dedicated test machines. Preserve failures and fix confirmed defects before rebuilding with a fresh identity if necessary.

### Task 3: Deploy provider and publish

- [ ] Back up production database/config/release pointers; validate capacity, provider migration0038->0039 and matching Console bundle.
- [ ] Deploy verified provider, run health/contract/old-client compatibility checks; keep rollback inputs.
- [ ] Publish signed Windows Setup/update catalog and Linux kit/update entries; verify real UI download bytes, signatures and registered digests.
- [ ] Apply only qualified update paths, verify advancing WSS heartbeats/version/source evidence; report remaining fleet limitations explicitly.

### Task 4: Canonical rules and final evidence

- [ ] Update AGENTS.md and one canonical release record with155/source/platform paths/digests; require updating that record and pointers on every subsequent release.
- [ ] Record tests, artifacts, deployment, acceptance and remaining limits; preserve precise commit/receipt identity. Verify clean task-only Git state and publish normal history without force.

## Execution ledger

- Ruling: use the existing managed, clean isolated installer worktree and new codex/unified-agent-release-155 branch; original and WorkTime WIP stay untouched.
- Ruling: no WorkTime migration merge is needed because WorkTime is outside this agent release; only the reviewed power0039 migration enters this provider.
- Ruling: Context7 quota is exhausted. Integration reuses previously reviewed APIs without dependency changes; verify behavior with source/tests and use official documentation if new external-API behavior becomes necessary.
- Ruling: fix ordinary authenticated uninstall before freezing155. Its deferred msi-enter callback must use exact prepared maintenance authority after MSI unpublication; initial full inspection, invalid-role/capture rejection and final native absence verification remain required. Historical149 immutable bytes are unchanged.
- Ruling:155 remains an immutable test candidate and is NOT the published/default agent. Actual unassigned-device acceptance failed: no effective policy means no APPLIED delivery, so the180-second trial correctly rejected it. The original PC remains in protected failed-recovery state; do not relabel that trial as passed.
- Ruling: continue the same authorized release as156. Add negotiated authenticated policy-readiness evidence, never assign monitoring rules or infer non-applicability from silence. Retain60-second stable connection,45-second heartbeat freshness and180-second deadline; any subsequent policy delivery revokes the no-policy evidence before application.
- Ruling: use a protected OS gate, independent of filesystem publication, to revoke stale positive proof before any handshake/policy/disconnect transition. A failed write must not leave previously accepting proof usable. Hold the gate through actual acceptance; missing/foreign/abandoned objects fail closed.
- Ruling: repair the180-second warm-launch boundary by settling the exact authenticated diagnostic worker before rollback. Never force-kill a native MSI or mutating helper. Unsettled mutation keeps recovery quarantine instead of attempting concurrent rollback.
- Ruling:155 native Linux qualification and Windows positive install/repeat/uninstall/repair/reboot replay passed, but clean rollback did not. Keep all artifacts/evidence. Do not count eventual fresh-owner recovery as original-call clean rollback.
- Ruling: a proposed negative-abort operator tool is unshipped WIP outside the build tree. Its fake-adapter tests are not native authority. It must not execute without complete native uninstall evidence, disposable-fixture qualification, source review and explicit fixed-plan approval; no guard or trial proof has been manually changed.

## Continuation:156 release gates

- [ ] Complete TDD for explicit policy applicability, durable OS-backed revocation, and authenticated worker settlement; review combined patch and regenerate contracts.
- [ ] Allocate156 immutable source/binding, rebuild/sign both platforms and kit, run native full gates and current CI.155 source/artifacts remain untouched.
- [ ] Requalify Windows assigned and unassigned cases, clean no-proof compensation, Linux native upgrade/rollback/reconnect, and compatible provider before publication.
- [ ] Resolve the original PC with supported, separately witnessed recovery; preserve protected state if prerequisites are absent. Never claim completion while its agent is quarantined.
- [ ] Publish only the successfully qualified shared release; update AGENTS.md and canonical version/path record after verified publication.
