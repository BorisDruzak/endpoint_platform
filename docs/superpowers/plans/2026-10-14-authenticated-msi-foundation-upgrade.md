# Authenticated MSI Foundation Upgrade Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Keep the existing independently authorized security reviewer; do not delegate implementation.

**Goal:** Fix the independently reproduced foundation upgrade failure while preserving exact enrollment security, authenticated installer ownership, native rollback and verified selected runtime history.

**Architecture:** Extend the existing PowerShell owner, package-bound helper protocol, durable provenance and installer fences. An external Windows Installer multi-package transaction can enlist the verified old uninstall and successor install under the same live owner; every package retains its own exact helper/session/phase authority. A protected parent upgrade plan survives owner loss and gates retirement, selection reconciliation and startup until all native and application postconditions are verified.

**Tech Stack:** Python 3.12, pywin32 311, existing PowerShell/C# owner, Windows Installer 5.0 APIs and WiX 4 authoring.

**Spec:** `docs/superpowers/specs/2026-10-03-agent-3.2.82-pre-fleet-hardening.md` and the user's current final-acceptance attachment. The single acceptance report remains `docs/superpowers/reports/2026-10-13-agent-3.2.82-final-acceptance.md`.

## Global Constraints

- Canonical82 and genuine81 remain immutable; fixture83–87 remain reserved. A changed signed release must use a free version after93.
- Preserve foundation/core ownership, exact hashes, Authenticode/timestamp, CIDR/CA/DNS/HTTPS/WSS, same-origin, reparse and ACL guards. No manual selector, receipt, fence or claim edits.
- Preserve device identity, credential bytes, CA/origin, enrollment leaf identity and exact owner/group/DACL. Private descriptors and paths stay inside protected local transaction evidence; no credential contents/digests in the new security proof.
- Use only the independent test guest for native mutations and resets. Preserve historical VM100/Seq04 and all existing immutable evidence.
- No provider deploy/restart/migration, new enrollment grant/catalog registration, OTA assignment or fleet minimum change is implied by this plan.
- Native prototype evidence is not Agent acceptance. Keep NOT READY until the full required matrix passes. No main publication before the final checks and gates.

## Review Focus

1. Loss of the PowerShell owner during a blocking native API or delayed commit callback.
2. Shared component inventory after old removal and successor installation, including failure/rollback.
3. Preservation of non-MSI ZIP/retained trees and true current/previous origins during cleanup and selector replacement.
4. Fresh CreateFolder ordering versus preexisting enrollment, descriptor propagation and substitutions between reads.
5. Browser Policy automatic startup and rollback-disabled/reboot exceptions to transaction atomicity.

## Files and Boundaries

- `pc_agent/platform/windows/acl.py`: read-only exact existing data-root policy validation, owner checked in the same descriptor as DACL.
- `pc_agent/platform/windows/installer_data_security.py`: bounded private pre-native root/leaf identities and O/G/D evidence, package/transaction/session binding, authenticated fresh-create and postcondition checks. It imports no enrollment/network transport.
- `pc_agent/platform/windows/installer_transaction_bridge.py`: calls the data proof at existing prepare/preflight/enter/configure/reconcile/finish boundaries; later adds explicit compound child/retirement phases without granting another package the old helper's authority.
- `packaging/windows/Install-EndpointAgentCanary.ps1`: existing mutex-owning thread, exact pinned media/helpers, independent package policies, native transaction ownership, delayed-commit lifecycle and multiplexed pumping.
- `pc_agent/platform/windows/installation_provenance.py`: explicit allowed native intermediate selector, retained ownership and final selected/previous transition; no first-install relaxation for an upgrade.
- `pc_agent/platform/windows/installer_fence.py` and service startup guards: protected parent exclusion and exact child evidence. Never overwrite old package fields to make them describe the successor.
- Native authoring/source manifests: package-bound expected default selector bytes and intentional successor lifecycle/startup. Preserve existing component identity and runtime feature retirement semantics.
- Existing Windows/packaging tests plus focused negative and native tests; one final public report.

## Task 1: Preserve Machine Data Security

- [x] Reproduce the existing-root rewrite in failing tests; validate both actual source policies without normalization.
- [x] Verify native root and two inherited leaf descriptors remain byte-for-byte unchanged; inject an unauthorized writer and prove rejection without repair.
- [x] Model genuine fresh MSI CreateFolder ordering with protected pre-native absence, not an empty-directory heuristic.
- [ ] Finish bounded proof shape/session/recovery/replay tests, ancestor/identity race tests and root initialization crash boundaries.
- [ ] Verify every live phase checks fresh owner authority before mutation, preserves original evidence and does not publish private facts.
- [ ] Run related source/native suites; obtain independent security review. Do not freeze/build a candidate while fresh MSI or recovery behavior is incomplete.

## Task 2: Establish Native Transaction Semantics

- [x] In the test guest only, use two small disposable MSI fixtures to observe enlistment, delayed commit callbacks, component registration and native rollback on failure/owner loss. Keep fixtures and raw evidence outside Git.
- [x] Determine whether same-process native API worker threads can enlist while the original mutex-owning thread continues pumping. Owner-transfer events must revoke authority.
- [x] Prove the timing of commit custom actions and settlement; reject rollback-disabled and unexpected reboot outcomes. Do not count successful API return as commit.
- [x] Preserve the existing Agent installation, enrollment and all protected facts throughout the isolated prototype. Remove only the identified disposable products through normal MSI operations.

## Task 3: Implement Exact Compound Ownership

- [ ] Write failing policy/plan tests for cross-package helper substitution, wrong session/package, second preflight, replay, owner loss and delayed commits.
- [ ] Publish a durable exact parent plan before native mutation, capturing both genuine media/helper identities, selections, archives, service startup and data security.
- [ ] Give old and successor packages separate checked capability/bridge lifetimes. Preserve immutable old helper behavior and its original global fence; add a separately bound successor child fence understood only by the new authenticated helper.
- [ ] Enlist actual old removal with exact verified successor ProductCode in UPGRADINGPRODUCTCODE. Source cleanup already distinguishes upgrades; prove actual preservation of ZIP/retained trees instead of assuming it. If any affected tree is not preserved, archive and rehydrate its genuine origin/receipt/payload before proceeding.
- [ ] Keep both policies and all peer handles alive until EndTransaction, both delayed commit callbacks and actual helper exits settle. No release of the product mutex during native work.
- [ ] Add an authenticated old-product-retirement phase verifying absence of old native ownership and verified successor ownership of shared resources. Do not invoke incompatible old uninstall finish or manufacture its completed receipt.
- [ ] Reconcile only from the exact package-bound intermediate native selector, original immutable before-state and prepared archives to the planned genuine current/previous state.
- [ ] Gate Agent/Updater startup and account for Browser Policy's automatic native start. Retain the parent barrier; publish an exact positive commit marker only after verified ready evidence, ACK and actual helper exits. No required helper or directory flush follows publication. Native installed acceptance remains open.
- [ ] On native rollback or owner loss, preserve quarantine and original evidence. New recovery must establish native settlement and exact resulting ownership; no age/PID idle shortcut or descriptor rebaselining.

## Task 4: Verify the Candidate and Required Acceptance

- [ ] Independent security review of the complete protected mechanism; source/native negative tests including interrupted child transitions.
- [ ] Freeze a free corrective version, commit only related source files, run final Linux/PostgreSQL CI and required Windows checks on that exact SHA.
- [ ] Build/sign/timestamp distinct immutable Setup/MSI/ZIP; verify resource identity, source closure, runtime tree and offline exclusion.
- [ ] Real test-guest upgrade with controller-held enrollment byte/descriptor baseline; natural terminal result, actual native product/components, service identities, selectors/history and provider WSS/context proof.
- [ ] Continue genuine79/81, clean one-EXE, repeat/reboot, required A/B OTA/rollback/disk and actual hypervisor-reset gates. Keep separate provider approval boundaries.
- [ ] Update the one public report with exact results and remaining limits. Publish normally to main only after all required gates pass.

## Rulings and Evidence

- The natural93 failure and failed fence were preserved before whole-guest restoration; restoration is containment, not installer recovery acceptance.
- One session forward cannot authorize immutable92 removal: helper hash, package, operation, preflight and fence bindings independently reject it.
- A naive pair of uninstall/install wrapper calls is rejected: it loses native atomicity and authenticated durable transition authority.
- Multi-package transaction is a design hypothesis until the native prototype passes. Microsoft documents commit actions at EndTransaction and rollback of enlisted packages; private Python/C#/ACL/fence writes still require their own preservation and recovery proof.
- Existing root validation alone was rejected in review because MSI CreateFolder precedes ConfigureFoundation. The private pre-native proof must distinguish native fresh creation from preexisting enrollment.
- The root-cleanup condition is `REMOVE~="ALL" AND NOT UPGRADINGPRODUCTCODE`; genuine upgrade context must be verified, never invented to suppress checks.

Primary references: [MsiBeginTransaction](https://learn.microsoft.com/en-us/windows/win32/api/msi/nf-msi-msibegintransactionw), [MsiEndTransaction](https://learn.microsoft.com/en-us/windows/win32/api/msi/nf-msi-msiendtransaction), [Multiple-package installations](https://learn.microsoft.com/en-us/windows/win32/msi/multiple-package-installations), [Commit custom actions](https://learn.microsoft.com/en-us/windows/win32/msi/commit-custom-actions).
