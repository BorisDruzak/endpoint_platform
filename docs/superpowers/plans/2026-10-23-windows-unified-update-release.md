# Unified Windows update and reconnect release implementation plan

> **For agentic workers:** Use superpowers:executing-plans to implement inline.

**Goal:** Publish and assign the combined staged updater and TCP recovery as the
primary compatible Windows release for existing and new agents.
**Architecture:** Merge current main into the staged worktree, port the bounded
transport fix, freeze a new immutable runtime, and use existing audited release,
campaign and rollout services. Runtime evidence precedes fleet assignment.
**Tech Stack:** Python 3.12, aiohttp 3.13.3, PyInstaller, WiX 4, PostgreSQL.
**Spec:** `docs/superpowers/specs/2026-10-23-windows-unified-update-release.md`.

## Global constraints

- Preserve unrelated dirty work and immutable historical releases.
- No weakened TLS/auth/protocol, installer trust or health/rollback checks.
- Existing and new Windows agents need compatible Foundation and Core paths.
- Active campaign scope and credential/policy state remain intact.
- Claims distinguish tested, published, assigned and actually installed states.

## Review focus

- Legacy Foundation cannot load a Core requiring a newer launcher.
- Merged ALT runtime and Windows platform fixture behavior must both survive.
- TCP loss retries; preserve credential/TLS rejection and existing protocol classification/recovery policy.
- Default Setup selection and enrollment campaign allowlists must agree.
- Offline/stale/revoked devices must not be represented as updated or online.

### Task 1: Integrate and allocate the immutable candidate

- [x] Merge origin/main; resolve CODEMAP, version and platform fixture conflicts.
- [x] Port 61784dc transport regression tests first; demonstrate RED before fix.
- [x] Apply transport fix and retain staged online executability check.
- [x] Allocate free 3.2.149 and update versioned packaging fixtures/contracts;
      preserve rejected 144/145/146/147/148 media and their failed acceptance evidence.
- [x] Run transport/runtime/platform/contract tests; commit coherent source.

### Task 2: Freeze, verify and review

- [ ] Build Core and immutable runtime/stage/source manifest from clean source.
- [ ] Run full Windows/packaging gate, contracts, compile and diff checks.
- [ ] Push exact-source branch CI and require its success.
- [ ] Build and timestamp-sign MSI/Setup; validate all embedded source closures,
      compiled Foundation inventory and MSI/ZIP/Setup identities.
- [x] Obtain independent review of the integrated changes; resolve blockers with
      failing regression tests and fresh affected verification before main.

Candidate 146 failed owner-loss recovery because native rollback cleared the
captured data-root AUTO_INHERITED flag. The correction restores only this exact
bit after a genuine owner-bound MSI settlement barrier and preserves strict
identity/ACL/private-data checks. Candidate 147 then failed owner-loss classification: a WMI provider timestamp
changed without reboot and incorrectly allowed a new trial. Candidate 148's
kernel GUID also stayed unchanged across an actual restart, so its native build
was stopped. Protected volatile registry witnesses and a durable unresolved gate
before every native attempt now replace those identities. Candidate 149 requires
fresh artifact, CI and installed acceptance; historical cases cannot satisfy them.

### Task 3: Dedicated Windows installed acceptance

- [ ] Admit only an idle dedicated guest; preserve restore points/private baseline.
- [ ] Prove compatible genuine predecessor upgrades and online staging/identities.
- [ ] Interrupt only the candidate transport; prove automatic fresh WSS recovery
      and matching policy without service/Core exit or manual restart.
- [ ] Prove crash/absent-proof automatic rollback and final Native/Core/private state.
- [ ] Record candidate-bound health/stability and remaining unsupported cases.

### Task 4: Publish main and production defaults

- [ ] Fast-forward publish verified integration to main and verify remote SHA.
- [ ] Back up applicable production release/campaign/rollout state and check disk.
- [ ] Register immutable signed Setup/MSI/Core artifacts using existing services.
- [ ] Make the compatible Windows Setup default and update applicable active
      campaign allowlists with audit, preserving all other campaign policy.
- [ ] Use supported rollout/Foundation reconciliation paths to target existing
      non-retired Windows agents; retain previous verified rollback inputs.

### Task 5: Verify delivered outcomes

- [ ] Verify trusted HTTPS downloads and published hashes/default selection.
- [ ] Check fresh server-visible versions, Foundation/launcher and matching policy;
      distinguish applied, pending offline, failed and blocked devices.
- [ ] Save a factual release/deployment report and return concise results.
