# Task 13 Continuation v1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. The user approved specification, plan and implementation without further confirmations on 2026-10-11. Independent review before VM remains mandatory.

**Goal:** Produce one genuine canonical receipt 04 using additive continuation authority, then stop at the resume gate.

**Architecture:** Separate historical verification from live continuation authority. A protected one-step loader binds exact sources and evidence, claims seq 04 once and publishes without replacing history. Original guest Facts and old executor predicates remain unchanged.

**Tech Stack:** Python 3.12, standard-library JSON/hash/ctypes/subprocess, Windows PowerShell 5.1 and existing fixed read-only observation helpers. No Agent/installer/provider changes.

**Spec:** `docs/superpowers/specs/2026-10-11-task-13-continuation-v1-design.md`

## Global Constraints

- Baseline `9144a26472239e5a4c61a79aacdabbda4ec961bc`; isolated branch `codex/task13-continuation-v1`.
- Schema `task13_continuation_v1`, version 1; only seq=4 / compare-after-start.
- Authorization 1,200 s; workload 120 s; settlement 10 s; SSH observation 145 s; persistence reserve 2 s.
- Preserve original plan/seal/receipts, baseline/snapshot and guest Facts.RunId/PlanSha256.
- No old live_plan/verify_chain/next_step monkeypatch or renewed old deadline.
- Live bootstrap uses fixed historical anchors; synthetic fixtures cannot create live authority.
- No automatic retry after dispatch claim or UNKNOWN; no marker/restore or mass rollout.
- Private configuration, evidence and operational targets stay outside Git.
- Use a verified Python 3.12 interpreter with pytest; commands below assume this interpreter is the active `python`.
- Independent PASS on final source/control closure is required before any VM operation.

## Review Focus

- Caller-supplied issuer/reviewer records must not replace independently pinned trust inputs (Task 2 tests).
- Wrong root process/boot or backward UTC must refuse even with a live numerical deadline (Task 2 tests).
- Historical stopped-guest brackets must remain explicitly historical (Task 1 tests).
- Distinct continuation IDs must share one original seq-04 dispatch claim (Task 2 tests).
- Partial receipt publication or complete-looking journal with missing exit proof must not enable PASS/retry (Task 4 tests).

### Task 1: Strict codec and historical checkpoint verifier

**Files:** Create `tools/canary/task13_continuation/{__init__,codec,history}.py`; test `tests/tools/test_task13_continuation_history.py`.

**Interfaces:** Produce `canonical(value)->bytes`, `digest(value)->str`, `parse_json(raw:bytes,limit:int)->dict`, `require(condition,message)->None`; `HistoricalPrefix` carries immutable original file bytes and validated checkpoint binding. `verify_historical_prefix(root:Path)->HistoricalPrefix` uses fixed original anchors and sealed original pure validators, never original live authorization.

- [ ] Write failing tests: duplicate/NaN/oversize JSON refused, all original file tamper classes refused, absent/reordered prefix refused, historical stopped-guest bracket preserved and source closure substitution refused. Operationally verify actual retained prefix using a local-only test input.
- [ ] Run `python -m pytest tests/tools/test_task13_continuation_history.py -q`. Expected: RED before implementation.
- [ ] Implement strict codec and verifier: raw/canonical anchors, complete manifest entries/prerequisites, unique retained references, candidate/accepted binding, original chronology/snapshot/LVM/native/inventory/source and corroborating owner predicates. No synthetic raw-output reconstruction.
- [ ] Repeat the command. Expected: GREEN; actual old live_plan/verify_chain/next_step still refuse current time.
- [ ] Inspect complete diff, `git diff --check`, stage only task files and commit `feat(canary): verify immutable Task 13 historical prefix`.

### Task 2: Protected native storage and capsule authority

**Files:** Create `tools/canary/task13_continuation/{windows,storage,authority}.py`; test `tests/tools/test_task13_continuation_authority.py`.

**Interfaces:** Consume codec and HistoricalPrefix. Produce `ProtectedStore(root:Path)`, `read(name:str)->bytes`, `create(name:str,raw:bytes)->None`, `publish(name:str,raw:bytes)->None`, `claim(prefix:HistoricalPrefix,continuation_id:str)->dict`; `observe_controller()->dict`, `create_capsule(prefix,closure,authority,review,identity)->dict`, `validate_authorization(capsule,authority,attestation,review,trust,identity)->None`, `LiveAuthorization.check()->None`.

- [ ] Write failing tests for expired authorization, UTC rollback, wrong boot/process, injected authority/review pins, source hash substitution, restrictive ACL/reparse/hardlink checks, concurrent/restart/cross-ID replay and no-replace publication crash boundaries.
- [ ] Run `python -m pytest tests/tools/test_task13_continuation_authority.py -q`. Expected: RED.
- [ ] Implement Win32 retained-handle reads/security validation, restrictive directory creation, exclusive durable claims, staged flushed non-replacing handle publication, real token/process/boot observations, strict capsule/authority/attestation schemas and independently pinned reviewer trust. Separate intent and attestation avoid hash cycles.
- [ ] Repeat command including local Windows-native cases. Expected: GREEN and immutable files intact.
- [ ] Verify and commit `feat(canary): authorize and persist Task 13 continuation`.

### Task 3: Corrected compare-only source closure

**Files:** Create `tools/canary/task13_continuation/{sources,journal}.py` and `Write-Task13ContinuationJournal.ps1`; test `tests/tools/test_task13_continuation_sources.py`.

**Interfaces:** Consume HistoricalPrefix. Produce `build_execution_sources(prefix,continuation_id:str,guest_root:str)->dict[str,bytes]`, `seal_sources(entries:dict[str,bytes])->dict`, `verify_sources(closure,entries)->None`, `validate_journal(raw:bytes,identity:dict)->dict`.

- [ ] Write failing tests for exact patch boundaries, compare-only entry, unchanged Facts inputs, altered reader/watchdog/wrapper/wire and corrupt/incomplete/wrong-identity journal.
- [ ] Run `python -m pytest tests/tools/test_task13_continuation_sources.py -q`. Expected: RED.
- [ ] Derive a separate helper from verified original, connect exact committed MSI reader and aggregate profile, preserve native observation semantics, generate exact wrapper/wire and protected journal, and seal all code/dependencies. Parse generated source with PowerShell 5.1. Watchdog requires ready/armed handshake and retained normal exit.
- [ ] Repeat command and existing `test_task13_msi_profile.py` / `test_task13_watchdog.py`. Expected: GREEN.
- [ ] Verify and commit `feat(canary): seal corrected Task 13 comparator closure`.

### Task 4: Evidence acceptance and canonical receipt validator

**Files:** Create `tools/canary/task13_continuation/receipt.py`; test `tests/tools/test_task13_continuation_receipt.py`.

**Interfaces:** Consume prefix, LiveAuthorization, sealed sources and journal validator. Produce `validate_execution_evidence(prefix,capsule,evidence)->None`, `make_receipt(prefix,capsule,evidence)->dict`, `verify_continuation_receipt(prefix,capsule,receipt,evidence)->None`.

- [ ] Write failing tests covering wrong Facts/baseline/snapshot, absent comparator PASS, SSH nonzero, timeout/UNKNOWN, terminated/unconfirmed native exit, absent/corrupt journals, stale provider/ownership/clock, seq skip and marker/restore refusal.
- [ ] Run `python -m pytest tests/tools/test_task13_continuation_receipt.py -q`. Expected: RED.
- [ ] Validate exact typed raw transport and retained-handle exit, protected journal, original Facts, fresh pre/postflight and evidence digest bindings; create only new schema seq04 linked to original tip and continuation seal. Reject synthetic evidence for operational acceptance.
- [ ] Repeat command. Expected: GREEN; failed evidence cannot publish a receipt.
- [ ] Verify and commit `feat(canary): validate canonical Task 13 continuation receipts`.

### Task 5: Canonical one-step loader and operational adapter

**Files:** Create `tools/canary/task13_continuation/{transport,loader}.py`, `tools/canary/run_task13_continuation.py` and operator documentation; test `tests/tools/test_task13_continuation_loader.py`.

**Interfaces:** Consume previous units. Produce `ContinuationTransport` for bounded raw-retaining observations, `run_seq04(config:dict,trust:dict)->dict`. Default CLI is nonoperational; explicit reviewed execution flag requires all trusted inputs. No arbitrary adapter/plugin injection in live mode.

- [ ] Write failing tests for defaults/no dispatch, stale preflight/source substitution, claim-before-side-effect, UNKNOWN stops/restart replay, successful receipt04 and unconditional stop before seq05.
- [ ] Run `python -m pytest tests/tools/test_task13_continuation_loader.py -q`. Expected: RED.
- [ ] Implement local trusted bootstrap, fresh observations through sealed existing read-only policy/interfaces, independent watchdog preparation, raw SSH transport/settlement, postflight, accepted receipt publication and final stop. Seal exact adapter/config/commands as external local inputs; never call old FixedAdapter.call or bypass its live gate.
- [ ] Run all continuation and existing MSI/watchdog tests. Expected: GREEN. Verify no runtime/provider/package diff.
- [ ] Verify and commit `feat(canary): execute only reviewed Task 13 continuation seq04`.

### Task 6: Independent review and controlled acceptance

**Files:** Update plan ledger, operator guide and final sanitized report under `docs/superpowers/reports/`; private review/authority/capsule/evidence outside Git.

**Interfaces:** Exact reviewed closure and its independently pinned PASS attestation feed the bootstrap from Task 5.

- [ ] Assemble full diff, source/manifest/transport pins, RED-to-GREEN log, native fault/concurrency results and immutable-prefix proof; ask an independent reviewer to judge all user-requested security/control gates. Expected: PASS with no blocking findings before VM.
- [ ] Fix blocking findings with RED-to-GREEN, full focused checks and renewed exact-source review. Expected: final independent PASS bound to the final closure. The user's exact-SHA review requirement overrides the skill's general no-re-review advice.
- [ ] Only after PASS, create fresh controller authority/capsule, reconcile actual VM/snapshot/baseline/SCM/MSI/update/provider/ownership/clock state through canonical loader. Expected: all preflight gates valid or no workload dispatch.
- [ ] Execute compare-after-start once; inspect real GUEST_COMPARATOR_PASS, SSH exit 0, watchdog normal retained-handle exit, unchanged baseline/snapshot, valid provider and new canonical receipt04. Expected: actual PASS or explicit FAIL/UNKNOWN with no manufactured receipt/retry.
- [ ] Stop at resume gate; no marker/restore. Publish sanitized final report with every requested field, exact implementation/hash IDs and remaining product tests. Expected: task scope satisfied without claiming Task 13 complete; actual failure remains unresolved rather than reported as success.
