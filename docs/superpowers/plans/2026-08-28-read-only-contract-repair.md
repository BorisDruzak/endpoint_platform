# Read-only Primitive Contract Repair Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Repair the merged EP1 read-only primitive contracts and agent behavior so they match the approved batch contract before EP2 introduces a canonical catalog.

**Architecture:** Keep the three fixed Gateway capability IDs and default-disabled server flag. Replace only their typed DTOs and fixed agent collectors: DNS candidates are independently policy-checked before route inference; psutil exposes bounded adapter facts; fixed internal service maps return a privacy-safe service state. No capability registry, new API route, Helpdesk dependency, or mutable operation is introduced.

**Tech Stack:** Python 3.12, Pydantic v2, FastAPI-generated schemas, psutil 7.2.2, native sockets, fixed-argument systemctl/Windows SCM.

**Spec:** Approved source specification, sections 6–8 and 20 (PR-EP1 repair boundary).

## Global Constraints

- Preserve `ENDPOINT_READ_ONLY_PRIMITIVES_ENABLED=false` by default.
- Accept no code, shell, Python, PowerShell, executable, path, URL, environment, credential, or raw service-name input.
- Never write, start, stop, restart, enable, or disable a service.
- Route candidates resolve first and every candidate is denied unless accepted by the agent policy; no allowed candidate means `network_target_denied`.
- Adapter output excludes MAC addresses, SSIDs, descriptions, raw registry paths, and raw command output.
- Linux `endpoint_agent_updater` is `unsupported` until an approved fixed unit exists.
- Do not add the EP2 catalog/registry API or modify Helpdesk.

---

### Task 1: Contract repair

**Files:**
- Modify: `endpoint_contracts/read_only_primitives.py`
- Modify: `endpoint_contracts/__init__.py`
- Modify: `endpoint_contracts/gateway_ws.py`
- Test: `tests/contracts/test_read_only_primitives.py`

- [x] Write failing DTO tests for the complete route, adapter, and service contract shapes and forbidden fields.
- [x] Run the focused contract test and confirm it fails because the merged DTOs lack the approved fields/schema names.
- [x] Implement only the bounded Pydantic DTOs and Gateway parameter validation required by those tests.
- [x] Re-run the focused contract test and confirm it passes.

### Task 2: Fixed agent collectors and policy enforcement

**Files:**
- Modify: `pc_agent/primitives/read_only/handlers.py`
- Modify: `pc_agent/primitives/read_only/command_execution.py`
- Test: `pc_agent/tests/primitives/test_read_only_handlers.py`

- [x] Write failing behavioral tests for policy-checking every resolved route candidate, deterministic route inference, adapter privacy/bounds, and fixed service mappings.
- [x] Run them and confirm the merged handlers fail for the expected contract mismatch.
- [x] Implement the smallest native socket/psutil/fixed-service changes; keep all external process arguments literal and fixed.
- [x] Re-run the primitive tests and confirm they pass.

### Task 3: Registration, generated contracts, and documentation

**Files:**
- Modify: `pc_agent/primitives/read_only/command_execution.py`
- Modify: `endpoint_server/operations/capabilities.py`
- Modify: `pc_agent/docs/CODEMAP.md`
- Modify: generated files under `contracts/`
- Test: `pc_agent/tests/runtime/test_read_only_primitive_registration.py`

- [x] Write failing registration/projection tests for the repaired schema versions while retaining the default-disabled feature gate.
- [x] Run the tests and confirm the old registration fails.
- [x] Update only the fixed registration/projection metadata, regenerate artifacts, and document the repaired bounded surface.
- [x] Run generated-artifact and focused registration tests successfully.

### Task 4: Verification and delivery

**Files:**
- Verify only; no further scope expansion.

- [x] Run lint, contract generation check, focused contract/agent/gateway/operations tests, architecture guards, and relevant package tests.
- [x] Inspect the complete diff and `git diff --check`.
- [ ] Commit one atomic conventional commit, fetch and verify `origin/main` ancestry, push normally, and create a draft PR to `main`.
