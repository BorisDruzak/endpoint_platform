# Endpoint Module Lab Lifecycle API Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the Endpoint-owned ModuleVersion lab gate executable through typed, audited Endpoint APIs without allowing fabricated lab evidence.

**Architecture:** A validated module version may create a lab-only parent operation through a dedicated Endpoint route. Gateway delivery must distinguish that parent from normal published module execution. Endpoint derives live-test evidence only from the terminal parent and its bounded child results, then accepts the declared platform gate before the existing publication transition.

**Tech Stack:** FastAPI, Pydantic v2 contracts, SQLAlchemy async, Alembic, Gateway WSS, pytest.

**Spec:** `C:\Users\admin-2\.codex\attachments\db6720e1-19bf-4d08-84fd-d1c5f015f6fa\pasted-text.txt`

## Global Constraints

- Endpoint remains the only source of truth for recipe validation, module operation, lab evidence and publication.
- Helpdesk gets no Endpoint database access and the browser gets no Endpoint token.
- A lab record must be derived from a real terminal Endpoint module parent with only typed child results.
- Normal module execution remains `published`-only; lab execution is available only while the version is `validated`.
- No generic command, dynamic import, Python, shell, URL, or raw agent result may be introduced.
- Preserve existing migrations; add a forward-only migration only if persistent execution-platform provenance is required.

---

### Task 1: Prove and close fabricated-live-test evidence

**Files:**
- Modify: `tests/modules/test_module_service.py`
- Modify: `endpoint_server/modules/service.py`
- Modify: `endpoint_server/db/models/operations.py` and migration only if needed for platform provenance

**Interfaces:**
- Consumes: `record_module_live_test(session, module_version, platform, endpoint_device_id, operation_id, status, safe_result_snapshot)`.
- Produces: a strict evidence validator that proves the parent belongs to the exact version/device, is terminal/succeeded and has complete typed safe steps.

- [x] Write a failing test that passes an unrelated operation UUID and expects `ModuleServiceError`.
- [x] Run `python -m pytest tests/modules/test_module_service.py -q` and observe the expected failure.
- [x] Implement the minimum relational checks and derive the safe snapshot from `ModuleOperationStep` rows instead of trusting caller-supplied data.
- [x] Run the focused test and the full module-service test file.

### Task 2: Create a validated-only lab parent path

**Files:**
- Modify: `endpoint_server/modules/operation_service.py`
- Modify: `endpoint_server/gateway/command_service.py`
- Modify: `tests/modules/test_module_operation_service.py`
- Modify: `tests/gateway/test_endpoint_operation_delivery.py`

**Interfaces:**
- Consumes: `create_module_parent_operation(..., execution_mode)`.
- Produces: `execution_mode="lab"` parents only for `validated` versions, while normal calls remain restricted to `published` versions.

- [x] Write failing tests that a normal operation rejects `validated`, a lab operation accepts `validated`, and Gateway rejects a lab parent if its state changes to anything other than the permitted lab state.
- [x] Run those tests and observe each assertion fail before production edits.
- [x] Add the smallest explicit execution-mode discriminator and bounded state checks; keep the discriminator private to Endpoint persistence/Gateway.
- [x] Run focused operation and Gateway tests.

### Task 3: Expose typed Endpoint-only lab routes

**Files:**
- Modify: `endpoint_contracts/modules.py`
- Modify: `endpoint_server/modules/routes.py`
- Modify: `endpoint_server/modules/execution_routes.py` or a focused `lab_routes.py`
- Modify: `tests/operations/test_operation_routes.py`
- Modify: contract artifact snapshots if generated contract checks require them

**Interfaces:**
- Consumes: exact module key/version, validated recipe inputs, Endpoint device UUID and a strict idempotency key.
- Produces: a scoped lab-operation create response and a scoped live-test acceptance response with no raw results.

- [x] Write failing ASGI tests for the validated-only lab route, scope rejection, idempotent replay and rejection of arbitrary operation evidence.
- [x] Run the new tests and observe 404/validation failures before route implementation.
- [x] Add routes guarded by existing module scopes; do not add Helpdesk BFF routes or browser access.
- [x] Run focused route tests and contract artifact generation.

### Task 4: Verify release, docs and staging procedure

**Files:**
- Modify: `docs/modules/ENDPOINT_MODULE_PLATFORM_DESIGN.md`
- Modify: relevant `CODEMAP.md`
- Test: `tests/contracts`, `tests/modules`, `tests/operations`, `tests/gateway`, `tests/architecture`, `tests/packaging`

- [x] Document the Endpoint-owned lab-only lifecycle and the immutable publication gate.
- [x] Run the required Endpoint suites, `python tools/contracts/generate_contract_artifacts.py --check`, compileall, and `git diff --check`.
- [ ] Commit the atomic implementation with a Conventional Commit message, open a draft PR, and deploy only after the reviewable checks pass.
