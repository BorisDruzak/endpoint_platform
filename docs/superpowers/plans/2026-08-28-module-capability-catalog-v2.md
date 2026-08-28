# Module Capability Catalog V2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish one Endpoint-owned, closed, versioned module-capability catalog and make every EP2 capability decision derive from it.

**Architecture:** `endpoint_contracts/capabilities.py` will define exactly the six typed primitive descriptors. The descriptor provides authoring parameter types, parameter/result DTOs and schema versions, platform/version compatibility, risk/consent, feature-flag, and policy metadata. Endpoint server recipe validation, recipe expansion, agent-command validation, device capability projection, and contract artifact generation consume that source rather than parallel capability maps.

**Tech Stack:** Python 3.14, Pydantic 2.12, FastAPI 0.115, SQLAlchemy async, pytest.

**Spec:** Approved EP2 batch specification delegated on 2026-08-28; baseline `origin/main` `561c53fc09a4a6fa426da429fd6a5da7e53d9daf`.

## Global Constraints

- The catalog contains exactly `dns.resolve`, `network.ping`, `tcp.connect`, `route.get`, `adapter.list`, and `system.service_status`.
- Preserve each repaired EP1 DTO, parameter/result schema version, closed service key, and default-disabled server feature flag.
- Expose only `GET /api/v1/module-capabilities`, scoped to `modules.read` and registered only with the module-platform server flag.
- Never accept shell, PowerShell, Python, executable/path/URL, raw service name, arbitrary command, Helpdesk data, Helpdesk dispatch, or a catalog UI.
- Do not create an execution route, agent package installation path, database migration, or Helpdesk change.

---

### Task 1: Closed registry and authoring contracts

**Files:**
- Create: `endpoint_contracts/capabilities.py`
- Modify: `endpoint_contracts/modules.py`, `endpoint_contracts/commands.py`, `endpoint_contracts/gateway_ws.py`, `endpoint_contracts/__init__.py`
- Test: `tests/contracts/test_module_capability_catalog.py`, `tests/contracts/test_gateway_ws_contract.py`

- [x] Write failing contract tests for the six-entry order, versioned catalog DTO shape, absent generic execution fields, and AgentCommand rejection of a non-catalog primitive.
- [x] Implement frozen descriptors that bind each capability to its existing parameter/result DTOs, schema versions, constrained authoring fields, compatibility metadata, and JSON-schema fragment.
- [x] Make recipe step and AgentCommand validation read the descriptor identifiers; remove parallel primitive command maps from the gateway contract.
- [x] Run the contract tests and retain existing legacy non-module command behavior.

### Task 2: Registry-backed server validation, expansion, compatibility, and catalog API

**Files:**
- Modify: `endpoint_server/modules/recipes.py`, `endpoint_server/modules/recipe_engine.py`, `endpoint_server/operations/capabilities.py`, `endpoint_server/main.py`
- Create: `endpoint_server/modules/catalog_routes.py`
- Test: `tests/modules/test_recipe_engine.py`, `tests/modules/test_recipe_catalog_validation.py`, `tests/operations/test_module_capability_catalog_routes.py`, `tests/operations/test_network_capability_projection.py`, `tests/operations/test_read_only_capability_projection.py`

- [x] Write failing tests for closed recipe capabilities, registry-derived primitive expansion, feature/policy/minimum-agent compatibility, `modules.read` authentication, disabled route absence, and response privacy.
- [x] Replace recipe parameter maps and primitive DTO switches with descriptor validation and normalized parameter dumps.
- [x] Replace projection metadata maps/version checks with registry compatibility checks; preserve policy gating for target probes and the default-disabled flags.
- [x] Add the GET route with a typed envelope and only catalog metadata; never read device/session/helpdesk state.
- [x] Run focused module, operation, and gateway tests.

### Task 3: Generated contracts and documentation

**Files:**
- Modify: `tools/contracts/generate_contract_artifacts.py`, `docs/modules/ENDPOINT_MODULE_PLATFORM_DESIGN.md`
- Generate: `contracts/jsonschema/*`, `contracts/openapi/endpoint-platform-v1.yaml`, `tests/fixtures/contracts/*`
- Test: `tests/contracts/test_contract_artifacts.py`

- [x] Write a failing generated-artifact test for the versioned catalog schema/OpenAPI route and fixture.
- [x] Generate registry-backed schemas, OpenAPI, and catalog fixture from the authoring DTOs.
- [x] Document Endpoint ownership, scope, metadata, and no-execution boundary.
- [x] Run generator `--check` and artifact tests.

### Task 4: Verification and delivery

- [x] Run focused contracts, modules, operations, gateway, architecture, compile, lint/diff, and generated-artifact checks.
- [x] Review GitNexus impact against the linked worktree and inspect the complete diff for Helpdesk or generic-execution leakage.
- [ ] Commit only EP2 source/docs/generated artifacts, push normally, and create a draft PR against `main`.
