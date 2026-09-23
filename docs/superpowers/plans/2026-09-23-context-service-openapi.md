# Device Context Service OpenAPI Implementation Plan

**Goal:** Publish all seven existing Device Context service routes in the generated canonical OpenAPI without changing runtime behavior.

**Architecture:** Extend the existing FastAPI router based service contract generator with the Context router and an explicit context path list. Describe current public projections with Pydantic documentation models and add the same bearer and `x-required-scopes` metadata used by operation routes. Keep `require_service_scope(...)` and route handlers unchanged.

**Tech Stack:** FastAPI 0.115.6, Pydantic 2.12.5, pytest, PyYAML.

**Spec:** User supplied Device Context OpenAPI repair specification, 2026-09-23.

## Global Constraints

- Preserve all runtime methods, paths, authorization decisions, persistence, SDK behavior, and operation/module contracts.
- Generate and commit the OpenAPI artifact through `tools/contracts/generate_contract_artifacts.py --write`.
- Keep database models, secrets, raw payloads, and diagnostic projections outside public response schemas.

## Review Focus

- The network identities route requires both `devices.read` and `context.read`.
- Collection creation documents both 201 creation and 200 replay.
- The collection request schema advertises only profiles accepted by the service route.
- Snapshot history includes baseline and inventory profiles while excluding diagnostic projections.
- Context response schemas contain only current public projection fields.
- Existing operation/module path objects stay unchanged after regeneration.

## Task 1: Reproduce the contract gap

**Files:** `tests/contracts/test_contract_artifacts.py`

- [x] Add a test of the seven exact method/path pairs, bearer security, route-specific `x-required-scopes`, 401/403/422 responses, applicable 404 responses, and public response schema references.
- [x] Add assertions for safe projection fields and absence of private database fields or diagnostic sections.
- [x] Run the focused test and confirm failure on the missing Context paths.

## Task 2: Publish the existing Context router

**Files:** `tools/contracts/generate_contract_artifacts.py`, `endpoint_server/context/routes.py`

- [x] Add the seven explicit paths to the existing service path list and include the Context router in the same temporary FastAPI application.
- [x] Add documentation-only Pydantic response models, `ServiceBearer` security, exact required scopes, and 401/403/404/422 metadata to each Context route.
- [x] Keep handler signatures, bodies, and `require_service_scope(...)` dependencies intact.
- [x] Run the focused test to green, then run the contract artifact and Context API tests.

## Task 3: Regenerate and verify

**Files:** `contracts/openapi/endpoint-platform-v1.yaml`

- [x] Run `python tools/contracts/generate_contract_artifacts.py --write` and then `--check`.
- [x] Run relevant contract, Context API, and SDK tests, followed by the repository suite.
- [x] Regenerate again and verify no diff, compare prior operation/module path objects, inspect all generated schema references and the complete final diff.
- [x] Commit only task files with a Conventional Commit message, after status, diff, diff-check, and tests pass.
