# Endpoint Operations Release Gates v1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restrict the Endpoint Operations correlation policy to its four public routes and make provider release evidence reproducible in GitHub Actions.

**Architecture:** Keep route ownership and the generated OpenAPI unchanged. Replace prefix matching in the HTTP middleware with method-plus-path-shape recognition, then prove both positive and negative boundaries in the existing operations tests. A provider workflow runs the contract, operations, Gateway, artifact-drift, compilation and diff gates on the provider surface.

**Tech Stack:** Python 3.12, FastAPI/Starlette, pytest, GitHub Actions.

**Spec:** `C:/Users/admin-2/.codex/attachments/7f3ca8d4-acc5-4719-9dba-2a92bbf48505/pasted-text.txt`

## Global Constraints

- Base is immutable Endpoint mainline merge `b50bee41b1c19174cba1f3ee0d28610d4b1d11e2`; no production action, credentials, configuration, agent rollout, or OpenAPI wire-contract change.
- The middleware may recognize only: `GET /api/v1/devices/{segment}`, `GET /api/v1/devices/{segment}/capabilities`, `POST /api/v1/devices/{segment}/operations`, and `GET /api/v1/operations/{segment}`.
- Do not parse UUIDs in middleware; router validation remains authoritative.
- The committed OpenAPI Git blob must be unchanged, checked by `python tools/contracts/generate_contract_artifacts.py --check`.

---

### Task 1: Exact Operations correlation boundary

**Files:**
- Modify: `endpoint_server/http/correlation.py`, `endpoint_server/main.py`
- Test: `tests/operations/test_operation_routes.py`

**Interfaces:**
- Consumes: FastAPI `Request.method`, `Request.url.path`, and `X-Correlation-ID`.
- Produces: `is_operation_api_request(method: str, path: str) -> bool`, used only by `echo_operation_correlation`.

- [ ] **Step 1: Write failing route-shape tests**

```python
assert is_operation_api_request("GET", "/api/v1/devices/device")
assert is_operation_api_request("GET", "/api/v1/devices/device/capabilities")
assert is_operation_api_request("POST", "/api/v1/devices/device/operations")
assert is_operation_api_request("GET", "/api/v1/operations/operation")
assert not is_operation_api_request("GET", "/api/v1/devices/device/context")
assert not is_operation_api_request("GET", "/api/v1/devices/network-identities")
assert not is_operation_api_request("GET", "/api/v1/devices/device/updates")
assert not is_operation_api_request("POST", "/api/v1/operations/operation")
```

- [ ] **Step 2: Run RED**

Run: `python -m pytest tests/operations/test_operation_routes.py -q --tb=short`

Expected: import/attribute failure because `is_operation_api_request` does not exist.

- [ ] **Step 3: Implement exact matcher and middleware use**

```python
def is_operation_api_request(method: str, path: str) -> bool:
    segments = path.split("/")
    return (
        (method == "GET" and len(segments) == 5 and segments[:4] == ["", "api", "v1", "devices"] and bool(segments[4]))
        or (method == "GET" and len(segments) == 6 and segments[:4] == ["", "api", "v1", "devices"] and bool(segments[4]) and segments[5] == "capabilities")
        or (method == "POST" and len(segments) == 6 and segments[:4] == ["", "api", "v1", "devices"] and bool(segments[4]) and segments[5] == "operations")
        or (method == "GET" and len(segments) == 5 and segments[:4] == ["", "api", "v1", "operations"] and bool(segments[4]))
    )
```

Replace each middleware predicate with `is_operation_api_request(request.method, request.url.path)`; retain the existing invalid-header 422 JSON and safe-header echo behavior.

- [ ] **Step 4: Run focused GREEN**

Run: `python -m pytest tests/operations/test_operation_routes.py -q --tb=short`

Expected: all operations-route tests pass.

- [ ] **Step 5: Commit the implementation**

```powershell
git add endpoint_server/http/correlation.py endpoint_server/main.py
git commit -m "fix(api): scope correlation validation to operation routes"
```

### Task 2: Correlation boundary regression evidence

**Files:**
- Modify: `tests/operations/test_operation_routes.py`

**Interfaces:**
- Consumes: the four route matcher shapes and the FastAPI app factory.
- Produces: tests proving invalid headers fail without echo/body disclosure on Operations routes and leave unrelated device APIs unchanged.

- [ ] **Step 1: Write one failing middleware-isolation test**

```python
response = client.get("/api/v1/devices/network-identities", headers={"X-Correlation-ID": "bad value space"})
assert response.status_code != 422
assert response.headers.get("X-Correlation-ID") is None
```

Add a separate invalid-header operation-route assertion for `422`, missing echo, and no invalid value in `response.text`.

- [ ] **Step 2: Run RED**

Run: `python -m pytest tests/operations/test_operation_routes.py -q --tb=short`

Expected: failure while prefix-based middleware still classifies an unrelated route.

- [ ] **Step 3: Keep the Task 1 matcher as the minimal fix**

No new production behavior beyond `is_operation_api_request` is permitted.

- [ ] **Step 4: Run GREEN and artifact check**

Run: `python -m pytest tests/operations/test_operation_routes.py -q --tb=short`

Run: `python tools/contracts/generate_contract_artifacts.py --check`

Expected: tests pass and generated artifacts are unchanged.

- [ ] **Step 5: Commit test evidence**

```powershell
git add tests/operations/test_operation_routes.py
git commit -m "test(api): cover exact operation correlation boundary"
```

### Task 3: Provider GitHub release gate

**Files:**
- Create or modify: `.github/workflows/endpoint-operation-provider.yml`

**Interfaces:**
- Consumes: changed provider surface paths and the repository Python test suites.
- Produces: JUnit XML artifacts for provider release-gate tests on PRs to `main`, pushes to `main`, and manual dispatch.

- [ ] **Step 1: Write a workflow-contract assertion or inspect existing CI conventions**

```python
workflow = Path(".github/workflows/endpoint-operation-provider.yml").read_text(encoding="utf-8")
assert "pull_request:" in workflow and "main" in workflow
assert "push:" in workflow and "workflow_dispatch:" in workflow
assert "--junitxml=artifacts/endpoint-operation-provider.xml" in workflow
```

- [ ] **Step 2: Run RED**

Run: `python -m pytest tests/contracts -q --tb=short`

Expected: workflow assertion fails until the release-gate workflow exists.

- [ ] **Step 3: Implement the workflow**

Use the stated critical paths. Install `requirements-ci.txt`; run `tests/contracts`, `tests/operations`, `tests/gateway`, artifact generation `--check`, `python -m compileall -q endpoint_contracts endpoint_server pc_agent`, and `git diff --check`; direct pytest output to `artifacts/endpoint-operation-provider.xml`; upload it with `actions/upload-artifact@v4`.

- [ ] **Step 4: Validate static workflow content and local commands**

Run: `python -m pytest tests/contracts tests/operations tests/gateway -q --tb=short`

Run: `python tools/contracts/generate_contract_artifacts.py --check`

Run: `python -m compileall -q endpoint_contracts endpoint_server pc_agent`

Run: `git diff --check`

- [ ] **Step 5: Commit CI**

```powershell
git add .github/workflows/endpoint-operation-provider.yml
git commit -m "ci: verify endpoint operation provider release gates"
```

### Task 4: Release-readiness record and full provider verification

**Files:**
- Modify: `docs/segmentation/HELPDESK_ENDPOINT_OPERATIONS_CONTRACT_V1.md`
- Modify: `docs/superpowers/plans/2026-08-21-operations-release-gates-v1.md`

**Interfaces:**
- Consumes: verified no-wire-contract-change evidence and provider CI behavior.
- Produces: a concise release-gate record without claiming production execution.

- [ ] **Step 1: Add a failing documentation guard if documentation checks exist**

```python
assert "provider release gate" in Path("docs/segmentation/HELPDESK_ENDPOINT_OPERATIONS_CONTRACT_V1.md").read_text(encoding="utf-8").lower()
```

- [ ] **Step 2: Run RED**

Run: `python -m pytest tests/contracts -q --tb=short`

Expected: the guard fails until the release-gate evidence is documented.

- [ ] **Step 3: Document only local/CI evidence and non-production limits**

Record exact-path middleware scope, generated-contract stability, CI trigger coverage, and that no canary or production configuration changed.

- [ ] **Step 4: Run full requested Endpoint verification**

Run: `python -m pytest tests/contracts -q`

Run: `python -m pytest tests/operations -q`

Run: `python -m pytest tests/gateway -q`

Run: `python -m pytest tests/architecture -q`

Run: `python tools/contracts/generate_contract_artifacts.py --check`

Run: `python -m compileall -q endpoint_contracts endpoint_server pc_agent`

Run: `git diff --check`

- [ ] **Step 5: Commit documentation**

```powershell
git add docs/segmentation/HELPDESK_ENDPOINT_OPERATIONS_CONTRACT_V1.md docs/superpowers/plans/2026-08-21-operations-release-gates-v1.md
git commit -m "docs: record endpoint provider release readiness"
```
