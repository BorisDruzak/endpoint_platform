# Endpoint Operation v1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expose one safe, idempotent Endpoint Operation that delivers `context.diagnostic.collect` only through Gateway WSS.

**Architecture:** Public Pydantic contracts and an EndpointOperation table isolate service callers from existing ContextCollection and Command storage. The operations service creates the private context request transactionally; CommandService owns WSS materialization and atomically mirrors ACK/results to the operation while the existing neutral runtime executes the typed diagnostic collector.

**Tech Stack:** Python 3.12, Pydantic v2, FastAPI, SQLAlchemy 2, Alembic, pytest.

**Spec:** `docs/superpowers/specs/2026-08-09-endpoint-operation-v1-design.md`

## Global Constraints

- Preserve existing collection, enrollment, update, Gateway WSS and HTTP-pull behavior; only Endpoint Operations are WSS-only.
- Use strict Pydantic contracts and committed JSON Schema artifacts/fixtures.
- Do not put Helpdesk metadata in AgentCommand/Gateway WSS or introduce generic execution.
- Feature flag defaults to false; no production/test-agent/deployment action is allowed.
- TDD: every production behavior begins with a test observed to fail.

---

### Task 1: Public contract and artifacts

**Files:**
- Create: `endpoint_contracts/operations.py`, `tests/contracts/test_endpoint_operations_contract.py`, `tests/fixtures/endpoint_operations/*.json`, `contracts/jsonschema/endpoint-operation-*.json`
- Modify: `endpoint_contracts/__init__.py`, schema generator manifest/test

**Interfaces:**
- Produces: `EndpointOperationCreateV1`, `EndpointOperationV1`, `EndpointDiagnosticResultV1`, `EndpointOperationStatusV1`.

- [ ] **Step 1: Write failing contract tests**

```python
def test_create_rejects_extra_and_url_like_reason() -> None:
    with pytest.raises(ValidationError):
        EndpointOperationCreateV1.model_validate({**VALID, "extra": True})
    with pytest.raises(ValidationError):
        EndpointOperationCreateV1.model_validate({**VALID, "parameters": {"reason": "https://bad"}})
```

- [ ] **Step 2: Run the contract test and observe import failure**

Run: `python -m pytest tests/contracts/test_endpoint_operations_contract.py -q`

- [ ] **Step 3: Implement strict contract models and schema generation**

```python
class EndpointOperationCreateV1(ContractModelV1):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["endpoint_operation_create_v1"]
    capability: Literal["context.diagnostic.collect"]
    parameters: DiagnosticCollectionParametersV1
    correlation: EndpointOperationCorrelationV1 | None = None
```

- [ ] **Step 4: Run contract suite and commit**

Run: `python -m pytest tests/contracts -q`

Commit: `feat: add endpoint operation v1 contracts`

### Task 2: Persist scoped operations

**Files:**
- Create: `endpoint_server/operations/__init__.py`, `endpoint_server/operations/service.py`, `endpoint_server/operations/projection.py`, `endpoint_server/operations/capabilities.py`, `endpoint_server/db/models/operations.py`, `endpoint_server/db/migrations/versions/0014_endpoint_operations.py`, `tests/operations/test_operation_service.py`
- Modify: `endpoint_server/db/models/__init__.py`, context repository/expiration path

**Interfaces:**
- Consumes: Task 1 contracts; `ServiceClient`, `ContextCollection`.
- Produces: `create_operation_outcome`, `read_operation_for_service`, `expire_operations`, `EndpointOperation`.

- [ ] **Step 1: Write failing persistence tests**

```python
async def test_exact_service_key_replay_returns_same_operation(session) -> None:
    first, created = await create_operation_outcome(session, request=REQUEST, service_client_id=CLIENT, device_id=DEVICE, idempotency_key="operation-key-0001")
    replay, replayed = await create_operation_outcome(session, request=REQUEST, service_client_id=CLIENT, device_id=DEVICE, idempotency_key="operation-key-0001")
    assert created is True and replayed is False and replay.id == first.id
```

- [ ] **Step 2: Run and observe missing operations module**

Run: `python -m pytest tests/operations/test_operation_service.py -q`

- [ ] **Step 3: Implement model/migration/service transaction**

```python
async def create_operation_outcome(session, *, request, service_client_id, device_id, idempotency_key):
    # validate active device and capability, create operation + diagnostic collection,
    # append audit event in caller's single transaction, then return (operation, created)
```

- [ ] **Step 4: Verify operation tests and migration head, then commit**

Run: `python -m pytest tests/operations -q; python -m alembic heads`

Commit: `feat: persist scoped endpoint operations`

### Task 3: Service routes, scopes and safe projections

**Files:**
- Create: `endpoint_server/operations/routes.py`, `tests/operations/test_operation_routes.py`
- Modify: `endpoint_server/auth/scopes.py`, `endpoint_server/config.py`, `endpoint_server/main.py`, API documentation/OpenAPI assertions

**Interfaces:**
- Consumes: Task 2 service; `ServicePrincipal`.
- Produces: feature-gated `GET capabilities`, `POST device operations`, `GET operation` routes.

- [ ] **Step 1: Write failing authorization/idempotency tests**

```python
async def test_create_requires_scope_and_returns_201_then_200(client) -> None:
    assert (await client.post(PATH, json=BODY, headers={"Idempotency-Key": KEY})).status_code == 401
    assert (await scoped_client("operations.create").post(PATH, json=BODY, headers={"Idempotency-Key": KEY})).status_code == 201
```

- [ ] **Step 2: Run and observe absent route**

Run: `python -m pytest tests/operations/test_operation_routes.py -q`

- [ ] **Step 3: Add scopes, false-default feature flag and routes**

```python
OPERATIONS_CREATE_SCOPE = "operations.create"
OPERATIONS_READ_SCOPE = "operations.read"
router = APIRouter(prefix="/api/v1", tags=["endpoint-operations"])
```

- [ ] **Step 4: Verify routes/projections and commit**

Run: `python -m pytest tests/operations -q tests/context/test_service_api.py -q`

Commit: `feat: expose endpoint operation service api`

### Task 4: WSS-only Gateway delivery and lifecycle linkage

**Files:**
- Modify: `endpoint_server/gateway/command_service.py`, `endpoint_server/gateway/ws_routes.py`, context expiry worker/repository
- Create: `tests/gateway/test_endpoint_operation_delivery.py`

**Interfaces:**
- Consumes: Task 2 operation ↔ collection/command relation.
- Produces: WSS-only selector and atomic ACK/result mirroring.

- [ ] **Step 1: Write failing WSS-only tests**

```python
async def test_operation_is_absent_from_http_pull_and_sent_over_wss(session) -> None:
    assert await next_http_pull_command(session, DEVICE) is None
    assert (await next_pending_command(session, DEVICE, transport="gateway_wss")).capability == "context.diagnostic.collect"
```

- [ ] **Step 2: Run and observe selector lacks transport isolation**

Run: `python -m pytest tests/gateway/test_endpoint_operation_delivery.py -q`

- [ ] **Step 3: Implement persisted WSS selection and operation synchronization**

```python
if collection.operation_id is not None and transport != "gateway_wss":
    continue
# commit command/delivery before send; update linked operation only after ownership/digest/context validation
```

- [ ] **Step 4: Verify gateway/context suites and commit**

Run: `python -m pytest tests/gateway -q; python -m pytest tests/context -q`

Commit: `feat: deliver diagnostic operations through gateway wss`

### Task 5: Headless capability and release guards

**Files:**
- Modify: `pc_agent/context_profiles/command_execution.py`, `pc_agent/runtime/command_executor.py` only if a missing typed validation is demonstrated
- Create: `tests/architecture/test_no_helpdesk_agent_release_dependencies.py`
- Modify: packaging tests and `pc_agent/docs/CODEMAP.md` if runtime/package behavior changes

**Interfaces:**
- Consumes: unchanged `GatewayCommandV1` typed `reason` contract.
- Produces: released-surface AST/package scan and evidence that diagnostic stays bounded.

- [ ] **Step 1: Write failing release-surface and agent validation tests**

```python
def test_released_surfaces_exclude_helpdesk_runtime() -> None:
    assert scan_released_paths(RELEASED_PATHS) == []
```

- [ ] **Step 2: Run and observe no release guard exists**

Run: `python -m pytest tests/architecture/test_no_helpdesk_agent_release_dependencies.py -q`

- [ ] **Step 3: Implement only demonstrated guard/execution fixes**

```python
FORBIDDEN = {"ws_ticket_v3", "TicketApiClient", "pc_agent.ui_gui", "pc_agent.ws_agent", "exec_script"}
```

- [ ] **Step 4: Verify runtime/transport/packaging tests and commit**

Run: `python -m pytest tests/architecture -q; python -m pytest tests/packaging -q; python -m pytest pc_agent/tests/runtime -q; python -m pytest pc_agent/tests/transport -q`

Commit: `test: guard released agent from helpdesk dependencies`

### Task 6: Acceptance documentation and full verification

**Files:**
- Modify: `PLANS.md`, segmentation documents, service API/OpenAPI docs, `pc_agent/docs/CODEMAP.md` when Task 5 changes agent behavior

- [x] **Step 1: Record actual lifecycle, migration, route/scope and release-scan evidence**

```markdown
Operation creation is atomic; HTTP pull excludes linked operations; WSS result ACK follows the database commit.
```

- [x] **Step 2: Run focused and full verification**

Run: `python -m pytest tests/contracts -q; python -m pytest tests/operations -q; python -m pytest tests/gateway -q; python -m pytest tests/context -q; python -m pytest tests/architecture -q; python -m pytest tests/packaging -q; python -m pytest pc_agent/tests/runtime -q; python -m pytest pc_agent/tests/transport -q; python -m compileall -q endpoint_contracts endpoint_server pc_agent; git diff --check; python -m pytest -q`

- [x] **Step 3: Commit acceptance evidence**

Commit: `docs: record endpoint operation acceptance`

## Self-review

Tasks 1–5 map respectively to the required contract, persistence, service API,
WSS delivery, and release guard commits. Task 6 records only evidence from
executed checks; it does not claim production or test-agent changes.

### Acceptance evidence (2026-08-18)

- `python -m pytest tests/contracts -q`: 265 passed (66 warnings).
- `python -m pytest tests/operations -q`: 30 passed, 4 skipped (the optional
  PostgreSQL integration cases were not configured).
- `python -m pytest tests/context -q`: 36 passed, 1 skipped.
- `python -m pytest tests/architecture -q`: 67 passed, including the released
  RPM/MSI surface guard and typed diagnostic execution proof.
- `python -m pytest pc_agent/tests/transport -q`: 55 passed.
- `python -m pytest tests/gateway -q`: 54 passed, 2 failed. Both failures are
  in `test_agent_runtime_wss_identity_asgi.py`, which monkeypatches the absent
  `pc_agent.runtime.application._https_update_hook`; they do not exercise the
  Endpoint Operation delivery tests.
- `python -m pytest tests/packaging -q`: 57 passed, 1 skipped, 1 failed:
  `initial-runtime-3.2.13.json` has a stale hash for
  `pc_agent/context_profiles/baseline.py`.
- `python -m pytest pc_agent/tests/runtime -q` did not complete within the
  30-second local command limit: the first 31 tests ran, then
  `test_windows_core_artifact_excludes_all_optional_runtime_packages` remained
  running. The independent completed subsets were 14 gateway characterization,
  10 update characterization, and 39 headless import/lifecycle/verification
  tests passing. This is not recorded as a full runtime-suite pass.
- `python -m compileall -q endpoint_contracts endpoint_server pc_agent` and
  `git diff --check` completed successfully before the full-suite invocation.
  `python -m pytest -q` stopped at collection with two missing legacy imports:
  `scripts.build_module_zip` and `scripts.register_support_modules`.
