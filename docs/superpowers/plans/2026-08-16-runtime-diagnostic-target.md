# Runtime Diagnostic Target API Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Provide Helpdesk with an authenticated, fail-closed Endpoint-owned runtime projection for one preselected device.

**Architecture:** A device bearer writes server-observed heartbeat data to the existing durable `DeviceInstance` and `DeviceSession` records. A new service route reads that bounded runtime projection only after both the Helpdesk client identity and exact scope authorize it; shared strict response models provide the adapter-facing parser and fixture surface.

**Tech Stack:** Python 3.12, FastAPI, Pydantic v2, SQLAlchemy async, Alembic, pytest/httpx.

## Global Constraints

- `device_ref` is exactly an Endpoint `Device.id` UUID; perform no Registry, person, binding, or asset lookup.
- Service authorization requires both `client_identifier == "helpdesk"` and scope `helpdesk.diagnostic_target.read`.
- Device heartbeat uses the existing device bearer and `agent_heartbeat_v1`; client `reported_at` never establishes presence.
- Presence uses durable server-observed session/heartbeat state and an exact 90-second TTL.
- `connection_state` is exactly `online` or `offline`, and `online` matches it.
- Success data has exactly `device_ref`, `online`, `connection_state`, `last_seen_at`, `last_handshake_at`, and `agent_version` under `schema_version: endpoint_runtime_v1` and the caller's exact correlation ID.
- Only an existing Endpoint UUID yields the correlated `endpoint_device_not_found` 404 envelope. Invalid/malformed/unavailable cases are never 404.
- Never emit MAC/IP/install ID/tokens/raw agent metadata/Registry data in this API or its audit event.
- Do not modify Helpdesk source; adapter-facing strict parser and fixtures live in this repository.

---

## File structure

- `endpoint_contracts/runtime.py`: strict, reusable success and not-found envelope models plus the fail-closed adapter parser.
- `endpoint_contracts/__init__.py`: exports only the public runtime contract symbols.
- `endpoint_server/db/models/devices.py`: adds a durable server-observed heartbeat timestamp to `DeviceSession`.
- `endpoint_server/db/migrations/versions/0011_runtime_session_heartbeat.py`: additive migration for the timestamp and runtime lookup index.
- `endpoint_server/runtime/routes.py`: device heartbeat persistence and Helpdesk-only runtime read endpoint.
- `endpoint_server/runtime/__init__.py`: marks the bounded runtime domain package.
- `endpoint_server/auth/scopes.py`: declares the diagnostic-target scope and exact Helpdesk dependency.
- `endpoint_server/main.py`: mounts the runtime router.
- `tools/contracts/generate_contract_artifacts.py`: publishes runtime schemas, fixture payloads and OpenAPI paths.
- `tests/server/test_runtime_diagnostic_target_api.py`: endpoint acceptance tests against SQLite/ASGI.
- `tests/contracts/test_runtime_contracts.py`: strict parser, redacted shadow and fail-closed classification tests.
- Generated `contracts/` and `tests/fixtures/contracts/` artifacts: checked contract output.

### Task 1: Define runtime contract and Helpdesk adapter fixtures

**Files:**
- Create: `endpoint_contracts/runtime.py`
- Modify: `endpoint_contracts/__init__.py`
- Modify: `tools/contracts/generate_contract_artifacts.py`
- Create: `tests/contracts/test_runtime_contracts.py`
- Modify: `tests/contracts/test_contract_models.py`

**Interfaces:**
- Produces `RuntimeDiagnosticTargetV1`, `RuntimeDiagnosticTargetEnvelopeV1`, `RuntimeDiagnosticTargetNotFoundEnvelopeV1`, and `parse_runtime_diagnostic_target_response(payload, correlation_id)`.
- The parser returns the strict success envelope or raises `RuntimeDiagnosticTargetUnavailable` for malformed JSON/object fields, unknown fields, schema mismatch, correlation mismatch, and unavailable HTTP inputs.

- [ ] **Step 1: Write failing strict-contract tests**

```python
def test_runtime_adapter_rejects_extra_field_and_correlation_mismatch() -> None:
    payload = {"schema_version": "endpoint_runtime_v1", "correlation_id": "corr-1",
               "data": {"device_ref": str(uuid4()), "online": True,
                        "connection_state": "online", "last_seen_at": None,
                        "last_handshake_at": None, "agent_version": "3.2.11",
                        "ip": "192.0.2.1"}}
    with pytest.raises(RuntimeDiagnosticTargetUnavailable):
        parse_runtime_diagnostic_target_response(payload, "corr-1")
    payload["data"].pop("ip")
    with pytest.raises(RuntimeDiagnosticTargetUnavailable):
        parse_runtime_diagnostic_target_response(payload, "corr-2")
```

- [ ] **Step 2: Run contract tests to verify failure**

Run: `python -m pytest tests/contracts/test_runtime_contracts.py -q`

Expected: FAIL because `endpoint_contracts.runtime` and its parser do not exist.

- [ ] **Step 3: Add immutable extra-forbid Pydantic envelopes and parser**

```python
class RuntimeDiagnosticTargetEnvelopeV1(ContractModelV1):
    schema_version: Literal["endpoint_runtime_v1"]
    correlation_id: CorrelationID
    data: RuntimeDiagnosticTargetV1

def parse_runtime_diagnostic_target_response(
    payload: object, correlation_id: str
) -> RuntimeDiagnosticTargetEnvelopeV1:
    try:
        parsed = RuntimeDiagnosticTargetEnvelopeV1.model_validate(payload)
    except ValidationError as error:
        raise RuntimeDiagnosticTargetUnavailable("invalid runtime target") from error
    if not hmac.compare_digest(parsed.correlation_id, correlation_id):
        raise RuntimeDiagnosticTargetUnavailable("correlation mismatch")
    return parsed
```

Use a string validation alias that accepts non-empty printable ASCII through 128 characters. Add a redacted shadow helper which projects only `online`, `connection_state`, `last_seen_at`, `last_handshake_at`, and `agent_version`; it must reject unknown data before projection.

- [ ] **Step 4: Publish models and generated artifacts**

Add runtime models to `endpoint_contracts.__all__`, `PUBLIC_MODELS`, fixture definitions, service bearer OpenAPI security, and explicit `/agent/v1/runtime/heartbeat` / `/service/v1/runtime/devices/{device_ref}` paths. Run:

```powershell
python tools/contracts/generate_contract_artifacts.py --write
```

- [ ] **Step 5: Run contract tests and artifact consistency check**

Run: `python -m pytest tests/contracts/test_runtime_contracts.py tests/contracts/test_contract_models.py tests/contracts/test_contract_artifacts.py -q`

Expected: PASS, including strict parsing, redacted shadow equality, correlation mismatch and invalid/unavailable fail-closed cases.

- [ ] **Step 6: Commit the contract unit**

```powershell
git add endpoint_contracts tools/contracts contracts tests/contracts tests/fixtures/contracts
git commit -m "feat: define runtime diagnostic target contract"
```

### Task 2: Persist server-observed durable heartbeat state

**Files:**
- Modify: `endpoint_server/db/models/devices.py`
- Create: `endpoint_server/db/migrations/versions/0011_runtime_session_heartbeat.py`
- Create: `endpoint_server/runtime/__init__.py`
- Create: `endpoint_server/runtime/routes.py`
- Modify: `endpoint_server/main.py`
- Create: `tests/server/test_runtime_diagnostic_target_api.py`

**Interfaces:**
- Consumes `AgentHeartbeatV1` and `_authenticate_device(session, request)`.
- Produces `POST /agent/v1/runtime/heartbeat` with 204 on a matched device bearer/body and durable instance/session timestamps.
- A session used by this route has `last_handshake_at` set from `datetime.now(UTC)` and `expires_at = observed_at + timedelta(seconds=90)`.

- [ ] **Step 1: Write failing device-heartbeat tests**

```python
response = await client.post(
    "/agent/v1/runtime/heartbeat", headers={"Authorization": f"Bearer {token}"},
    json={"schema_version": "agent_heartbeat_v1", "device_id": str(device.id),
          "platform": "linux", "agent_version": "3.2.11",
          "reported_at": "2000-01-01T00:00:00Z"},
)
assert response.status_code == 204
assert session_row.last_handshake_at > datetime(2026, 1, 1, tzinfo=UTC)
assert session_row.expires_at - session_row.last_handshake_at == timedelta(seconds=90)
```

Add a second test where the bearer belongs to a different UUID and assert 401, and a body with an extra key and assert 422.

- [ ] **Step 2: Run the heartbeat tests to verify failure**

Run: `python -m pytest tests/server/test_runtime_diagnostic_target_api.py -k heartbeat -q`

Expected: FAIL with route-not-found or missing `last_handshake_at` model column.

- [ ] **Step 3: Add additive schema and heartbeat route**

Add nullable `DeviceSession.last_handshake_at` and a descending `(device_id, last_handshake_at, id)` index in model and Alembic revision. In `runtime/routes.py`, authenticate device bearer, reject `body.device_id != principal.device.id`, locate or create the sole `DeviceInstance` named `runtime-gateway`, update its `agent_version` and `last_seen_at` using server UTC time, then lock/update its latest open runtime session or insert a new server-generated session. Commit the transaction only after all writes succeed.

- [ ] **Step 4: Mount and verify heartbeat behavior**

Register the runtime router in `create_app`, then run:

```powershell
python -m pytest tests/server/test_runtime_diagnostic_target_api.py -k heartbeat -q
python -m pytest tests/server/test_migrations.py -q
```

Expected: PASS; no client `reported_at` value determines stored presence.

- [ ] **Step 5: Commit durable heartbeat support**

```powershell
git add endpoint_server tests/server/test_runtime_diagnostic_target_api.py
git commit -m "feat: persist endpoint runtime heartbeats"
```

### Task 3: Enforce Helpdesk-only runtime read projection and audit

**Files:**
- Modify: `endpoint_server/auth/scopes.py`
- Modify: `endpoint_server/runtime/routes.py`
- Modify: `tests/server/test_runtime_diagnostic_target_api.py`
- Modify: `endpoint_server/db/models/__init__.py` only if the test needs direct `AuditEvent` import.

**Interfaces:**
- Produces `require_helpdesk_diagnostic_target_read(request) -> ServicePrincipal`.
- Produces `GET /service/v1/runtime/devices/{device_ref}` with a `RuntimeDiagnosticTargetEnvelopeV1` response and exact `X-Correlation-ID` echo.
- Produces a `RuntimeDiagnosticTargetNotFoundEnvelopeV1` only when the endpoint device UUID does not exist.

- [ ] **Step 1: Write failing service acceptance tests**

```python
response = await client.get(
    f"/service/v1/runtime/devices/{device.id}",
    headers={"Authorization": "Bearer helpdesk-token", "X-Correlation-ID": "diag-42"},
)
assert response.status_code == 200
assert response.headers["X-Correlation-ID"] == "diag-42"
assert response.json() == {
    "schema_version": "endpoint_runtime_v1", "correlation_id": "diag-42",
    "data": {"device_ref": str(device.id), "online": True,
             "connection_state": "online", "last_seen_at": expected_seen,
             "last_handshake_at": expected_handshake, "agent_version": "3.2.11"},
}
```

Add cases for no bearer (401), scope-only non-Helpdesk client (403), Helpdesk without scope (403), missing/invalid correlation (422), malformed UUID (422), unknown UUID exact 404 envelope, absent heartbeat offline, expired heartbeat offline, and audit/API text assertions excluding `Bearer`, MAC, IP, install ID and raw metadata markers.

- [ ] **Step 2: Run the service tests to verify failure**

Run: `python -m pytest tests/server/test_runtime_diagnostic_target_api.py -k diagnostic_target -q`

Expected: FAIL because the Helpdesk-only dependency and service route do not exist.

- [ ] **Step 3: Implement exact authorization, correlation validation and projection**

Declare `HELPDESK_DIAGNOSTIC_TARGET_READ_SCOPE = "helpdesk.diagnostic_target.read"` and a dependency that delegates credential validation then requires literal scope membership and `principal.client.client_identifier == "helpdesk"`. Validate the request correlation before querying. Select only `Device`, latest `DeviceInstance` by server-observed `last_seen_at`, and latest runtime session; do not select context or enrollment tables. Build the Pydantic response with the six allowlisted data fields, determine `online` from `session.expires_at > now`, append a redacted audit event containing only `device_ref`, `online`, and `connection_state`, and commit before returning.

- [ ] **Step 4: Implement strict correlated 404**

When exact `Device.id` lookup returns none, return status 404 using `RuntimeDiagnosticTargetNotFoundEnvelopeV1`, set the header to the validated request value, and audit only the opaque UUID/request attribution. Never use this branch for invalid UUIDs, missing correlation, auth failure, invalid body, database failure, or parser failure.

- [ ] **Step 5: Run all service acceptance tests**

Run: `python -m pytest tests/server/test_runtime_diagnostic_target_api.py tests/server/test_service_auth.py tests/server/test_audit.py -q`

Expected: PASS, demonstrating double authorization, 90-second TTL semantics, exact schema/correlation, strict 404 and no forbidden field/audit leakage.

- [ ] **Step 6: Commit the service boundary**

```powershell
git add endpoint_server/auth endpoint_server/runtime tests/server/test_runtime_diagnostic_target_api.py
git commit -m "feat: expose helpdesk runtime diagnostic target"
```

### Task 4: Integrate validation and document deployment boundary

**Files:**
- Modify: `docs/superpowers/specs/2026-08-16-runtime-diagnostic-target-design.md` only if implementation differs from the approved design.
- Modify: `deploy/server/PRODUCTION_RUNBOOK.md` to document creation of the scoped `helpdesk` service credential and the 90-second runtime heartbeat expectation.
- Modify: generated contracts from Task 1 only if the consistency check identifies a mismatch.

**Interfaces:**
- Consumes the implemented runtime routes and generated schemas.
- Produces deployment guidance that preserves HTTPS/mTLS-or-service-bearer enforcement at the existing TLS boundary and never shares raw bearer material.

- [ ] **Step 1: Add a failing artifact/openapi assertion if route metadata is absent**

```python
def test_openapi_publishes_runtime_service_bearer_route() -> None:
    document = yaml.safe_load(Path("contracts/openapi/endpoint-platform-v1.yaml").read_text())
    assert "/service/v1/runtime/devices/{device_ref}" in document["paths"]
```

- [ ] **Step 2: Run the focused generated-artifact test**

Run: `python -m pytest tests/contracts/test_contract_artifacts.py -q`

Expected: PASS after the Task 1 generated artifacts are current; otherwise update the generator, not generated files by hand.

- [ ] **Step 3: Update operational documentation**

Document only the exact client identifier/scope, HTTPS public origin, correlation requirement, heartbeat TTL and absence of Registry authority. Do not include a bearer value, device identifier, IP, MAC or install identifier.

- [ ] **Step 4: Run the full relevant verification set**

Run:

```powershell
python tools/contracts/generate_contract_artifacts.py --check
python -m pytest tests/contracts tests/server/test_runtime_diagnostic_target_api.py tests/server/test_agent_gateway_api.py tests/server/test_service_auth.py tests/server/test_audit.py tests/server/test_migrations.py -q
git diff --check
```

Expected: all commands succeed with no artifact drift or whitespace errors.

- [ ] **Step 5: Commit documentation and final verification changes**

```powershell
git add deploy/server/PRODUCTION_RUNBOOK.md docs/superpowers/specs contracts tests
git commit -m "docs: document helpdesk runtime diagnostics"
```

## Self-review

- Spec coverage: Tasks 1–3 cover strict schema/parser, device bearer correlation, durable server timestamps, 90-second presence TTL, dual Helpdesk authorization, correlated responses/404, audit redaction and fail-closed adapter behavior. Task 4 covers artifacts and deployment guidance.
- Placeholder scan: no deferred implementation language or unspecified validation remains.
- Type consistency: Task 1 defines the envelope/parser used by Task 3; Task 2 defines durable `last_handshake_at` consumed by Task 3; all route paths match the approved design.
