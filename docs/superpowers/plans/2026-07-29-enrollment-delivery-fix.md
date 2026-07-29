# Retry-Safe Enrollment Delivery Fix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make committed enrollment delivery recoverable from a pre-commit client proof, publish the actual wire contracts, protect audit correlation, destroy expired envelopes and define safe proxy trust.

**Architecture:** New strict transport models become the FastAPI request/response models and generated OpenAPI operations. A focused enrollment delivery module owns deterministic receipt derivation, locked recovery and bounded cleanup; route code owns authorization and transaction outcomes. Shared audit and source-address helpers remove duplicated unsafe header handling.

**Tech Stack:** Python 3.12, Pydantic v2, FastAPI, async SQLAlchemy, PostgreSQL, Alembic, pytest/httpx, JSON Schema and OpenAPI 3.1.

## Global Constraints

- Preserve all accepted campaign, claim, HMAC credential, rotation and atomic-audit invariants from `b312177`.
- Raw delivery nonce, campaign/claim bearer, receipt, hardware fingerprint and device token never persist or enter audit/log/error output.
- No agent runtime, WebSocket, Helpdesk/UI, production deployment or `pc_agent` changes.
- No schema migration unless a demonstrated persistence requirement cannot use the existing retry-envelope columns.
- Uvicorn proxy-header rewriting remains disabled; only the application resolves explicitly trusted proxies.

---

### Task 1: Publish exact agent HTTP contracts

**Files:**
- Modify: `endpoint_contracts/enrollment.py`
- Modify: `endpoint_contracts/__init__.py`
- Modify: `tools/contracts/generate_contract_artifacts.py`
- Modify: `tests/contracts/test_contract_models.py`
- Modify: `tests/contracts/test_contract_artifacts.py`
- Generate: `contracts/jsonschema/agent-enrollment-request-v1.json`
- Generate: `contracts/jsonschema/agent-enrollment-delivery-v1.json`
- Generate: `contracts/jsonschema/enrollment-delivery-proof-v1.json`
- Generate: `contracts/jsonschema/device-credential-rotation-v1.json`
- Modify: `contracts/openapi/endpoint-platform-v1.yaml`

**Interfaces:**
- Produces: `AgentEnrollmentRequestV1`, `AgentEnrollmentDeliveryV1`, `EnrollmentDeliveryProofV1`, `DeviceCredentialRotationV1`.
- Produces: concrete OpenAPI operations for all five `/agent/v1` enrollment/credential routes.
- Preserves: `EnrollmentRequestV1` and `EnrollmentResponseV1` unchanged.

- [ ] **Step 1: Write failing strict-model and OpenAPI tests**

```python
request = AgentEnrollmentRequestV1.model_validate({
    "schema_version": "agent_enrollment_request_v1",
    "platform": "linux",
    "hardware_fingerprint": "sha256:fixture",
    "installation_id": "install-fixture",
    "delivery_nonce": "A" * 43,
    "requested_at": "2026-07-29T12:00:00Z",
})
assert request.delivery_nonce == "A" * 43
assert openapi["paths"]["/agent/v1/enroll"]["post"]["responses"]["201"]
```

Also prove unknown fields, wrong discriminator and non-43-character/non-URL-safe nonce/token/receipt values fail. Assert secret-bearing schemas exist but their filenames are absent from `FIXTURES`.

- [ ] **Step 2: Run RED**

Run: `python -m pytest tests/contracts/test_contract_models.py tests/contracts/test_contract_artifacts.py -q`

Expected: collection fails because the four transport models do not exist.

- [ ] **Step 3: Implement strict models and generated paths**

Use literal schema versions and `Field(pattern=r"^[A-Za-z0-9_-]{43}$", repr=False)`. Keep `PUBLIC_MODELS` for every published schema and restrict committed golden payloads to the existing secret-free `FIXTURES`. Generate request/response `$ref` operations and an HTTP bearer security scheme from the same model registry.

- [ ] **Step 4: Generate and verify artifacts**

Run:

```powershell
python tools/contracts/generate_contract_artifacts.py --write
python tools/contracts/generate_contract_artifacts.py --check
python -m pytest tests/contracts -q
```

Expected: contract tests pass and no secret-bearing fixture is created.

### Task 2: Recover a lost committed response

**Files:**
- Create: `endpoint_server/enrollment/delivery.py`
- Modify: `endpoint_server/enrollment/credentials.py`
- Modify: `endpoint_server/enrollment/agent_routes.py`
- Modify: `tests/server/test_device_credentials.py`
- Modify: `tests/server/test_agent_enrollment_api.py`
- Modify: `tests/server/test_enrollment_postgresql.py`

**Interfaces:**
- Produces: `derive_enrollment_receipt(session_secret: bytes, *, delivery_nonce: str, device_identifier: str, campaign_id: UUID, claim_id: UUID | None, platform: str, requested_at: datetime) -> str`.
- Modifies: `seal_retry_envelope(..., receipt: str | None = None)`; default remains random for existing callers.
- Route behavior: first enrollment returns 201; a proven duplicate returns the identical `AgentEnrollmentDeliveryV1` with 200 and no mutation/audit.

- [ ] **Step 1: Write failing deterministic-derivation tests**

```python
receipt = derive_enrollment_receipt(
    b"session-secret",
    delivery_nonce="A" * 43,
    device_identifier="dev_" + "1" * 64,
    campaign_id=UUID("11111111-1111-4111-8111-111111111111"),
    claim_id=None,
    platform="linux",
    requested_at=datetime(2026, 7, 29, 12, tzinfo=UTC),
)
same_receipt = derive_enrollment_receipt(
    b"session-secret",
    delivery_nonce="A" * 43,
    device_identifier="dev_" + "1" * 64,
    campaign_id=UUID("11111111-1111-4111-8111-111111111111"),
    claim_id=None,
    platform="linux",
    requested_at=datetime(2026, 7, 29, 12, tzinfo=UTC),
)
assert len(urlsafe_b64decode(receipt + "=")) == 32
assert receipt == same_receipt
```

Assert changing each ordered field changes the result and timezone-equivalent timestamps do not.

- [ ] **Step 2: Run derivation RED**

Run: `python -m pytest tests/server/test_device_credentials.py -q`

Expected: import fails because `endpoint_server.enrollment.delivery` is absent.

- [ ] **Step 3: Implement canonical HMAC encoding**

Prefix with `b"endpoint-enrollment-delivery-receipt-v1\0"`. Encode every field as `len(value).to_bytes(4, "big") + value`; UUID values use 16 raw bytes; the absent claim uses a zero-length field; timestamps use UTC `isoformat(timespec="microseconds")`.

- [ ] **Step 4: Write failing lost-response HTTP tests**

Send the same complete request twice without using the first response. Assert 201 then 200, byte-for-byte equal JSON, one device, one quota use and no new audit row on the second call. Add changed nonce and changed `requested_at` cases that return generic unavailable/denied and do not mutate.

- [ ] **Step 5: Run route RED**

Run: `python -m pytest tests/server/test_agent_enrollment_api.py -q`

Expected: the route rejects the new request discriminator/nonce or returns the old duplicate 409.

- [ ] **Step 6: Implement duplicate recovery**

Use the canonical request model directly. On new enrollment derive the receipt before mutation and pass it into `seal_retry_envelope`. On an attributed existing device, derive the receipt again, lock its credential/envelope, recover and validate the token and return the original delivery. Do not append audit or commit in the recovery branch.

- [ ] **Step 7: Run focused GREEN**

Run: `python -m pytest tests/server/test_device_credentials.py tests/server/test_agent_enrollment_api.py -q`

Expected: all focused tests pass.

### Task 3: HMAC untrusted audit correlation

**Files:**
- Create: `endpoint_server/audit/request_ids.py`
- Modify: `endpoint_server/auth/admin_sessions.py`
- Modify: `endpoint_server/enrollment/admin_routes.py`
- Modify: `endpoint_server/enrollment/agent_routes.py`
- Modify: `tests/server/test_audit.py`
- Modify: `tests/server/test_admin_auth.py`
- Modify: `tests/server/test_enrollment_admin_api.py`
- Modify: `tests/server/test_agent_enrollment_api.py`

**Interfaces:**
- Produces: `audit_request_id(request: Request) -> str`.
- Output: `external_<64 lowercase hex>` for supplied headers and `server_<32 lowercase hex>` when absent.

- [ ] **Step 1: Write failing injection tests**

```python
for marker in (campaign_token, claim_token, receipt, device_token, "Bearer secret-marker"):
    correlation = audit_request_id(request_with_header(marker))
    assert marker not in correlation
    assert correlation == audit_request_id(request_with_header(marker))
```

Exercise campaign/claim create, enrollment, ack and rotation mutations and assert markers are absent from every `AuditEvent` representation/details/request ID and from error bodies.

- [ ] **Step 2: Run RED**

Run: `python -m pytest tests/server/test_audit.py tests/server/test_admin_auth.py tests/server/test_enrollment_admin_api.py tests/server/test_agent_enrollment_api.py -q`

Expected: raw supplied `X-Request-ID` values appear in current route audit rows.

- [ ] **Step 3: Implement and adopt shared correlation**

Use HMAC-SHA256 under `request.app.state.settings.session_secret` with domain `b"endpoint-audit-request-id-v1\0"`. Hash raw UTF-8 bytes without logging or reflecting them. Replace all route-local `_request_id` helpers.

- [ ] **Step 4: Run audit GREEN**

Run the same four test modules; expected all pass.

### Task 4: Destroy expired envelopes safely

**Files:**
- Modify: `endpoint_server/enrollment/delivery.py`
- Modify: `endpoint_server/enrollment/agent_routes.py`
- Modify: `endpoint_server/worker.py`
- Modify: `tests/server/test_agent_enrollment_api.py`
- Create: `tests/server/test_enrollment_cleanup.py`
- Modify: `tests/server/test_enrollment_postgresql.py`
- Modify: `tests/server/test_health.py`

**Interfaces:**
- Produces: `cleanup_expired_retry_envelopes(session: AsyncSession, *, request_id: str, now: datetime | None = None, limit: int = 100) -> int`.
- Modifies: `run_worker(settings, session_provider=None, *, cleanup_interval_seconds: float = 60.0)`.

- [ ] **Step 1: Write failing observed-expiry and batch tests**

Assert an expired matching retry request deletes the envelope, adds exactly one bounded `enrollment.delivery_expired` audit event and commits. Assert wrong receipt/fingerprint does not delete. For batch cleanup, assert the SQL selection has `LIMIT 100`, `FOR UPDATE SKIP LOCKED`, deletes only returned expired rows and audits each.

- [ ] **Step 2: Run cleanup RED**

Run: `python -m pytest tests/server/test_agent_enrollment_api.py tests/server/test_enrollment_cleanup.py -q`

Expected: observed expiry leaves the row and the cleanup module/function is absent.

- [ ] **Step 3: Implement locked observed expiry and batch cleanup**

Keep envelope lookup under `FOR UPDATE`. Verify the presented receipt digest before classifying expiry. Delete and audit in the route transaction, then commit before returning the generic unavailable response. Batch rows use `expires_at <= now`, stable expiry/ID ordering, `limit(limit)` and `with_for_update(skip_locked=True)`.

- [ ] **Step 4: Wire periodic worker**

The worker owns or accepts a session provider, executes one cleanup batch per interval, commits success, rolls back failure, remains cancellable and closes only providers it owns.

- [ ] **Step 5: Run cleanup GREEN**

Run: `python -m pytest tests/server/test_agent_enrollment_api.py tests/server/test_enrollment_cleanup.py tests/server/test_health.py -q`

Expected: all pass.

### Task 5: Resolve trusted proxy source safely and accept

**Files:**
- Modify: `endpoint_server/config.py`
- Create: `endpoint_server/network.py`
- Modify: `endpoint_server/enrollment/agent_routes.py`
- Modify: `tests/server/test_config.py`
- Modify: `tests/server/test_agent_enrollment_api.py`
- Modify: `docs/superpowers/specs/2026-07-29-enrollment-design.md`
- Modify: `.superpowers/sdd/2026-07-29-enrollment/task-3-report.md` (ignored)

**Interfaces:**
- Adds: `Settings.trusted_proxy_cidrs: tuple[Network, ...]`, optional environment source `TRUSTED_PROXY_CIDRS`, default empty.
- Produces: `observed_client_address(request: Request) -> IPv4Address | IPv6Address`.

- [ ] **Step 1: Write failing proxy tests**

Prove an untrusted peer cannot spoof `X-Forwarded-For`; a trusted peer with exactly one valid forwarded IP resolves it; missing, comma-separated or malformed forwarded values from a trusted peer fail closed.

- [ ] **Step 2: Run proxy RED**

Run: `python -m pytest tests/server/test_config.py tests/server/test_agent_enrollment_api.py -q`

Expected: no trusted-proxy setting/helper exists and trusted proxy requests resolve to the proxy peer.

- [ ] **Step 3: Implement source resolver and documentation**

Default proxy CIDRs to empty in `Settings.from_environment`. Ignore forwarding headers for all non-trusted peers. For trusted peers require one IP with no comma or whitespace ambiguity. Update enrollment design with the Uvicorn-disabled/Nginx-overwrite deployment invariant.

- [ ] **Step 4: Run focused and full verification**

```powershell
python -m pytest tests/contracts tests/server -q
python -m pytest tests -q
python -m ruff format --check endpoint_contracts endpoint_server tests/server tools/contracts
python -m ruff check endpoint_contracts endpoint_server tests/server tools/contracts
python -m compileall -q endpoint_server endpoint_contracts tools shared
python tools/contracts/generate_contract_artifacts.py --check
python tools/extraction/check_retained_tree.py
python -m alembic upgrade head --sql | Out-Null
python -m alembic downgrade 0005_enrollment_campaigns:base --sql | Out-Null
git diff --check
git diff --exit-code b312177 -- pc_agent
```

Expected: all commands exit zero; PostgreSQL execution tests remain opt-in when no loopback disposable URL is configured.

- [ ] **Step 5: Commit coherent review fix**

```powershell
git add endpoint_contracts endpoint_server contracts tests tools docs
git commit -m "fix: harden retry-safe enrollment delivery"
```
