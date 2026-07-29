# web_ovpn Device Context Adapter Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let `web_ovpn` consume only Endpoint Platform's safe Device Context API through a TLS-verifying scoped client, then expose authenticated adapter endpoints with an explicit degraded mode.

**Architecture:** Publish a typed Python SDK in Endpoint Platform first. A clean `web_ovpn` worktree reads a root-managed service token and CA file, calls that SDK/service boundary with bounded read retries, and adapts normalized responses into its existing authenticated/CSRF-protected API. No raw agent result, diagnostic content, credential, IP-only correlation, or netctl merge is introduced.

**Tech Stack:** Python 3.14, FastAPI, Pydantic/httpx-compatible HTTPS client, pytest, existing `web_ovpn` FastAPI/Jinja2 application.

## Global Constraints

- Use only `devices.read`, `context.read`, and `context.collect` service scopes.
- TLS verification is mandatory; never use `verify=False`.
- Token comes from `ENDPOINT_PLATFORM_TOKEN_FILE`; no token or CA is committed.
- Retries are bounded and are permitted only for idempotent reads.
- All mutations propagate a caller-supplied idempotency key and preserve existing CSRF/auth/audit boundaries.
- Endpoint Platform outage returns a deterministic degraded response, never a local 500.
- `web_ovpn` Network Context remains separate; correlation is a later explicit projection and never IP-only.
- No remote migration, deployment, real collection, ALT pilot, network-device action, or dirty worktree edit belongs to this plan.

---

### Task 1: Typed safe Endpoint Platform SDK

**Files:**
- Create: `sdk/python/endpoint_platform_client/{__init__,client,models,errors}.py`
- Create: `tests/sdk/test_client.py`

**Interfaces:**
- `EndpointPlatformClient(base_url, token_file, ca_file, timeout_seconds)` exposes `list_devices()`, `get_device(device_id)`, `get_latest_context(device_id, profile)`, `request_collection(device_id, profile, idempotency_key)`, `get_collection(collection_id)`, and `compare_context(device_id, from_snapshot_id, to_snapshot_id)`.
- Every method returns typed safe models or raises a typed redacted error; it never exposes raw transport bodies in exception text.

- [ ] **Step 1: Write failing transport/security tests**

```python
def test_client_uses_ca_and_redacts_token_on_error(tmp_path):
    client = EndpointPlatformClient("https://endpoint.invalid", token_file=token(tmp_path), ca_file=ca(tmp_path))
    with pytest.raises(EndpointPlatformUnavailable) as exc:
        client.list_devices()
    assert "secret-token" not in str(exc.value)
```

- [ ] **Step 2: Verify RED**

Run: `python -m pytest tests/sdk/test_client.py -q`

Expected: import failure before the package exists.

- [ ] **Step 3: Implement strict client and models**

```python
def request_collection(self, device_id: UUID, profile: Literal["baseline_v1", "health_v1", "network_v1"], idempotency_key: str) -> Collection:
    return self._request("POST", f"/api/v1/context/devices/{device_id}/collections", json={"profile": profile}, headers={"Idempotency-Key": idempotency_key}, retry=False)
```

Use a configured CA bundle, read the token per client construction with restrictive error messages, validate JSON through typed models, reject diagnostic profile requests, and retry only safe GET operations a bounded number of times.

- [ ] **Step 4: Verify and commit**

Run: `python -m pytest tests/sdk/test_client.py tests/context/test_service_api.py -q`

```bash
git add sdk/python tests/sdk
git commit -m "feat: add endpoint platform service client"
```

### Task 2: web_ovpn configuration and authenticated adapter API

**Files:**
- Modify: `app/config.py`, `app/api.py`
- Create: `app/endpoint_platform_client.py`, `app/endpoint_context_adapter.py`
- Create: `tests/test_endpoint_platform_client.py`, `tests/test_endpoint_context_api.py`

**Interfaces:**
- `GET /api/v1/endpoints`, `GET /api/v1/endpoints/{device_id}`, `POST /api/v1/endpoints/{device_id}/collections`, `GET /api/v1/endpoint-collections/{collection_id}`, `GET /api/v1/endpoints/{device_id}/context/compare`.
- Adapter returns `{status: "degraded", code: "endpoint_platform_unavailable"}` for upstream outage and forwards only safe typed fields.

- [ ] **Step 1: Write failing auth/CSRF/degraded tests**

```python
def test_request_collection_requires_existing_csrf_and_forwards_idempotency(client, auth_headers, monkeypatch):
    response = client.post("/api/v1/endpoints/11111111-1111-1111-1111-111111111111/collections", json={"profile": "baseline_v1"}, headers=auth_headers | {"Idempotency-Key": "request-1"})
    assert response.status_code == 202
```

- [ ] **Step 2: Verify RED**

Run: `python -m pytest tests/test_endpoint_platform_client.py tests/test_endpoint_context_api.py -q`

Expected: routes/client imports do not exist.

- [ ] **Step 3: Implement config, adapter and routes**

```python
try:
    collection = adapter.request_collection(device_id, profile, idempotency_key)
except EndpointPlatformUnavailable:
    return {"status": "degraded", "code": "endpoint_platform_unavailable"}
```

Map existing authenticated principal/audit metadata without forwarding credentials or raw errors. Preserve existing CSRF checks for POST, propagate idempotency, and explicitly reject `diagnostic_v1`.

- [ ] **Step 4: Verify and commit**

Run: `python -m pytest tests/test_endpoint_platform_client.py tests/test_endpoint_context_api.py -q`

```bash
git add app tests
git commit -m "feat: add endpoint context adapter API"
```

## Follow-on Work

The Russian-first page/UI is a separate task after adapter acceptance. Explicit netctl correlation is another task and must require confirmed/manual binding or distinct evidence; it must never merge by IP alone.
