# Endpoint Agent V2 Implementation Plan — 03 Gateway Wss

## Task 5: Define the neutral Gateway WSS contract

**Files:**
- Create: `endpoint_contracts/gateway_ws.py`
- Create: `contracts/jsonschema/agent_hello_v1.json`
- Create: `contracts/jsonschema/gateway_hello_v1.json`
- Create: `contracts/jsonschema/gateway_ws_envelope_v1.json`
- Create: `tests/contracts/test_gateway_ws_contract.py`
- Create: `tests/fixtures/gateway_ws/*.json`

**Interfaces:**

```python
class AgentHelloV1(BaseModel):
    schema_version: Literal["agent_hello_v1"]
    device_id: UUID
    agent_instance_id: UUID
    agent_version: str
    launcher_version: str
    platform: Literal["linux_amd64", "windows_amd64"]
    boot_id: str
    capabilities: list[str]
    last_result_sequence: int
    last_policy_revision: int

class GatewayHelloV1(BaseModel):
    schema_version: Literal["gateway_hello_v1"]
    session_id: UUID
    heartbeat_interval_seconds: int
    maximum_message_bytes: int
    policy_revision: int
    effective_capabilities: list[str]
    server_time: AwareDatetime
```

Envelope kinds:

```text
agent_hello
gateway_hello
heartbeat
command
command_ack
command_result
command_cancel
result_ack
policy_update
server_shutdown_notice
error
```

- [ ] **Step 1: Write strict schema tests**

Reject:

- unknown envelope kind;
- unknown fields;
- oversized strings/lists;
- negative sequence;
- missing timezone;
- ticket-specific required fields;
- arbitrary URL or executable parameters.

- [ ] **Step 2: Implement frozen Pydantic models**

Use `extra="forbid"`.

- [ ] **Step 3: Generate committed JSON Schemas**

- [ ] **Step 4: Add golden serialization fixtures**

- [ ] **Step 5: Run and commit**

```powershell
python -m pytest tests/contracts/test_gateway_ws_contract.py -q
git add endpoint_contracts contracts tests/contracts tests/fixtures
git commit -m "feat: define neutral gateway websocket contract"
```

---

## Task 6: Implement server-side Gateway WSS

**Files:**
- Create: `endpoint_server/gateway/ws_routes.py`
- Create: `endpoint_server/gateway/connection_registry.py`
- Create: `endpoint_server/gateway/protocol.py`
- Create: `endpoint_server/gateway/command_service.py`
- Create: `endpoint_server/gateway/presence_service.py`
- Modify: `endpoint_server/main.py`
- Modify: database models/migration for active session metadata when required
- Create: `tests/gateway/test_ws_authentication.py`
- Create: `tests/gateway/test_ws_delivery.py`
- Create: `tests/gateway/test_ws_reconnect.py`
- Create: `tests/gateway/test_ws_protocol_limits.py`

**Interfaces:**
- WSS route: `/agent/v1/connect`
- Existing device bearer authentication is reused.
- Existing command/context/update tables remain source of truth.

- [ ] **Step 1: Write authentication tests**

Test:

- valid device token;
- revoked token;
- wrong device;
- source outside approved CIDR;
- missing TLS proxy trust metadata;
- raw token never logged.

- [ ] **Step 2: Write single-active-session tests**

A newer authenticated session replaces the older session for the same `device_id`, sends a shutdown notice when possible, and records audit/presence state.

- [ ] **Step 3: Write delivery/replay tests**

A command is persisted before send.

After disconnect:

- unacknowledged command is replayed;
- acknowledged/running command is not blindly re-executed;
- terminal result is idempotent;
- result ACK advances the durable sequence.

- [ ] **Step 4: Implement bounded connection registry**

V1 may remain process-local only when production runs one API worker. Add a startup assertion that prevents unsupported multi-worker configuration.

- [ ] **Step 5: Implement heartbeats and presence**

Presence is derived from authenticated WSS session and heartbeat, not from agent-provided IP.

- [ ] **Step 6: Keep HTTPS pull routes enabled**

Do not remove them in this task.

- [ ] **Step 7: Run tests**

```powershell
python -m pytest tests/gateway -q
python -m pytest tests/context tests/updates -q
```

- [ ] **Step 8: Commit**

```powershell
git add endpoint_server endpoint_contracts tests/gateway
git commit -m "feat: add neutral agent gateway websocket"
```

---

## Task 7: Implement agent-side Gateway WSS transport

**Files:**
- Create: `pc_agent/transport/websocket.py`
- Create: `pc_agent/tests/transport/test_websocket_transport.py`
- Create: `pc_agent/tests/transport/test_websocket_reconnect.py`
- Modify: `pc_agent/runtime/application.py`
- Modify: config schema/defaults

**Interfaces:**
- Implements `GatewayTransport`.
- Uses existing device token and internal CA.
- Connects only to the configured Endpoint Platform origin.

- [ ] **Step 1: Write handshake tests**

Validate exact `AgentHelloV1` and `GatewayHelloV1`.

- [ ] **Step 2: Write TLS/origin tests**

Reject:

- `ws://`;
- IP substitution for configured hostname;
- `verify=False`;
- redirects to another host;
- artifact or API URLs outside Endpoint origin.

- [ ] **Step 3: Write reconnect tests**

Transient network failures use bounded exponential backoff with jitter.

Authentication/protocol denial is terminal and does not switch transport.

- [ ] **Step 4: Implement WSS send/receive loop**

Keep update artifacts on HTTPS.

- [ ] **Step 5: Implement explicit migration fallback**

Temporary config may specify:

```yaml
transport:
  mode: gateway_wss
  migration_http_pull_fallback: false
```

When the fallback flag is true, it may activate only after transport-level unavailability and only for the same Endpoint origin. It must never activate after 401, 403, schema error, or policy denial.

- [ ] **Step 6: Run integration tests**

```powershell
python -m pytest pc_agent/tests/transport pc_agent/tests/runtime tests/gateway -q
```

- [ ] **Step 7: Commit**

```powershell
git add pc_agent/transport pc_agent/runtime pc_agent/tests
git commit -m "feat: connect headless agent through gateway websocket"
```

---
