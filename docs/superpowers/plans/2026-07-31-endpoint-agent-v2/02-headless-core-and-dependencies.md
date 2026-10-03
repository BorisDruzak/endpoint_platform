# Endpoint Agent V2 Implementation Plan — 02 Headless Core And Dependencies

## Task 2: Create the neutral headless core entrypoint

**Files:**
- Create: `pc_agent/runtime/__init__.py`
- Create: `pc_agent/runtime/main.py`
- Create: `pc_agent/runtime/application.py`
- Create: `pc_agent/runtime/lifecycle.py`
- Create: `pc_agent/runtime/command_executor.py`
- Create: `pc_agent/runtime/verification.py`
- Create: `pc_agent/runtime/status.py`
- Modify: `pc_agent/ws_agent.py`
- Create: `pc_agent/tests/runtime/test_headless_imports.py`
- Create: `pc_agent/tests/runtime/test_headless_lifecycle.py`
- Create: `pc_agent/tests/runtime/test_headless_verify.py`

**Interfaces:**

```python
@dataclass(frozen=True, slots=True)
class RuntimeSettings:
    data_root: Path
    install_root: Path
    ca_file: Path
    endpoint_origin: str
    transport_mode: Literal["gateway_wss", "gateway_http_pull"]

async def run_runtime(settings: RuntimeSettings) -> int: ...
def run_verify(settings: RuntimeSettings) -> int: ...
```

- [ ] **Step 1: Write the failing import-boundary test**

The test imports `pc_agent.runtime.main` while blocking:

```text
PySide6
qasync
pc_agent.ui_gui
pc_agent.ui_bridge
pc_agent.ui_gui.server_api
```

Expected before implementation: import failure because `pc_agent.runtime` does not exist.

- [ ] **Step 2: Write lifecycle tests**

Cover:

```text
startup
credential load
transport start
command executor start
controlled update exit 42
clean shutdown
unexpected transport failure with reconnect
terminal credential rejection
```

- [ ] **Step 3: Implement `RuntimeSettings` and `run_runtime`**

Move only neutral responsibilities from `ws_agent.py` and `endpoint_gateway.py`.

Do not move GUI, Helpdesk registration, Ticket API, or Remote Assist UI into the core.

- [ ] **Step 4: Implement neutral command executor**

```python
class CommandExecutor:
    async def execute(self, command: AgentCommandV1) -> AgentResultV1:
        ...
```

It uses the existing typed Device Context execution path and rejects unknown capabilities before invoking a collector.

- [ ] **Step 5: Implement network-free verify mode**

Verify:

- configuration schema;
- local DB migration;
- identity/credential file structure;
- collector registry;
- update selector;
- import boundaries.

It must not connect to Gateway.

- [ ] **Step 6: Turn `ws_agent.py` into a compatibility entrypoint**

At this stage:

- accepted ALT Gateway mode delegates to `pc_agent.runtime.main`;
- legacy GUI/Helpdesk mode remains available only for existing development tests;
- no new platform package may use legacy mode.

- [ ] **Step 7: Run tests**

```powershell
python -m pytest pc_agent/tests/runtime -q
python -m compileall -q pc_agent
python -m pytest pc_agent/tests -m "not manual" -q
```

- [ ] **Step 8: Commit**

```powershell
git add pc_agent/runtime pc_agent/ws_agent.py pc_agent/tests/runtime
git commit -m "refactor: add neutral headless endpoint agent core"
```

---

## Task 3: Split runtime dependencies and build specifications

**Files:**
- Create: `requirements/agent-core.txt`
- Create: `requirements/agent-collectors.txt`
- Create: `requirements/agent-session-helper.txt`
- Create: `requirements/agent-remote-assist.txt`
- Create: `requirements/build-linux.txt`
- Create: `requirements/build-windows.txt`
- Create: `pc_agent/pyinstaller_endpoint_core_linux.spec`
- Create: `pc_agent/pyinstaller_endpoint_core_windows.spec`
- Create: `pc_agent/tests/runtime/test_dependency_split.py`
- Modify: `pc_agent/requirements.txt`
- Modify: relevant build documentation

**Interfaces:**
- Produces a core artifact that contains no Qt, Helpdesk UI, or Remote Assist dependencies.

- [ ] **Step 1: Write failing dependency tests**

Core requirements must not include:

```text
PySide6
qasync
aiortc
aioice
av
pylibsrtp
mss
Pillow
pynput
imageio-ffmpeg
```

- [ ] **Step 2: Define exact core dependencies**

Initial core set:

```text
aiohttp
aiosqlite
loguru
psutil
pydantic
PyYAML
```

Pin versions through the existing project dependency policy or a generated lock file. Do not claim “latest”.

- [ ] **Step 3: Create headless PyInstaller specs**

Entrypoint:

```text
pc_agent/runtime/main.py
```

Core specs must not collect GUI submodules or GUI assets.

- [ ] **Step 4: Keep old specs temporarily**

Mark inherited specs as legacy and prohibit their use for new MSI/RPM packages.

- [ ] **Step 5: Run tests and build-analysis checks**

```powershell
python -m pytest pc_agent/tests/runtime/test_dependency_split.py -q
python -m PyInstaller --noconfirm pc_agent/pyinstaller_endpoint_core_windows.spec
```

The Linux build runs on Linux CI or the ALT build worker.

- [ ] **Step 6: Commit**

```powershell
git add requirements pc_agent/*.spec pc_agent/tests/runtime docs
git commit -m "build: split headless agent dependencies and artifacts"
```

---

## Task 4: Introduce a transport abstraction

**Files:**
- Create: `pc_agent/transport/__init__.py`
- Create: `pc_agent/transport/base.py`
- Create: `pc_agent/transport/protocol.py`
- Create: `pc_agent/transport/http_pull.py`
- Create: `pc_agent/transport/backoff.py`
- Modify: `pc_agent/endpoint_gateway.py`
- Create: `pc_agent/tests/transport/test_transport_contract.py`
- Create: `pc_agent/tests/transport/test_http_pull_adapter.py`

**Interfaces:**

```python
class GatewayTransport(Protocol):
    async def connect(self, hello: AgentHelloV1) -> GatewayHelloV1: ...
    async def receive(self) -> GatewayInboundV1: ...
    async def send_ack(self, ack: AgentCommandAckV1) -> None: ...
    async def send_result(self, result: AgentResultV1) -> None: ...
    async def send_heartbeat(self, heartbeat: AgentHeartbeatV1) -> None: ...
    async def close(self) -> None: ...
```

- [ ] **Step 1: Write contract tests with a fake transport**

Run the same runtime lifecycle tests against an in-memory fake.

- [ ] **Step 2: Wrap current HTTPS pull**

`HttpPullGatewayTransport` implements the interface without changing accepted server behavior.

- [ ] **Step 3: Remove direct HTTP calls from the runtime application**

Only transport classes know HTTP/WSS routes.

- [ ] **Step 4: Implement explicit transport selection**

Allowed values:

```text
gateway_http_pull
gateway_wss
```

Unknown values fail startup validation.

No legacy Helpdesk option is allowed in new deployment configuration.

- [ ] **Step 5: Run tests**

```powershell
python -m pytest pc_agent/tests/transport pc_agent/tests/runtime -q
```

- [ ] **Step 6: Commit**

```powershell
git add pc_agent/transport pc_agent/endpoint_gateway.py pc_agent/runtime pc_agent/tests
git commit -m "refactor: isolate endpoint gateway transport"
```

---
