# Gateway Contracts V1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver strict, versioned V1 Python contracts, generated JSON Schema/OpenAPI artefacts, and synthetic golden fixtures for the future Endpoint Platform Gateway.

**Architecture:** `endpoint_contracts` is a Pydantic v2-only package with no server, database, filesystem, or network code. Public frozen models are the single source of truth; an explicit generator produces reviewed JSON Schema and OpenAPI files, while tests validate fixtures through both the models and committed schemas.

**Tech Stack:** Python 3.12, Pydantic 2.12+, jsonschema 4.23+, pytest.

## Global Constraints

- Scope is 6A-1 only: do not create `endpoint_server`, change `pc_agent`, start services, contact remote hosts, or deploy production infrastructure.
- Every public model uses a literal V1 `schema_version`, `extra="forbid"`, and `frozen=True`.
- Use UUIDs for durable identifiers and timezone-aware UTC timestamps for protocol times.
- Bound text, collection, and JSON-value sizes; reject unknown fields and executable command fields.
- `AgentCommandV1` carries a capability and JSON-compatible parameters only; it must never model arbitrary shell, Python, PowerShell, RouterOS, or Scheme execution.
- Golden fixtures are synthetic and contain no credential, token, secret, production device data, or absolute host path.
- Generated schemas and OpenAPI are committed and must match regenerated output exactly.

## File structure

| Path | Responsibility |
| --- | --- |
| `endpoint_contracts/__init__.py` | Re-exports the public V1 contract surface. |
| `endpoint_contracts/base.py` | Shared frozen/strict model base and validators. |
| `endpoint_contracts/identity.py` | `DeviceIdentityV1` and `AgentSessionV1`. |
| `endpoint_contracts/enrollment.py` | `EnrollmentRequestV1` and non-secret `EnrollmentResponseV1`. |
| `endpoint_contracts/commands.py` | Command, correlation, acknowledgement, and result contracts. |
| `endpoint_contracts/telemetry.py` | Heartbeat and build-recommendation contracts. |
| `tools/contracts/generate_contract_artifacts.py` | Deterministically renders JSON Schema and OpenAPI. |
| `contracts/jsonschema/*.json` | One committed JSON Schema per public V1 model. |
| `contracts/openapi/endpoint-platform-v1.yaml` | Generated OpenAPI 3.1 component document. |
| `tests/contracts/*.py` | Model, schema, generator, and fixture tests. |
| `tests/fixtures/contracts/*.json` | Synthetic valid payloads. |

## Task 1: Add strict identity and enrollment contracts

**Files:**

- Create: `endpoint_contracts/__init__.py`
- Create: `endpoint_contracts/base.py`
- Create: `endpoint_contracts/identity.py`
- Create: `endpoint_contracts/enrollment.py`
- Create: `tests/contracts/test_contract_models.py`
- Modify: `requirements-ci.txt`

**Interfaces:**

- Produces `DeviceIdentityV1`, `AgentSessionV1`, `EnrollmentRequestV1`, and `EnrollmentResponseV1`.
- Each model supports Pydantic v2 `model_validate(payload)` and `model_dump(mode="json")`.
- `EnrollmentResponseV1` contains only `device_id`, `policy_id`, `enrollment_receipt`, and `issued_at`; it never carries a raw device token.

- [ ] **Step 1: Write failing identity and enrolment tests**

```python
import pytest
from pydantic import ValidationError

from endpoint_contracts import DeviceIdentityV1, EnrollmentRequestV1


def test_device_identity_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError, match="extra_forbidden"):
        DeviceIdentityV1.model_validate({
            "schema_version": "device_identity_v1",
            "device_id": "11111111-1111-4111-8111-111111111111",
            "platform": "linux",
            "hardware_fingerprint": "sha256:fixture",
            "shell": "rm -rf /",
        })


def test_enrolment_request_requires_aware_timestamp() -> None:
    with pytest.raises(ValidationError):
        EnrollmentRequestV1.model_validate({
            "schema_version": "enrollment_request_v1",
            "platform": "linux",
            "hardware_fingerprint": "sha256:fixture",
            "installation_id": "install-fixture-01",
            "requested_at": "2026-07-28T12:00:00",
        })
```

- [ ] **Step 2: Run focused tests to verify RED**

Run: `python -m pytest tests/contracts/test_contract_models.py -q`

Expected: collection fails because `endpoint_contracts` does not exist.

- [ ] **Step 3: Implement the shared strict base and four models**

```python
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class ContractModelV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class DeviceIdentityV1(ContractModelV1):
    schema_version: Literal["device_identity_v1"]
    device_id: UUID
    platform: Literal["linux", "windows"]
    hardware_fingerprint: Annotated[str, Field(min_length=8, max_length=256)]
```

Use `AwareDatetime` for every protocol timestamp. Define installation, policy,
and receipt fields as bounded strings. Re-export exactly the four models from
`endpoint_contracts/__init__.py`. Replace the bare `pydantic` CI requirement
with `pydantic>=2.12,<3`.

- [ ] **Step 4: Run focused tests to verify GREEN**

Run: `python -m pytest tests/contracts/test_contract_models.py -q`

Expected: PASS; tests prove strict unknown-field handling and naive timestamp rejection.

- [ ] **Step 5: Commit the identity boundary**

```bash
git add endpoint_contracts requirements-ci.txt tests/contracts/test_contract_models.py
git commit -m "feat: add gateway identity contracts"
```

## Task 2: Add command, result, heartbeat, and update contracts

**Files:**

- Create: `endpoint_contracts/commands.py`
- Create: `endpoint_contracts/telemetry.py`
- Modify: `endpoint_contracts/__init__.py`
- Modify: `tests/contracts/test_contract_models.py`

**Interfaces:**

- Produces `AgentCommandV1`, `CommandCorrelationV1`, `AgentCommandAckV1`, `AgentResultV1`, `AgentHeartbeatV1`, and `AgentBuildRecommendationV1`.
- `AgentCommandV1` accepts only JSON-compatible `parameters`, validates `deadline_at > created_at`, and includes a bounded idempotency key.
- Command states are `queued`, `delivered`, `acknowledged`, `running`, `succeeded`, `failed`, `canceled`, and `expired`.

- [ ] **Step 1: Write failing lifecycle and bounds tests**

```python
import pytest
from pydantic import ValidationError

from endpoint_contracts import AgentCommandV1


def test_command_rejects_deadline_not_after_creation() -> None:
    with pytest.raises(ValidationError):
        AgentCommandV1.model_validate({
            "schema_version": "agent_command_v1",
            "command_id": "22222222-2222-4222-8222-222222222222",
            "device_id": "11111111-1111-4111-8111-111111111111",
            "capability": "agent.status.read",
            "parameters": {},
            "requested_by_service": "fixture-service",
            "idempotency_key": "fixture-command-01",
            "created_at": "2026-07-28T12:00:00Z",
            "deadline_at": "2026-07-28T12:00:00Z",
        })


def test_command_rejects_unknown_shell_field() -> None:
    payload = valid_agent_command()
    payload["shell"] = "rm -rf /"
    with pytest.raises(ValidationError, match="extra_forbidden"):
        AgentCommandV1.model_validate(payload)
```

Also test an invalid idempotency key, more than 32 result items, an unknown
status, a non-64-hex SHA-256, and a nested non-JSON parameter value.

- [ ] **Step 2: Run focused tests to verify RED**

Run: `python -m pytest tests/contracts/test_contract_models.py -q`

Expected: import fails because the command and telemetry models do not exist.

- [ ] **Step 3: Implement closed lifecycle and metadata models**

```python
class AgentCommandV1(ContractModelV1):
    schema_version: Literal["agent_command_v1"]
    command_id: UUID
    device_id: UUID
    capability: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_.-]{2,95}$")]
    parameters: dict[str, JsonValue] = Field(default_factory=dict, max_length=32)
    requested_by_service: Annotated[str, Field(min_length=3, max_length=96)]
    idempotency_key: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")]
    created_at: AwareDatetime
    deadline_at: AwareDatetime
    correlation: CommandCorrelationV1 = Field(default_factory=CommandCorrelationV1)
```

Use a model validator enforcing `deadline_at > created_at`. Use Literal unions
for status, platform, and archive type. Limit result items to 32 and free text
to 4096 characters. Build recommendations contain version, platform, relative
artifact path, byte size, SHA-256, minimum launcher version, channel, and
issuance time; they do not contain executable content or local host paths.

- [ ] **Step 4: Run focused tests to verify GREEN**

Run: `python -m pytest tests/contracts/test_contract_models.py -q`

Expected: PASS with malformed payloads rejected at the model boundary.

- [ ] **Step 5: Commit command and telemetry contracts**

```bash
git add endpoint_contracts tests/contracts/test_contract_models.py
git commit -m "feat: add gateway command contracts"
```

## Task 3: Generate and verify schemas, OpenAPI, and golden fixtures

**Files:**

- Create: `tools/contracts/__init__.py`
- Create: `tools/contracts/generate_contract_artifacts.py`
- Create: `contracts/jsonschema/*.json` for all nine public models
- Create: `contracts/openapi/endpoint-platform-v1.yaml`
- Create: `tests/fixtures/contracts/*.json` for all nine public models
- Create: `tests/contracts/test_contract_artifacts.py`

**Interfaces:**

- `render_artifacts(output_root: Path) -> dict[Path, str]` renders deterministically without mutation.
- `python tools/contracts/generate_contract_artifacts.py --check` exits 0 only when tracked output equals regenerated output.
- Every fixture validates through its model and `Draft202012Validator` against its committed JSON Schema.

- [ ] **Step 1: Write failing renderer and fixture tests**

```python
import json
from pathlib import Path

from jsonschema import Draft202012Validator

from endpoint_contracts import AgentCommandV1
from tools.contracts.generate_contract_artifacts import render_artifacts


def test_committed_contract_artifacts_match_renderer(tmp_path: Path) -> None:
    for relative_path, expected in render_artifacts(tmp_path).items():
        assert (Path.cwd() / relative_path).read_text(encoding="utf-8") == expected


def test_agent_command_fixture_validates_against_model_and_schema() -> None:
    fixture = json.loads(Path("tests/fixtures/contracts/agent-command-v1.json").read_text())
    schema = json.loads(Path("contracts/jsonschema/agent-command-v1.json").read_text())
    AgentCommandV1.model_validate(fixture)
    Draft202012Validator(schema).validate(fixture)
```

Parameterize the second assertion over all public fixtures. Add a fixture-text
test that rejects credential labels and Unix or Windows absolute path values.

- [ ] **Step 2: Run focused tests to verify RED**

Run: `python -m pytest tests/contracts/test_contract_artifacts.py -q`

Expected: collection fails because renderer, schemas, and fixtures are absent.

- [ ] **Step 3: Implement deterministic rendering and generate outputs**

```python
PUBLIC_MODELS = {
    "device-identity-v1.json": DeviceIdentityV1,
    "agent-session-v1.json": AgentSessionV1,
    "enrollment-request-v1.json": EnrollmentRequestV1,
    "enrollment-response-v1.json": EnrollmentResponseV1,
    "agent-command-v1.json": AgentCommandV1,
    "agent-command-ack-v1.json": AgentCommandAckV1,
    "agent-result-v1.json": AgentResultV1,
    "agent-heartbeat-v1.json": AgentHeartbeatV1,
    "agent-build-recommendation-v1.json": AgentBuildRecommendationV1,
}
```

Render `model_json_schema()` with sorted keys, two-space indent, and terminal
newline. Render an OpenAPI 3.1 document containing `info`, `openapi`, empty
`paths`, and `components.schemas` from the same models. Create fixtures with
fixed UUIDs, `2026-07-28T12:00:00Z`, and non-secret data. Invoke `--write` once
to create the reviewed files.

- [ ] **Step 4: Run acceptance checks**

Run:

```bash
python -m pytest tests/contracts -q
python tools/contracts/generate_contract_artifacts.py --check
python tools/extraction/check_retained_tree.py
python -m compileall -q endpoint_contracts tools shared
git diff --check
```

Expected: all commands exit 0 and no file under `pc_agent/` changes.

- [ ] **Step 5: Commit public artefacts**

```bash
git add endpoint_contracts tools/contracts contracts tests/contracts tests/fixtures/contracts
git commit -m "feat: publish gateway contract schemas"
```

## Plan self-review

- Spec coverage: Tasks 1–2 implement all nine V1 models and strict validation; Task 3 delivers schemas, OpenAPI, fixtures, generation checks, extraction protection, and compilation verification.
- Placeholder scan: every implementation step has a concrete test, model shape, command, or output list.
- Type consistency: public class names, file names, renderer signature, and validation commands are defined consistently across all tasks.

## Execution boundary

Completion is 6A-1 only. 6A-2, the FastAPI/PostgreSQL foundation, is a separate plan and must not be folded into these commits.
