# Update Rollout Control Plane Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver an audited, PostgreSQL-safe Endpoint Platform control plane for immutable builds, canary/bulk/rollback rollout targets, and device update recommendations/reports.

**Architecture:** Extend the existing ownership-only update tables in one forward migration.  A focused update service owns validation, lifecycle transitions and locks; small authenticated admin and agent route modules translate strict contracts to that service.  Rollback is a new rollout to an existing immutable build, never a mutation of a prior build or rollout.

**Tech Stack:** FastAPI, Pydantic v2, SQLAlchemy async, Alembic, PostgreSQL, existing HMAC device credentials, admin sessions and immutable audit.

## Global Constraints

- Do not modify `pc_agent`, its launcher, release version, release builders, WebSocket transport, UI, Helpdesk or remote hosts.
- Artifacts already exist at HTTPS URLs; do not upload, proxy, download or persist binary data.
- Raw device tokens, HTTP authorization values, update archive paths, pending-update payloads, stack traces and logs must never persist or enter audits.
- Builds are immutable; a rollback is a newly created compatible rollout to an older build.
- `scheduled` is not success; only explicit future `applied` reports represent post-restart handshake success.
- Every state mutation writes a redacted immutable audit event in its transaction.
- Test all concurrency/migration claims against disposable PostgreSQL during acceptance.

---

### Task 1: Strict update control-plane contracts and generated artifacts

**Files:**
- Modify: `endpoint_contracts/__init__.py`
- Create: `endpoint_contracts/updates.py`
- Modify: `tools/contracts/generate_contract_artifacts.py`
- Generate: `contracts/jsonschema/update-build-manifest-v1.json`
- Generate: `contracts/jsonschema/update-rollout-v1.json`
- Generate: `contracts/jsonschema/agent-update-recommendation-v1.json`
- Generate: `contracts/jsonschema/agent-update-ack-v1.json`
- Generate: `contracts/jsonschema/agent-update-report-v1.json`
- Modify: `contracts/openapi/endpoint-platform-v1.yaml`
- Test: `tests/contracts/test_contract_models.py`
- Test: `tests/contracts/test_contract_artifacts.py`

**Interfaces:**
- Produces `UpdateBuildManifestV1`, `UpdateRolloutCreateV1`, `AgentUpdateRecommendationV1`, `AgentUpdateAcknowledgementV1`, and `AgentUpdateReportV1`.
- `UpdateBuildManifestV1` fields: `build_identifier`, `version`, `platform`, `channel`, `artifact_url`, `artifact_name`, `archive_type`, `sha256`, `size`, optional `release_notes`.
- `AgentUpdateReportV1` fields: `schema_version`, `report_key`, `status`, `reported_version`, optional bounded `safe_code` and `safe_message`; it excludes opaque diagnostics.

- [ ] **Step 1: Write failing strict-model tests.**

```python
def test_update_build_manifest_rejects_non_https_and_bad_digest() -> None:
    with pytest.raises(ValidationError):
        UpdateBuildManifestV1.model_validate({**VALID_BUILD, "artifact_url": "http://bad"})
    with pytest.raises(ValidationError):
        UpdateBuildManifestV1.model_validate({**VALID_BUILD, "sha256": "ABC"})

def test_agent_update_report_excludes_raw_diagnostics() -> None:
    with pytest.raises(ValidationError):
        AgentUpdateReportV1.model_validate({**VALID_REPORT, "traceback": "secret"})
```

- [ ] **Step 2: Run the new tests and confirm imports/models are absent.**

Run: `python -m pytest tests/contracts/test_contract_models.py -q`

Expected: FAIL because the update V1 models do not exist.

- [ ] **Step 3: Implement strict models and generator registration.**

```python
class UpdateBuildManifestV1(StrictContractModel):
    schema_version: Literal["update_build_manifest_v1"]
    artifact_url: AnyUrl
    sha256: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
    size: Annotated[int, Field(gt=0)]
```

Use literal constrained platform/channel/archive/status fields.  Require HTTPS
in a model validator, forbid extras, bound every identifier/message and export
the models through `endpoint_contracts.__init__` and artifact generation.

- [ ] **Step 4: Generate artifacts and prove model/OpenAPI alignment.**

Run: `python tools/contracts/generate_contract_artifacts.py --check; python -m pytest tests/contracts/test_contract_models.py tests/contracts/test_contract_artifacts.py -q`

Expected: PASS; generated schemas contain strict required fields and no raw
diagnostic field.

- [ ] **Step 5: Commit.**

```bash
git add endpoint_contracts tools/contracts contracts tests/contracts
git commit -m "feat: add update control plane contracts"
```

### Task 2: Update persistence migration and safe data model

**Files:**
- Modify: `endpoint_server/db/models/updates.py`
- Modify: `endpoint_server/db/models/__init__.py`
- Create: `endpoint_server/db/migrations/versions/0006_update_control_plane.py`
- Test: `tests/server/test_migrations.py`
- Test: `tests/server/test_update_postgresql.py`

**Interfaces:**
- Produces `UpdateBuild`, `UpdateRollout`, `UpdateTarget`, `UpdateReport` fields used by Task 3.
- `UpdateTarget.operation_id: str`, `status: str`, `assigned_at`, `requested_at`, `scheduled_at`, `terminal_at`, `safe_reason`.
- `UpdateReport.report_key: str` has unique `(update_target_id, report_key)` identity.

- [ ] **Step 1: Write migration/model RED tests.**

```python
def test_update_models_require_immutable_manifest_and_target_operation() -> None:
    assert UpdateBuild.__table__.c.artifact_url.nullable is False
    assert UpdateTarget.__table__.c.operation_id.nullable is False

def test_0006_downgrade_disables_active_targets(postgres_url: str) -> None:
    # Populate active rollout/target, downgrade, then assert legacy state cannot
    # remain an actionable assignment after re-upgrade.
    ...
```

- [ ] **Step 2: Run focused tests and confirm the new columns/revision are absent.**

Run: `python -m pytest tests/server/test_migrations.py tests/server/test_update_postgresql.py -q`

Expected: FAIL until revision `0006_update_control_plane` exists.

- [ ] **Step 3: Add fields, constraints and forward/downgrade revision.**

Add manifest URL/name/archive/channel, rollout mode/reason/lifecycle times,
target operation/timestamps/reason, report key/safe detail.  Add unique
manifest identity and report-key constraints; add an index for active target
lookup.  In downgrade cancel active rollouts/targets before dropping fields;
do not delete historic builds/reports that legacy ownership tables represent.

- [ ] **Step 4: Verify migration shape and populated PostgreSQL history.**

Run: `python -m alembic upgrade head --sql; python -m alembic downgrade 0005_enrollment_campaigns --sql; python -m pytest tests/server/test_migrations.py tests/server/test_update_postgresql.py -q`

Expected: PASS locally except explicitly opt-in PostgreSQL tests without a URL.

- [ ] **Step 5: Commit.**

```bash
git add endpoint_server/db tests/server
git commit -m "server: persist update rollout control state"
```

### Task 3: Immutable build and rollout domain service

**Files:**
- Create: `endpoint_server/updates/__init__.py`
- Create: `endpoint_server/updates/service.py`
- Create: `endpoint_server/updates/errors.py`
- Test: `tests/server/test_update_service.py`
- Test: `tests/server/test_update_postgresql.py`

**Interfaces:**
- Produces async `register_build(session, manifest, actor, request_id)`, `create_rollout(session, build_id, mode, device_ids, reason, actor, request_id)`, `activate_rollout(...)`, `complete_rollout(...)`, and `create_rollback_rollout(...)`.
- Produces `recommendation_for_device(session, device_id, platform, now)` and `record_ack(...)` / `record_report(...)` for Task 4.

- [ ] **Step 1: Write RED service tests.**

```python
async def test_conflicting_manifest_cannot_replace_existing_build(session):
    await register_build(session, VALID_MANIFEST, ADMIN, "req-a")
    with pytest.raises(UpdateConflict):
        await register_build(session, {**VALID_MANIFEST, "sha256": OTHER}, ADMIN, "req-b")

async def test_bulk_requires_completed_canary_for_same_build(session):
    with pytest.raises(UpdateStateError):
        await create_rollout(session, build_id, "bulk", [device_id], "release", ADMIN, "req")
```

- [ ] **Step 2: Run RED tests.**

Run: `python -m pytest tests/server/test_update_service.py -q`

Expected: FAIL because the update service is absent.

- [ ] **Step 3: Implement domain transitions with atomic audit.**

Use bounded string validation from contracts.  Lock build/rollout/target rows
with `FOR UPDATE`; create an opaque UUID operation id per target; reject a
second active assignment.  A bulk rollout must reference a completed canary
for the same build.  A rollback must point to a compatible build different
from the triggering rollout's build and retain the trigger identifier in its
safe reason.  Append `updates.build_registered`, `updates.rollout_*`, and
`updates.target_assigned` audit events before commit.

- [ ] **Step 4: Add real PostgreSQL race coverage.**

```python
async def test_concurrent_active_assignments_leave_one_target(postgres_url):
    outcomes = await asyncio.gather(assign_first(), assign_second(), return_exceptions=True)
    assert sum(isinstance(item, UpdateTarget) for item in outcomes) == 1
```

Run: `python -m pytest tests/server/test_update_service.py tests/server/test_update_postgresql.py -q`

Expected: PASS with database URL; race proves one active target only.

- [ ] **Step 5: Commit.**

```bash
git add endpoint_server/updates tests/server
git commit -m "feat: add immutable update rollout service"
```

### Task 4: Authenticated admin and device update APIs

**Files:**
- Modify: `endpoint_server/db/models/administration.py`
- Modify: `endpoint_server/auth/admin_sessions.py`
- Modify: `endpoint_server/auth/bootstrap_admin.py`
- Create: `endpoint_server/db/migrations/versions/0007_admin_update_scopes.py`
- Create: `endpoint_server/updates/admin_routes.py`
- Create: `endpoint_server/updates/agent_routes.py`
- Modify: `endpoint_server/main.py`
- Test: `tests/server/test_update_admin_api.py`
- Test: `tests/server/test_update_agent_api.py`
- Test: `tests/server/test_audit.py`

**Interfaces:**
- Admin API: create build; create/activate/pause/complete rollout; create rollback rollout.
- Agent API: `GET /agent/v1/updates/recommendation`, `POST /agent/v1/updates/{operation_id}/ack`, `POST /agent/v1/updates/{operation_id}/reports`.
- Agent routes consume Task 1 strict models and Task 3 service functions.
- `require_admin_update_scope(request) -> AdminPrincipal` loads the interactive
  session principal and requires persisted `updates:write`; no request header
  grants a scope.  The 0007 migration adds normalized `AdminUser.scopes` and
  backfills the explicit `updates:write` grant for existing administrators.

- [ ] **Step 1: Write RED API/security tests.**

```python
async def test_agent_cannot_read_another_devices_recommendation(client, device_a, device_b):
    response = await client.get("/agent/v1/updates/recommendation", headers=device_a.headers)
    assert response.json()["operation_id"] == device_a.target_operation
    assert device_b.target_operation not in response.text

async def test_report_key_is_idempotent_but_payload_conflict_fails(client, device):
    assert (await client.post(device.report_url, json=REPORT)).status_code == 200
    assert (await client.post(device.report_url, json={**REPORT, "status": "failed"})).status_code == 409

async def test_admin_update_scope_is_persisted_not_header_granted(client, admin):
    assert (await client.post("/api/admin/updates/builds", headers=admin.headers)).status_code == 403
    assert (await client.post("/api/admin/updates/builds", headers={**admin.headers, "X-Scope": "updates:write"})).status_code == 403
```

- [ ] **Step 2: Run targeted tests and confirm routes are absent.**

Run: `python -m pytest tests/server/test_update_admin_api.py tests/server/test_update_agent_api.py -q`

Expected: FAIL with missing routes.

- [ ] **Step 3: Implement admin and agent route boundaries.**

Add `AdminUser.scopes` as a normalized persisted collection in revision 0007;
backfill and bootstrap the explicit `updates:write` grant, and add
`require_admin_update_scope` around the existing interactive-session and CSRF
checks.  Require that dependency for every admin mutation.  Resolve the
device from its bearer credential, not request data.  Return a generic no
assignment response for no target, foreign platform/channel and inactive
rollout.  Map domain errors to non-enumerating status codes.  Use an HMAC-safe
request correlation ID; redact every request-derived audit detail.

- [ ] **Step 4: Verify audit atomicity and secret redaction.**

Run: `python -m pytest tests/server/test_update_admin_api.py tests/server/test_update_agent_api.py tests/server/test_audit.py -q`

Expected: PASS; an injected bearer/archive path/trace marker occurs in neither
audit payload/request id nor HTTP error response.

- [ ] **Step 5: Commit.**

```bash
git add endpoint_server/main.py endpoint_server/updates tests/server
git commit -m "feat: expose update rollout control APIs"
```

### Task 5: Acceptance, documents and isolated PostgreSQL verification

**Files:**
- Modify: `docs/AGENT_CAPABILITIES_AND_REQUIREMENTS.md` only if it lists an update API surface changed by this work.
- Test: `tests/contracts/test_contract_artifacts.py`
- Test: `tests/extraction/test_retained_tree.py`
- Test: all `tests/server/test_update_*.py`

- [ ] **Step 1: Run focused control-plane verification.**

Run: `python -m pytest tests/contracts/test_contract_models.py tests/contracts/test_contract_artifacts.py tests/server/test_update_service.py tests/server/test_update_admin_api.py tests/server/test_update_agent_api.py tests/server/test_update_postgresql.py -q`

Expected: all non-opt-in tests pass.

- [ ] **Step 2: Run full static and standalone gates.**

Run: `python -m pytest tests -q; python -m ruff format --check $(git diff --name-only HEAD~4..HEAD -- '*.py'); python -m ruff check endpoint_server endpoint_contracts tests/server tests/contracts; python -m compileall -q endpoint_server endpoint_contracts; git diff --check; git diff --name-only HEAD~4..HEAD -- pc_agent`

Expected: standalone suite passes; no `pc_agent` path is changed.

- [ ] **Step 3: Run disposable PostgreSQL acceptance.**

Start a loopback-only disposable PostgreSQL cluster, set
`ENDPOINT_TEST_POSTGRES_URL`, and run the normal-order migration/concurrency
suite plus the complete `tests` tree.  Drop test databases, stop PostgreSQL
and remove its temporary root afterwards.

Expected: populated 0005→0006→0005 migrations, concurrent target/report and
rollback behavior all pass without skipped PostgreSQL cases.

- [ ] **Step 4: Regenerate/check public artifacts and retained tree.**

Run: `python tools/contracts/generate_contract_artifacts.py --check; python -m pytest tests/extraction/test_retained_tree.py -q; python -m alembic upgrade head --sql; python -m alembic downgrade 0005_enrollment_campaigns --sql`

Expected: generated artifacts are current; no Helpdesk/server import enters
the retained tree.

- [ ] **Step 5: Commit only required documentation.**

```bash
git add docs/AGENT_CAPABILITIES_AND_REQUIREMENTS.md
git commit -m "docs: record update rollout control plane"
```

Skip this commit when no documentation file changed.
