# Device Context Foundation Implementation Plan

> For agentic workers: REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Deliver strict bounded ALT Device Context profiles, server semantic snapshots and a safe API, without web_ovpn modification, deployment or real collection.

**Architecture:** Existing AgentCommandV1 and AgentResultV1 remain the only transport. A fixed agent capability maps to a typed profile envelope; endpoint_server/context exclusively owns lifecycle, snapshots, diffs, scheduling and safe projections in additive PostgreSQL tables.

**Tech Stack:** Python 3, Pydantic v2, SQLAlchemy 2 async, Alembic, PostgreSQL, pytest.

## Global Constraints

- ALT Linux is first. No release artifact, remote migration, device collection, web_ovpn change, deployment or canary is part of this plan.
- Reuse inventory code; no caller may select a module, method, shell command or arbitrary probe.
- Profiles are strict, bounded and read-only. Diagnostics are manual-only and never appear in safe service output.
- Baseline hash excludes timestamps, uptime, load, free space, primary IP, processes and warnings; server recomputes it.
- Duplicate command results cannot create another collection or snapshot.
- Scheduler: baseline 24h, health 5m, network 15m; diagnostic manual only; one active collection per device/profile.
- Safe output excludes credentials, raw AgentResultV1, artifact URLs, raw diagnostics, paths and tracebacks.

---

## File Structure

- endpoint_contracts/context.py: strict envelopes and diff contract.
- pc_agent/context_profiles/: bounded probe/profile collectors and fixed registry.
- endpoint_server/context/: persistence, ingestion, hash/diff, retention, scheduler and routes.
- migration 0008: additive Context ownership tables.
- tests/contracts, pc_agent/tests/context and tests/context: strict, agent and PostgreSQL evidence.

### Task 1: Strict Device Context contracts

**Files:**

- Create: endpoint_contracts/context.py
- Modify: endpoint_contracts/__init__.py
- Create: contracts/jsonschema/device_context_{baseline,health,network,diagnostic,diff}_v1.json
- Create: tests/contracts/test_context_contracts.py
- Create: tests/fixtures/context/{alt,windows}/baseline_v1.json

**Interfaces:**

- ContextProfileV1 is baseline_v1, health_v1, network_v1 or diagnostic_v1.
- DeviceContextEnvelopeV1 has schema_version, profile, collected_at, sections and warnings.
- validate_context_result_item(value) returns DeviceContextEnvelopeV1.

- [ ] **Step 1: Write failing strict tests**

~~~python
def test_context_rejects_unknown_or_volatile_fields():
    with pytest.raises(ValidationError):
        DeviceContextEnvelopeV1.model_validate({**baseline_fixture(), "uptime": 10})

def test_context_result_requires_known_profile():
    with pytest.raises(ValidationError):
        validate_context_result_item({"schema_version": "device_context_v1", "profile": "arbitrary"})
~~~

- [ ] **Step 2: Verify RED**

Run: python -m pytest tests/contracts/test_context_contracts.py -q

Expected: context contract import fails before implementation.

- [ ] **Step 3: Implement strict bounded models**

Use Pydantic v2 extra forbid, profile discriminators, bounded strings/lists and stable warning codes. Do not accept device identity inside payload: command transport binds it. Generate committed schemas and anonymized ALT/Windows fixtures.

- [ ] **Step 4: Verify and commit**

Run: python -m pytest tests/contracts/test_context_contracts.py -q; python tools/contracts/generate_contract_artifacts.py --check

~~~powershell
git add endpoint_contracts contracts/jsonschema tests/contracts tests/fixtures/context
git commit -m "feat: add device context contracts"
~~~

### Task 2: Probe boundary and collector profiles

**Files:**

- Create: pc_agent/context_profiles/{probe,stable_keys,baseline,health,network,diagnostic,registry}.py
- Create: pc_agent/tests/context/test_{alt_baseline,privacy,health,network,diagnostic_limits}.py
- Modify: pc_agent/modules/impl/inventory.py

**Interfaces:**

- SystemProbe exposes bounded read_text(path, max_bytes) and run(argv, timeout_seconds, max_bytes).
- collect_baseline, collect_health, collect_network and collect_diagnostic each return DeviceContextEnvelopeV1.
- execute_context_capability(capability, parameters, probe) returns one typed envelope.

- [ ] **Step 1: Write failing collector tests**

~~~python
def test_network_uses_default_route_not_public_connect(fake_probe):
    assert collect_network(fake_probe, collected_at=FIXED_TIME).sections.default_route.interface == "eth0"
    assert fake_probe.network_connect_calls == []

def test_diagnostic_is_bounded(fake_probe):
    result = collect_diagnostic(fake_probe, collected_at=FIXED_TIME)
    assert len(result.sections.processes) <= DIAGNOSTIC_PROCESS_LIMIT
    assert len(result.sections.log_excerpt.encode()) <= DIAGNOSTIC_LOG_BYTES
~~~

- [ ] **Step 2: Verify RED**

Run: python -m pytest pc_agent/tests/context -q

Expected: collector imports fail before implementation.

- [ ] **Step 3: Implement read-only profiles**

Use fixed command allowlists and timeouts. Baseline uses WWN then serial then bounded fallback for disks and normalized MAC then fallback for interfaces. Health/network optional failures add fixed warnings. Diagnostic redacts before truncation. Preserve inventory.collect compatibility; no collector contacts a network endpoint.

- [ ] **Step 4: Verify and commit**

Run: python -m pytest pc_agent/tests/context -q

~~~powershell
git add pc_agent/context_profiles pc_agent/tests/context pc_agent/modules/impl/inventory.py
git commit -m "feat: collect bounded device context"
~~~

### Task 3: Fixed command capability integration

**Files:**

- Modify: endpoint_contracts/commands.py
- Modify: pc_agent/core/{registry,orchestrator}.py
- Create: pc_agent/tests/context/test_{capability_registry,command_execution}.py

**Interfaces:**

- Extend AgentCapabilityV1 exactly with context.baseline.collect, context.health.collect, context.network.collect, context.diagnostic.collect.
- Each successful command serializes one validated envelope into AgentResultV1.result_items.
- Diagnostic requires bounded reason; others accept only an empty object.

- [ ] **Step 1: Write failing allowlist test**

~~~python
def test_only_fixed_context_capabilities_resolve():
    assert execute_context_capability("context.baseline.collect", {}, probe=FAKE).profile == "baseline_v1"
    with pytest.raises(ContextCapabilityError):
        execute_context_capability("context.run_shell", {"argv": ["id"]}, probe=FAKE)
~~~

- [ ] **Step 2: Verify RED**

Run: python -m pytest pc_agent/tests/context/test_capability_registry.py pc_agent/tests/context/test_command_execution.py -q

- [ ] **Step 3: Implement exact mapping**

No generic dispatcher. Validate before AgentResultV1 construction; map timeout/cancellation to fixed result codes and retain existing durable duplicate-command replay.

- [ ] **Step 4: Verify and commit**

Run: python -m pytest pc_agent/tests/context/test_capability_registry.py pc_agent/tests/context/test_command_execution.py -q

~~~powershell
git add endpoint_contracts/commands.py pc_agent/core pc_agent/tests/context
git commit -m "feat: register device context capabilities"
~~~

### Task 4: PostgreSQL lifecycle and idempotent ingestion

**Files:**

- Create: endpoint_server/context/{models,repository,ingestion,service}.py
- Modify: endpoint_server/db/models/__init__.py
- Create: endpoint_server/db/migrations/versions/0008_device_context_foundation.py
- Create: tests/context/test_{collection_lifecycle,ingestion_idempotency}.py

**Interfaces:**

- Context statuses: requested, queued, delivered, collecting, result_received, validated, completed, failed, expired.
- request_collection(session, device_id, profile, requested_by, idempotency_key) returns ContextCollection.
- ingest_context_result(session, command_result_id, result) returns ContextCollection.

- [ ] **Step 1: Write failing duplicate test**

~~~python
async def test_duplicate_result_creates_one_snapshot(session):
    first = await ingest_context_result(session, command_result_id=RESULT_ID, result=baseline_result())
    second = await ingest_context_result(session, command_result_id=RESULT_ID, result=baseline_result())
    assert first.id == second.id
    assert await snapshot_count(session, first.device_id, "baseline_v1") == 1
~~~

- [ ] **Step 2: Verify RED**

Run: python -m pytest tests/context/test_collection_lifecycle.py tests/context/test_ingestion_idempotency.py -q

- [ ] **Step 3: Implement additive context ownership**

Create context_collections, context_snapshots, context_diffs, context_current and context_findings with UUID/FK, timezone timestamps and indexes for device/profile/status, result correlation and current reads. Store validated raw JSON separately from normalized projection. Lock result correlation transactionally; failure never replaces current. Do not run Alembic remotely.

- [ ] **Step 4: Verify and commit**

Run: python -m pytest tests/context/test_collection_lifecycle.py tests/context/test_ingestion_idempotency.py -q; python -m alembic -c alembic.ini upgrade head

~~~powershell
git add endpoint_server/context endpoint_server/db/models endpoint_server/db/migrations tests/context
git commit -m "feat: persist device context collections"
~~~

### Task 5: Canonical snapshots, semantic diff and safe API

**Files:**

- Create: endpoint_server/context/{canonicalize,semantic_hash,diff,projection,routes}.py
- Modify: endpoint_server/main.py
- Modify: endpoint_server/auth/scopes.py
- Create: tests/context/test_{semantic_hash,canonicalization_golden,diff,safe_projection,service_api}.py

**Interfaces:**

- canonicalize_baseline(snapshot) returns dict.
- semantic_hash(canonical) returns string.
- compare_snapshots(before, after) returns DeviceContextDiffV1.
- Safe service routes list devices, read context, request collection, read collection and compare snapshots.

- [ ] **Step 1: Write failing invariance/API tests**

~~~python
def test_hash_ignores_timestamp_ip_and_order():
    assert semantic_hash(canonicalize_baseline(sample_a())) == semantic_hash(canonicalize_baseline(sample_b()))

def test_safe_projection_has_no_raw_result_or_token(client, service_token):
    body = client.get(CONTEXT_URL, headers=service_token).json()["data"]
    assert "raw_payload" not in body
    assert "token" not in str(body)
~~~

- [ ] **Step 2: Verify RED**

Run: python -m pytest tests/context/test_semantic_hash.py tests/context/test_diff.py tests/context/test_safe_projection.py tests/context/test_service_api.py -q

- [ ] **Step 3: Implement deterministic semantic store and routes**

Use sorted-key JSON and stable-key list comparison. Emit only fixed change codes for platform/hardware/storage/network/software/agent changes. Store a baseline only when server hash changes. Add least-privilege scopes devices.read, context.read and context.collect; state-changing request requires audit/idempotency key. No raw payload or diagnostic enters projection.

- [ ] **Step 4: Verify and commit**

Run: python -m pytest tests/context/test_semantic_hash.py tests/context/test_canonicalization_golden.py tests/context/test_diff.py tests/context/test_safe_projection.py tests/context/test_service_api.py -q

~~~powershell
git add endpoint_server/context endpoint_server/main.py endpoint_server/auth/scopes.py tests/context
git commit -m "feat: expose device context service API"
~~~

### Task 6: Scheduler, retention and acceptance documentation

**Files:**

- Create: endpoint_server/context/{scheduler,retention}.py
- Modify: endpoint_server/worker.py
- Create: tests/context/test_{scheduler,retention}.py
- Modify: PLANS.md
- Modify: pc_agent/docs/CODEMAP.md
- Create: docs/runbooks/DEVICE_CONTEXT_FOUNDATION.md

- [ ] **Step 1: Write failing scheduling test**

~~~python
async def test_scheduler_creates_one_active_baseline(session):
    assert await schedule_due_collections(session, now=NOW) == 1
    assert await schedule_due_collections(session, now=NOW) == 0
~~~

- [ ] **Step 2: Verify RED**

Run: python -m pytest tests/context/test_scheduler.py tests/context/test_retention.py -q

- [ ] **Step 3: Implement bounded jobs**

Use transaction locking/active lookup so concurrent ticks do not duplicate work. Schedule baseline 24h, health 5m, network 15m; exclude diagnostic. Retention keeps current, previous and pinned snapshots. Worker failures roll back and continue.

- [ ] **Step 4: Run acceptance and commit**

Run: python -m pytest tests/contracts/test_context_contracts.py pc_agent/tests/context tests/context -q; python -m pytest tests -q; python tools/contracts/generate_contract_artifacts.py --check; git diff --check

Document profile/interval/capability/scope rules and that web_ovpn, remote migration, deployment and ALT pilot remain separately authorized.

~~~powershell
git add endpoint_server/context endpoint_server/worker.py tests/context PLANS.md pc_agent/docs/CODEMAP.md docs/runbooks
git commit -m "docs: verify device context foundation"
~~~

