# Endpoint Context & Evidence Retention v2 Implementation Plan

**Goal:** Preserve current state, a bounded hot history, durable compact changes, and explicitly pinned safe operation results without indefinite raw JSON growth.

**Baseline:** `0aa22537d93e29e79eb43dce01e8e1e50ee23a6f`, `0025_console_enrollment_queue`, Agent `3.2.65`.

**Architecture:** Extend current pointers with observation time. Deduplicate state profiles at validated ingestion, emit standalone compact events in the same transaction, and run independent bounded retention jobs. Store safe terminal operation results in a separate evidence row with a 24-hour expiry and transactional pin.

## Repository findings

- `ContextSnapshot.raw_payload` and `ContextCollection.raw_result_payload` are written at ingestion and have no production readers. Both can be scrubbed after one hour.
- `_record_module_step_result` in `gateway/command_service.py` creates the validated step result and advances the parent to terminal. The same transaction is the evidence creation point.
- Diagnostic operations are linked by `EndpointOperation.context_collection_id`; `operations/routes.py::_response_data` currently reads a diagnostic `ContextSnapshot` and raises 503 when it is missing. Evidence must become the read source.
- Console `/devices/{id}/changes` compares retained baseline/inventory snapshot pairs, so its long-term view must switch to DeviceEvent. The existing service comparison route can keep short snapshot comparisons.
- `ContextCurrent.snapshot_id` references a snapshot with a composite FK and `ON DELETE CASCADE`; retention must explicitly exclude current and serialize with ingestion. `ContextDiff` and `ContextFinding` cascade on snapshot deletion. DeviceEvent references Device only.
- DeviceEvent source identity uses the resulting snapshot ID plus change code, unique per device. Replays are already keyed by command result, and state transitions with identical hashes at different times remain distinct.
- SecurityEvent schema is deferred: there is no sensor producer or policy contract. Document a separate continuous policy/sensor boundary without speculative storage or Agent route.

## Tasks

- [ ] Add a single typed retention registry and forward migration for `last_observed_at`, nullable raw snapshot JSON, DeviceEvent, OperationEvidence, and cleanup indexes. Verify metadata and migration on PostgreSQL.
- [ ] Add session/network canonical semantic hashes, advance observation freshness on all successful collections, preserve health samples, and test ordering, actual changes, replay and concurrent pointer behavior.
- [ ] Emit bounded independent DeviceEvents for baseline/inventory diffs and session/network changes; test idempotency and survival after snapshot cleanup.
- [ ] Replace broad snapshot loading with index-backed bounded profile-aware cleanup; add separate raw scrub, result scrub and worker job transactions with tested counts.
- [ ] Materialize safe operation evidence at terminal Module and diagnostic results. Make projections tolerant of expired results, implement row-locked pin and audited Console action, and test cleanup races.
- [ ] Add typed paginated Device Events and Context history Console routes. Update Russian Device and Operation UI for freshness, history, evidence expiry, pin and scrub states; test relevant browser flows.
- [ ] Document storage estimate, security boundary, deployment counts and rollback. Run focused tests, full pytest, contract generation, compileall, frontend tests/build and Playwright.
- [ ] At production gate, verify disk, take and verify PostgreSQL backup, record DB revision and dry counts, deploy additive migration, run bounded cleanup, then verify service, worker, Context, events, operation evidence and live Agent `3.2.65`.

## Review focus

- A delayed successful result must not make freshness or current state go backwards.
- A pin racing cleanup must either preserve payload or return a conflict.
- Retention must never delete the current snapshot, including retired devices.
- Raw scrub must leave normalized current and service projections readable.
- A scrubbed successful operation must return lifecycle metadata without a 503.
