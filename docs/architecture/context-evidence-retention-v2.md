# Context and Evidence Retention v2

## Storage boundaries

`ContextCurrent` is the authoritative device/profile pointer. `updated_at` records
the last state transition; `last_observed_at` records the latest successful
server-validated observation, including deduplicated polls. A current snapshot
survives hot-history cleanup and remains available when stale.

`health_v1` produces a sample on every successful poll. `session_v1` and
`network_v1` use semantic hashes of normalized state, excluding transport time,
warnings and ordering. `baseline_v1` and `inventory_v1` retain their canonical
deduplication. The fixed collection schedule remains 24 hours, 5 minutes,
15 minutes, 24 hours and 5 minutes respectively; diagnostic remains manual.

`DeviceEvent` is a compact durable change fact with a unique device/source key.
It has no snapshot FK. Events contain fixed codes and an empty or bounded safe
metadata object, never raw Agent payload or long-term network address lists.
Existing `ContextDiff` is still the short-lived link between retained snapshots.

`OperationEvidence` holds only validated server safe projections. A digest and
operation lifecycle remain after the 24-hour payload scrub. A row-locked pin
before expiry clears `expires_at`, retains the safe payload and appends one
administrative audit event. Pin after scrub or expiry returns a conflict.
Module step result copies also expire; their capability, status, error code and
timing remain. Diagnostic operations are read from evidence when present and
return `result_available=false` after expiry.

Raw collection and snapshot transport JSON expires after one hour. The worker
runs separate bounded transactions for raw scrub, snapshot cleanup, scheduler
collection bookkeeping cleanup, evidence scrub and module step scrub. The four
payload/bookkeeping jobs run every minute (up to 100 rows per table per cycle),
while snapshot cleanup runs hourly. Each
service returns processed row counts for testing and operational measurement.

`SecurityEvent` is deliberately deferred. There is no approved sensor producer
or retention policy to validate a storage schema against. Future DLP is a
continuous Agent capability and policy subsystem with its own metadata-only
event retention, separate from Context, Module Operations and Audit. Module
recipes remain on-demand typed operations. No DLP collection, generic plugin
loader, arbitrary command channel or Agent protocol change is introduced here.

## Capacity expectation

For 120 devices, scheduled baseline/inventory once daily, health/session every
5 minutes and network every 15 minutes yield about 80,880 collection attempts
per day before deduplication. The main hot window holds at most about 34,560
health samples plus changed session/network snapshots. Unchanged session and
network states create no new snapshots. Completed scheduler collection records
with no retained snapshot are removed after 24 hours. DeviceEvent volume follows
meaningful changes, not poll frequency. These are order-of-magnitude counts;
measure actual row and byte growth after rollout.

## Production runbook

1. Record source release SHA, current Alembic revision, disk free space, API,
   worker and PostgreSQL health. Take a custom-format `pg_dump` backup of the
   production database outside the release directory; verify it with
   `pg_restore --list` and record path, size and SHA-256.
2. Measure candidates before cleanup, using read-only counts with UTC cutoffs:

   ```sql
   SELECT count(*) FROM context_collections WHERE raw_result_payload IS NOT NULL AND result_received_at < now() - interval '1 hour';
   SELECT count(*) FROM context_snapshots s JOIN context_collections c ON c.id=s.collection_id WHERE s.raw_payload IS NOT NULL AND c.result_received_at < now() - interval '1 hour';
   SELECT profile, count(*) FROM context_snapshots WHERE collected_at < now() - interval '24 hours' GROUP BY profile;
   SELECT count(*) FROM operation_evidence WHERE safe_payload IS NOT NULL AND expires_at < now();
   SELECT count(*) FROM endpoint_operation_steps WHERE safe_result_json IS NOT NULL AND completed_at < now() - interval '24 hours';
   ```

3. Deploy the verified server release and apply `0026_context_evidence_v2`.
   Apply `0027_context_observed_backfill` to recover the last completed
   observation for existing semantically deduplicated profiles.
   Start API and worker. Cleanup services process at most 100 rows per class
   per worker cycle and commit separately. Do not run a bulk delete.
4. Record rows before, scrubbed/deleted and after for each class. Confirm
   current pointers, Console Context/history/events, operation detail/pin,
   Module detail, Audit and service API reads through strict HTTPS.
5. Confirm worker is healthy, WSS is connected, real Context collection and
   Module operation succeed with existing Windows Agent `3.2.65`. Record the
   release SHA, DB revision and backup hash in `PLANS.md`.

Rollback restores the verified backup together with the previous release.
The migration is forward-only in production once payload scrub has begun;
reintroducing `NOT NULL` for raw JSON after scrub is unsafe.
