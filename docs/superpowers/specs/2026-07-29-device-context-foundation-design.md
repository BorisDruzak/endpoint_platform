# Device Context Foundation Design

## Decision

Wave 1 starts with the Endpoint Platform foundation, then adds a typed service
client and read-only adapter in a clean `web_ovpn` worktree.  `web_ovpn` never
receives an agent command result or device credential.  Its existing Network
Context remains a separate source of raw network observations; correlation is
an explicit later projection, never an IP-based merge.

## Scope and delivery order

This design preserves the complete Wave 1 objective while making its delivery
testable:

1. strict Device Context envelopes and generated schemas;
2. bounded, read-only ALT collector profiles plus Gateway capability allowlist;
3. server collection lifecycle, immutable snapshots, canonicalization,
   semantic hash, diff, retention and safe read/request APIs;
4. typed Python service SDK and a clean `web_ovpn` adapter/UI worktree;
5. explicit netctl correlation and the separately authorized ALT pilot.

The current delivery implements items 1--3 only.  It creates no `web_ovpn`
change, release artifact, deployment, collector configuration, network-device
action or canary.

## Contracts

`endpoint_contracts/context.py` owns four strict Pydantic v2 envelopes:

- `baseline_v1`: stable machine/platform/hardware/storage/interface and
  allowlisted software facts;
- `health_v1`: bounded, volatile health facts;
- `network_v1`: route-aware local network facts;
- `diagnostic_v1`: manual-only, redacted and byte/item-bounded facts.

Every model forbids unknown fields and carries a collection timestamp,
profile name, device-bound correlation and stable warning codes.  Schemas are
generated into `contracts/jsonschema/`.  The baseline canonical form excludes
timestamps, uptime, load, free space, primary IP, process lists and warnings;
the server recomputes its hash rather than trusting agent input.

## Agent boundary

Existing inventory code is characterized before extraction.  Small collector
modules use an injectable `SystemProbe`; they are read-only and return typed
sections plus fixed warning codes.  The registry exposes only the fixed
capabilities `context.baseline.collect`, `context.health.collect`,
`context.network.collect` and `context.diagnostic.collect`; callers cannot
select a module, method, shell command or arbitrary probe.  Diagnostic
collection is manual only; baseline, health and network are bounded scheduled
profiles.

The existing protocol result remains the transport envelope.  The agent
validates the context payload before it leaves the process and preserves normal
durable command-result replay for duplicate command IDs.

## Server boundary

The `endpoint_server/context` ownership zone consumes a completed command
result only after validating its profile contract.  It records one collection
state machine:

`requested → queued → delivered → collecting → result_received → validated → completed`

with terminal `failed` and `expired` states.  The database has separate
collections, snapshots, diffs, current pointers and findings tables.  A
duplicate result cannot create a second snapshot.  A failed collection never
replaces the current snapshot.

Canonicalization uses deterministic JSON and stable keyed comparisons.  A new
baseline snapshot is stored only when its semantic hash changes.  The safe API
returns device identity, profile availability, snapshots, normalized diffs and
bounded warnings; it never returns a bearer, raw diagnostic secret, raw agent
result or artifact URL.

The scheduler requests baseline every 24 hours, health every 5 minutes and
network every 15 minutes, while enforcing one active collection per
device/profile, bounded backoff and offline expiry.  Retention keeps current,
previous and explicitly pinned snapshots.

## `web_ovpn` handoff

After the foundation accepts locally, a separate clean worktree of
`BorisDruzak/web_ovpn` gets a scoped service client.  Its root-managed token
has only `devices.read`, `context.read` and `context.collect`; internal CA
verification remains enabled.  It adapts list/detail/request/collection/
compare calls into the existing authenticated/CSRF-protected UI and returns an
explicit degraded response if Endpoint Platform is unavailable.  Its Network
Context API remains authoritative for network observations; device correlation
is `confirmed`, `ambiguous` or `unresolved`, never inferred by IP alone.

## Safety and verification

- ALT Linux is the first agent profile; Windows fixtures remain contract
  compatibility checks, not a Wave 1 deployment target.
- No Helpdesk registration or `web_ovpn` user change is required.
- All collection probes are read-only; no collector contacts or changes a
  network device.
- Database migration tests run against the remote-PostgreSQL-safe workflow;
  local disposable PostgreSQL validates concurrency and idempotency.
- Tests cover strict parsing/limits, agent privacy, capability allowlist,
  duplicate delivery, state transitions, semantic-hash invariance, golden
  diffs, scheduler/retention and safe projections.
- A real ALT pilot requires separate authorization after the entire Wave 1
  foundation plus `web_ovpn` adapter are verified.  It requires one named
  test-agent, trusted internal CA, an enrollment campaign and post-collection
  evidence; production remains untouched.

## Explicit non-goals

This foundation does not modify the dirty `web_ovpn` checkout, deploy the
Endpoint Platform, install an ALT agent, collect a real device, alter
OpenVPN/netctl/MikroTik/DNS/DHCP, build an agent release, or run an update
canary.  Those actions are later gates with independent authorization.
