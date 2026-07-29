# Agent Update Adapter Design

## Goal

Connect the existing `pc_agent` self-update lifecycle to Endpoint Platform's
new `/agent/v1/updates/*` control plane without changing launcher semantics.

## Compatibility

The adapter polls Endpoint Platform first using the existing device bearer.
It maps a recommendation to the already supported update command payload,
writes no new persistent secrets, and preserves `pending_update.json`, exit
42, launcher verify/publish/rollback and post-restart success rules.

While Endpoint Platform is being adopted, a documented legacy poll is a
fallback only when the new endpoint is explicitly unavailable (404/501 or
connection failure).  A valid new endpoint response, including no assignment,
never falls back.  The fallback creates no Endpoint Platform report.

## Flow

1. At startup/manual update, agent reads local pending state; it never polls
   while an update is pending.
2. It requests a platform/channel recommendation from `/agent/v1/updates`.
3. With an assignment, it posts `requested`, downloads/verifies artifact via
   the existing command path, posts `scheduled`, then exits normally through
   code 42.
4. After launcher apply and successful next handshake, it posts `applied`;
   terminal launcher failure posts `failed` or `rolled_back` with a safe code
   only.  The report idempotency key is local and durable.
5. A rollback assignment is an ordinary older release; no in-place overwrite
   or direct launcher manipulation occurs.

## Boundaries

- No release build, upload, bulk rollout, deployment or production canary in
  this increment.
- The agent never logs/returns bearer tokens, URLs with credentials, pending
  payloads, local paths, traces or raw launcher logs.
- Endpoint Platform responses use strict generated contracts.  Unknown/malformed
  payloads fail closed and leave no pending update.
- The first live test is a named local canary/test-agent only after unit and
  release artifact verification; production remains untouched.
