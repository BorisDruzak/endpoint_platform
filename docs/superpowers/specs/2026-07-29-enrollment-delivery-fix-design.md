# Retry-Safe Enrollment Delivery Fix Design

## Scope

This fix closes the Task 3 review findings without changing the device-token
storage model, campaign/claim authorization, agent runtime, WebSocket, UI or
deployment. It preserves `b312177` and adds a new canonical transport contract,
pre-commit recovery proof, safe audit correlation, expired-envelope cleanup and
explicit trusted-proxy semantics.

## Canonical transport contracts

The agent HTTP boundary uses new strict public models:

- `AgentEnrollmentRequestV1` carries the original enrollment intent plus a
  43-character URL-safe client-generated `delivery_nonce`.
- `AgentEnrollmentDeliveryV1` carries the device ID, policy ID, bounded policy,
  enrollment receipt, raw show-once device token and issuance timestamp.
- `EnrollmentDeliveryProofV1` carries the receipt and hardware fingerprint for
  retry and acknowledgement.
- `DeviceCredentialRotationV1` carries a show-once pending token and overlap
  deadline.

Each model has its own literal `schema_version`, rejects unknown fields and is
published as JSON Schema and as concrete request/response operations in the
generated OpenAPI document. The legacy non-secret `EnrollmentRequestV1` and
`EnrollmentResponseV1` remain unchanged for compatibility, but the live agent
routes do not claim to emit them.

Secret-bearing transport schemas are committed because they are the canonical
wire contract. They intentionally have no committed golden payload fixture, so
the existing synthetic-fixture rule continues to prohibit credentials and
token-like samples.

## Pre-commit recovery proof

The agent generates `delivery_nonce` before its first enrollment request and
retains the complete request until delivery is durable. The nonce is never
persisted or audited.

The server derives the receipt with HMAC-SHA256 under `session_secret` using the
domain `endpoint-enrollment-delivery-receipt-v1` and an unambiguous canonical
message. Every variable field is encoded as a four-byte unsigned big-endian
length followed by its bytes. The ordered fields are:

1. nonce ASCII bytes;
2. device identifier ASCII bytes;
3. campaign UUID bytes;
4. claim UUID bytes, or zero length when no claim exists;
5. platform ASCII bytes;
6. `requested_at` normalized to UTC with fixed microsecond precision.

The 32-byte HMAC is returned as unpadded URL-safe Base64 and becomes the
enrollment receipt. Persistence retains only its contextual HMAC digest and the
existing encrypted token envelope.

After authority, source, platform, claim binding and device-event attribution
are revalidated, a duplicate request derives the same receipt, locks the
existing envelope and recovers the same token. It returns HTTP 200 without
changing quota, state or audit. A new enrollment returns HTTP 201. A changed
nonce or changed bound intent cannot authenticate the envelope and fails
closed. A missing, acknowledged or expired envelope is never recreated.

## Audit request correlation

Client `X-Request-ID` is untrusted. Route code never persists it directly.
When present, a shared helper stores a domain-separated HMAC-SHA256 correlation
under `session_secret`; when absent, it creates a server random identifier.
This preserves repeat correlation without allowing campaign, claim, receipt,
device-token or other secret-like strings to enter audit rows. Internal service
boundaries may continue to accept request IDs that were already server-derived.

Validation and HTTP errors continue to remove attacker-controlled input values.

## Envelope expiry and cleanup

Retry and acknowledgement lock an envelope with `FOR UPDATE`. If the matching
receipt is expired, the same transaction deletes the row, appends an
`enrollment.delivery_expired` audit event with public identifiers only and
commits before returning the generic unavailable response.

A bounded cleanup function selects at most 100 expired envelopes ordered by
expiry with `FOR UPDATE SKIP LOCKED`, deletes each and appends one audit event
per row. The server worker runs this batch periodically and commits each batch;
failures roll back the batch and retry after the next interval.

The row lock is the race boundary. A recovery that acquires the lock while the
envelope is still valid completes before cleanup may delete it. Cleanup skips
rows already locked by active recovery, so it cannot invalidate a just-valid
recovery in flight.

## Trusted proxy policy

The application owns client-address trust. `TRUSTED_PROXY_CIDRS` is optional
and defaults to empty, so direct `request.client.host` is authoritative and
forwarding headers are ignored.

When the observed peer is in a trusted proxy CIDR, the request must contain
exactly one syntactically valid `X-Forwarded-For` IP. Multiple, missing or
malformed values fail closed. Production Nginx must overwrite this header with
`$remote_addr`, never append caller input. Uvicorn proxy-header rewriting must
be disabled so the application can still observe and authenticate the proxy
peer. Deployment configuration is deferred to the existing deployment gate.

## Verification

Tests cover lost-first-response recovery, changed nonce/intent denial, canonical
model and OpenAPI validation, secret-header audit injection, observed and batch
expiry deletion, cleanup locking shape, trusted/untrusted proxy behavior and
all prior enrollment, retry, acknowledgement and rotation invariants.

Acceptance reruns focused and standalone tests, Ruff, compileall, generated
schema/OpenAPI checks, retained-tree extraction, Alembic offline
upgrade/downgrade, diff checks and the opt-in disposable PostgreSQL tests when a
loopback URL is available.
