# Endpoint Enrollment Implementation Plan

**Goal:** Deliver 6A-4 campaigns, claims, HMAC device credentials, retry-safe enrolment and rotation.

**Constraints:** No agent runtime, WebSocket, Helpdesk/UI or deployment changes. Every mutation audits atomically; raw tokens never persist/log.

## Task 1: Schema and credential primitives

- Create device credential digest/envelope primitives and forward migrations.
- RED tests: HMAC compare, 32-byte token, encryption/retry receipt expiry/fingerprint binding, rotation overlap.
- GREEN: encrypted short-TTL envelope and pending credential state; commit `feat: add device credential primitives`.

## Task 2: Campaigns and install claims

- Create enrollment services/models and admin APIs.
- RED tests: expiry, max uses, platform/CIDR, revoke, concurrent final use, claim one-time/session/fingerprint binding.
- GREEN with PostgreSQL transaction locks and atomic audit; commit `feat: add enrollment campaigns`.

## Task 3: Agent enrolment and retry

- Create `/agent/v1/enroll`, receipt retry/ack and credential rotate/activate routes.
- RED tests: idempotent duplicate, envelope replay/expiry, mismatch, response retry, rotation activation/deadline.
- GREEN: device id/policy/token response, generic failures/redaction; commit `feat: add retry-safe enrollment`.

## Task 4: Acceptance

- Run focused enrollment tests, standalone tests, migration upgrade/downgrade on disposable PostgreSQL, extraction/compile/schema/diff checks, no `pc_agent` changes.
