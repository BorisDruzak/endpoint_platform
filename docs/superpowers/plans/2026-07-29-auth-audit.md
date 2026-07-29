# Endpoint Authentication and Audit Implementation Plan

> **For agentic workers:** Execute task-by-task with TDD and independent review.

**Goal:** Add local admin, scoped service auth, and immutable redacted audit for 6A-3.

**Constraints:** Argon2id only; raw password/token/secret never stored/logged; no UI, enrolment, agent or deployment work; no `pc_agent` changes.

## Task 1: Password, opaque sessions, and CSRF

**Files:** Create `endpoint_server/auth/passwords.py`, `admin_sessions.py`, `csrf.py`, `bootstrap_admin.py`; modify `main.py`, requirements; create `tests/server/test_admin_auth.py`.

- [ ] Write failing tests for Argon2id hash/verify, interactive-only bootstrap, 32-byte opaque session generation, HMAC-only storage, expiry/revocation, cookie attributes, and CSRF denial.
- [ ] Run focused tests RED.
- [ ] Implement password/session/CSRF services plus `require_admin()`; use `HttpOnly; Secure; SameSite=Strict` session cookie.
- [ ] Run GREEN and commit `feat: add admin authentication`.

## Task 2: Scoped service credentials

**Files:** Create `endpoint_server/auth/service_tokens.py`, `scopes.py`; modify models/migration as needed; create `tests/server/test_service_auth.py`.

- [ ] Write RED tests for one-time token display, HMAC digest/prefix-only persistence, revoked/expired credential, exact scope allow/deny, and no raw token in result/audit.
- [ ] Implement creator and `require_service_scope(scope)`; produce random 32-byte material and use service pepper HMAC.
- [ ] Run GREEN and commit `feat: add service credential scopes`.

## Task 3: Immutable redacted audit

**Files:** Create `endpoint_server/audit/service.py`, `redaction.py`; create `tests/server/test_audit.py`.

- [ ] Write RED tests for actor/object/request attribution, UTC time, recursive password/token/authorization/cookie/secret/bearer redaction, and update/delete rejection.
- [ ] Implement append-only audit service and DB guards.
- [ ] Run GREEN and commit `feat: add immutable audit service`.

## Task 4: Acceptance

- [ ] Run server, standalone, contract schema, extraction, compile and diff checks; inspect no `pc_agent` changes.
- [ ] Review all changes against the specification and preserve no raw credential in test output or Git.
