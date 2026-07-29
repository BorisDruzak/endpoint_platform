# Endpoint Authentication and Audit Design

## Scope

6A-3 adds local administrator authentication, scoped service credentials, and immutable audit records. It does not add UI pages, enrolment, agent transport, commands, or deployment.

## Administrator authentication

The local bootstrap CLI reads the first administrator password only from an interactive terminal and stores Argon2id output in `admin_users.password_digest`. It never accepts a password from an environment variable, command line, log, audit payload, or fixture.

Successful login creates 32 random bytes encoded as an opaque session token. Only `HMAC-SHA256(session_secret, token)` is stored in `admin_sessions`; the raw token is an `HttpOnly; Secure; SameSite=Strict` cookie. Sessions expire, can be revoked, and are checked by `require_admin()`. Unsafe HTTP methods require a per-session CSRF token and reject missing/mismatched values.

## Service credentials

Service tokens contain a public identifier and 32 random bytes. The full value is shown once on creation; storage retains only a non-secret prefix and `HMAC-SHA256(service_token_pepper, token)`. `require_service_scope(scope)` checks active status and exact scope membership before allowing a route. No admin or service secret is returned by read endpoints.

## Audit

Every mutation writes an append-only `audit_events` record: actor type/id, action, object type/id, request id, UTC timestamp, and JSON-safe redacted detail. The service rejects attempts to update or delete audit rows. Redaction removes password, token, authorization, cookie, secret and bearer values recursively before persistence.

## Tests and acceptance

Tests prove Argon2id verification, cookie attributes, expiry/revocation, CSRF, scope denial, show-once credential handling, HMAC-only storage, audit immutability and redaction. Acceptance runs server and standalone tests, schema/extraction/compile/diff checks. Real passwords/tokens/secrets never enter Git or test reports.
