# Endpoint Enrollment Design

## Scope

6A-4 adds campaigns, install claims, device credentials and retry-safe enrolment. It excludes WebSocket transport, agent runtime changes, Helpdesk identity and UI.

## Campaign enrolment

An administrator creates a bounded campaign with expiry, maximum uses, allowed CIDRs, target platform, policy, optional label/site and revocation state. `POST /agent/v1/enroll` validates the campaign token, source address, platform and fingerprint; then atomically reserves one use, creates device identity and a unique HMAC-digested device token.

Raw device tokens are never persisted. A successful enrolment stores a short-lived encrypted retry envelope keyed by an opaque receipt and bound to the same hardware fingerprint. Receipt replay before expiry may recover the token; first acknowledged delivery or expiry destroys the envelope. Failed response delivery therefore does not consume a campaign use irrecoverably.

## Install claims and credentials

Install claims are one-time, expiring credentials bound to installation session and fingerprint. Mismatched fingerprint, expired/reused claim and revoked campaign fail closed. Device credential rotation creates a pending HMAC digest and overlap deadline; old credential remains only until new-token activation confirmation or deadline.

## Security and tests

Every mutation creates an audit record in the same transaction. Campaign, claim, receipt and raw token values are redacted. Tests cover expiry, max-use races, platform/CIDR/revocation, idempotency, claim binding, receipt replay, fingerprint mismatch, digest comparison, rotation and audit atomicity.
