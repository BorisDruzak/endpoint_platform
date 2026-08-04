# ADR 0002: Neutral Agent Transport

- Status: Accepted
- Date: 2026-08-01

## Decision

Current HTTPS pull is transitional.
Target is neutral Gateway WSS.
Legacy Helpdesk WebSocket is not retained.
No silent fallback to legacy transport.

## Consequences

The agent transport evolves through Endpoint Platform Gateway WSS. A failed or
unavailable target transport must be visible to operators; it must not switch
silently to the retired Helpdesk transport.
