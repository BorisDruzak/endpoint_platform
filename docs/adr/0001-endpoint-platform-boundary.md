# ADR 0001: Endpoint Platform Boundary

- Status: Accepted
- Date: 2026-08-01

## Decision

Endpoint Platform is the exclusive endpoint-agent control plane.
It is not the service-to-service integration bus.
Helpdesk ↔ Knowledge uses direct versioned APIs or a separate future integration layer.

## Consequences

Endpoint-agent control flows belong to Endpoint Platform. Service-to-service
integration remains outside that boundary and must use an explicitly versioned
API or a separately approved integration layer.
