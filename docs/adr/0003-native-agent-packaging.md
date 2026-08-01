# ADR 0003: Native Agent Packaging

- Status: Accepted
- Date: 2026-08-01

## Decision

One Git repository.
ALT uses RPM.
Windows uses MSI.
Common runtime and contracts; platform-specific service and package layers.

## Consequences

Shared runtime behavior and contracts stay in this repository. ALT and Windows
release artifacts use their native package formats and isolate platform service
and packaging details from the common runtime.
