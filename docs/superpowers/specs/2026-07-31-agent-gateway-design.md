# Agent Gateway Design

## Goal

Replace the legacy Helpdesk WebSocket dependency in the ALT service with the
Endpoint Platform Gateway while preserving the installed agent's bounded
Device Context capabilities.

## Decision

The service uses only `https://endpoint.sosnadmin.local` with the installed
CA and its root-owned, enrolment-issued device credential.  It never falls
back to the legacy Helpdesk address, token store, or unauthenticated HTTP.

## Flow

1. The existing first-boot gate writes the device credential once.
2. A dedicated Gateway runtime reads that credential with strict ownership
   checks and uses it as a bearer only for Endpoint Platform agent routes.
3. The server authenticates the device, schedules fixed context capabilities,
   and receives typed, bounded results.
4. Network failure keeps the service alive with bounded reconnect; rejected
   credentials fail closed without secret output.

## Compatibility

Legacy Helpdesk WebSocket startup is not part of the ALT systemd runtime.
The old GUI/helpdesk flows remain untouched for their existing distribution.

## Verification

Unit tests cover credential validation, HTTPS-only origin, request/result
contracts and retry behaviour.  The pilot proves an enrolled ALT agent stays
active, exchanges a Gateway request, and records a baseline snapshot.
