# Endpoint CUPS maintenance

These operations target one existing queue on a Linux agent. The agent
announces them over Gateway WSS when it finds the local CUPS socket and
client utilities. CUPS must permit the service's local identity to perform
the requested operation.

| HTTP method and path | Exact service scope | Request |
| --- | --- | --- |
| `POST /api/v1/devices/{device_id}/cups/queue-configurations` | `cups.queue.configure` | `{"queue":"office","enabled":"on","accepting":"on"}` |
| `POST /api/v1/devices/{device_id}/cups/test-pages` | `cups.test_page.submit` | `{"queue":"office"}` |
| `GET /api/v1/cups-operations/{operation_id}` | `cups.operations.read` | Owning service client only |

Set `ENDPOINT_OPERATIONS_API_ENABLED` and apply migration
`0037_cups_operations` before enabling use. Each request takes the usual
`X-Correlation-ID`. Both POSTs require a UUID in `Idempotency-Key`. Retrying
with the same request and service client returns the same operation. A
different request under the same key conflicts.

The queue action accepts `on`, `off`, or `keep` for enabled and accepting
state. It verifies the current and resulting state without recreating the
queue, clearing jobs, or releasing jobs held individually. The print action
submits one fixed page with one copy and returns the CUPS job ID after
acceptance. Verify physical output at the printer when needed.

Endpoint logs the authenticated service client at admission. Give each
direct operator a distinct service client for attribution. The terminal
audit contains the operation and device IDs, queue, result or failure code,
and job ID when known.

The durable agent journal is required for retry safety. Keep it with the
enrolled agent's data. Endpoint sends a delivered operation again only to
the same installed agent identity. Treat `cups_outcome_unknown` as a request
to reconcile the local CUPS state or spool before offering another action.

[Queue controls](https://openprinting.github.io/cups/doc/man-cupsenable.html)
[Acceptance controls](https://openprinting.github.io/cups/doc/man-cupsaccept.html)
[Print submission](https://openprinting.github.io/cups/doc/man-lp.html)

## Linux scheduler validation

On 2026-11-19, an isolated Ubuntu 24.04 sandbox used the CUPS 2.4.7 scheduler,
a private Unix socket, and a synthetic queue. The Endpoint runner used the
normal CUPS CLI and its SQLite journal. Queue reconfiguration enabled the queue
and restored acceptance while both individually held jobs remained. The fixed
test page was the third job. Replaying the operation returned its original job
ID and the spool still contained exactly three jobs. The sandbox verified the
submitted page content and was removed after the scheduler stopped.
