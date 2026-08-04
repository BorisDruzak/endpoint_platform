# Periodic WSS Update Polling Design

## Problem

The headless agent invokes its HTTPS update-recommendation check only from the
WSS connection callback.  A healthy long-lived WSS session therefore cannot
observe a rollout created after that initial callback.  The five-minute value
currently records a next-poll deadline but never schedules work at that
deadline.

## Decision

Keep WSS as the command transport.  Add a bounded, cancellable periodic task
to the runtime lifecycle that invokes the existing authenticated
update-recommendation flow at the configured interval while WSS remains
connected.  It must not request the legacy command-poll endpoint and it must
stop when the WSS lifecycle stops.

The first recommendation check remains at successful WSS connection.  The
periodic task performs later checks and uses the existing TLS verification,
device credential, update integrity checks, ACKs, artifact download, and ALT
root-worker handoff unchanged.

## Alternatives considered

- Restart the service for each rollout.  Rejected: it masks the scheduling
  defect and makes delivery depend on an operational intervention.
- Add a new WSS update message.  Rejected: it changes the Gateway protocol
  and server deployment surface for a problem solved by the existing bounded
  HTTPS update API.

## Acceptance criteria

- A rollout created after a stable WSS connection is requested within the
  configured interval without restarting the agent.
- The existing immediate connection-time check remains available.
- No legacy `/agent/v1/gateway/commands/next` request is made by the
  periodic update check.
- Stopping or reconnecting the WSS lifecycle cancels the periodic task and
  does not leave duplicate check loops.
- Runtime unit tests cover the deadline and cancellation behavior.
