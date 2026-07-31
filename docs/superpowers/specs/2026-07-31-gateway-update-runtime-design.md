# Gateway Update Runtime Design

## Goal

Allow the finalized ALT service to receive a signed Endpoint Platform update
recommendation, stage it, restart through its immutable launcher and report
the terminal outcome over the existing TLS-only Gateway identity.  The flow
must support launcher rollback without starting the legacy Helpdesk runtime.

## Observed Compatibility Boundary

The ALT bundle is not a generic desktop install.  Its selector is
`/opt/endpoint-agent/current.json` with the exact schema
`schema_version`, `source_revision`, and `version`; its release payload is
`versions/<version>/{launcher,pc_agent/,manifest.json}`.  The generic
`pc_agent.launcher.installer.apply_update` writes a different selector shape
and deletes `source_revision`, so it cannot be used directly for ALT.

The pilot's pre-Gateway bundle labels are not semantic versions.  Endpoint
Update contracts and their durable journal require semantic versions.  Before
the first controller-driven update, the test host is re-installed from a
verified ALT bundle whose manifest and current selector use a semantic
baseline version.  The operation is limited to `test-agent-lin`.

## Decision

Create a compact ALT-specific update runtime.  It shares the Gateway fixed
origin, CA, durable device credential, strict HTTPS session, and
`EndpointUpdateAdapter` contracts, but has no legacy callback.  It has three
responsibilities:

1. on startup, derive a terminal report from the local ALT launcher history
   and retry the durable scheduled acknowledgement;
2. periodically fetch a `linux_amd64` recommendation from the `canary`
   channel, acknowledge `requested`, download only the controller-provided
   artifact using the device bearer, and stage a pending update;
3. request a controlled process exit only after the pending file is durable.

The ALT launcher gets a matching ALT-specific apply path.  It validates the
bundle manifest before publish, keeps the immutable release layout, preserves
the selector schema, records `previous` only in launcher history, and rolls
back to the previous immutable bundle after repeated immediate crashes.

## Safety Rules

- The only controller origin is `https://endpoint.sosnadmin.local`; TLS CA and
  hostname checks are mandatory.
- Device credentials and raw response bodies are never logged.
- A 401 or 403 is terminal for the current process and does not trigger a
  legacy or untrusted fallback.
- Only `linux_amd64` and the canary channel are eligible for this pilot.
- A candidate must have a strictly newer SemVer than the installed selector.
- The updater verifies size, SHA-256, archive structure, manifest, file modes,
  and source revision before changing the selector.
- `scheduled` is not success.  `applied`, `failed`, or `rolled_back` is
  reported only after the launcher has a durable local outcome.

## Verification

Unit tests must cover: rejected credentials, no legacy fallback, a newer
recommendation becoming a durable pending release, selector schema retention,
idempotent scheduled/terminal reporting, and rollback reporting.  A single
canary on `test-agent-lin` then proves update to a fresh semantic release,
Gateway reconnect, a repeated baseline request, and a deliberately invalid
candidate that rolls back to the verified prior release.  No production agent
is updated in this phase.
