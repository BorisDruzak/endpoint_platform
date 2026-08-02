# ALT Root-Mediated Crash Rollback Design

## Goal

Allow the unprivileged ALT launcher to recover from a newly selected headless
release that repeatedly crashes without granting it write access to the
root-owned install root or weakening the systemd sandbox.

## Observed failure boundary

The installed selector is `/opt/endpoint-agent/current.json`, owned by
`root:root` with mode `0644`. The launcher runs as
`endpoint-agent:endpoint-agent`; `ProtectSystem=strict` is active and its only
writable systemd paths are `/var/lib/endpoint-agent` and
`/var/log/endpoint-agent`. The current crash path writes the selector directly
from that unprivileged process. The denied write leaves the bad release selected.

## Authority model

The existing root-owned update worker remains the only process allowed to
publish releases and selectors. A successful update first verifies the current
release against its embedded manifest and atomically writes its strict selector
identity to `/opt/endpoint-agent/previous.json`. Only then may it atomically
replace `current.json` with the newly verified candidate.

`previous.json` and `current.json` have exactly `schema_version`,
`source_revision`, and `version`. Both are root-owned authority. Service-writable
history remains diagnostics only and is never rollback authority.

## Rollback request

After three crashes inside the existing immediate-crash window, an ALT launcher
reads both root-owned identities and atomically publishes only
`/var/lib/endpoint-agent/updates/rollback-request.json`. Its exact keys are
`crashed_source_revision`, `crashed_version`, `rollback_source_revision`,
`rollback_version`, and `schema_version`, whose fixed value is
`endpoint_alt_rollback_request_v1`.

The request contains no path, command, operation, selector body, or arbitrary
worker argument. It is a regular mode-`0600` service-owned file. The launcher
records `startup_crash_rollback_requested` and exits; it does not claim success.

## Root worker

The existing update path also watches the fixed rollback request. Its root
service keeps the same `ReadWritePaths=/opt/endpoint-agent /var/lib/endpoint-agent`
boundary. The helper accepts no caller input and validates
the fixed request as a non-symlink regular mode-`0600` service-owned file, and
calls the fixed stable launcher with `--apply-alt-rollback` plus fixed roots.

The privileged launcher rejects the request unless its exact schema is valid,
the crash identity equals root-owned `current.json`, the rollback identity equals
root-owned `previous.json` and differs from current, and the previous release
manifest matches its selector, exact file set, hashes, and modes.

On success it atomically replaces only `current.json` with the root-derived
previous selector, consumes `previous.json` and the request, and writes the final
`startup_crash_rollback` marker. Malformed, stale, unsupported, tampered, or
unverifiable requests are archived to one fixed failure record without changing
either selector. If update and rollback requests coexist, rollback is handled
first. No target comes from service-writable history or a supplied path.

## Legacy behavior

The legacy launcher retains its in-process selector rollback outside ALT mode.
The new request and privileged mode are ALT-only.

## Finalized-unit migration

The installer finalizer owns one idempotent fixed-unit transformation: remove
the claim `LoadCredential`, remove the provisioning-handoff environment line,
and replace enrollment-required with gateway-ready. It runs after a verified
claim-removal request and when both claim and request are already absent.

The already-finalized branch first requires the mode-`0600`, service-owned
permanent credential and canonical enrollment identity. A reviewed unit
replacement can therefore be repaired without restoring a one-time claim, while
a merely missing claim on an unenrolled host fails closed. Repeated finalization
is safe and calls `daemon-reload` after the fixed transformation.

## Verification

Tests cover the deployed ownership reproduction, bad-headless request creation,
root-mediated rollback to the exact previous accepted headless release, request
and release tampering, unsupported/stale requests, legacy safety, fixed worker
inputs, and idempotent claim-free unit repair with missing-proof rejection.

No remote mutation or canary is part of this fix round.
