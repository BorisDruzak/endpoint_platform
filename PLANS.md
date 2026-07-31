# Endpoint Platform Plan

## Goal

Deliver Wave 1 Device Context, then expose normalized projections in web_ovpn without coupling that panel to raw agent results.

## Current State

6A enrollment and update control-plane work are merged locally. Device Context
foundation has passed independent review and local acceptance: strict profiles,
bounded ALT collectors, fixed Gateway capabilities, additive lifecycle/snapshot
storage, safe service routes, scheduler and retention. The typed safe SDK plus
the feature-gated `web_ovpn` adapter API and Russian-first endpoint pages have
also passed local review in clean worktrees. Explicit netctl correlation has
also passed review without IP-only matching. ALT packaging/provisioning and the
isolated test-agent acceptance harness are complete. A valid wildcard
`*.sosnadmin.local` certificate is in active use on the TLS source host; its
private key has not been copied into the workspace.

The initial production deployment is complete on `endpoint-platform-server`
at release `42de4d53f0d1`: PostgreSQL listens only on loopback, Nginx and the
API service are enabled, and the database is migrated through
`0010_session_last_seen_index`. The live `https://endpoint.sosnadmin.local`
health check passes strict CA and hostname verification.

The initial administrator `osn-admin` is active with the explicit
`updates:write` grant. Bootstrap was audited, and the strict-HTTPS login check
created then revoked its temporary verification session.

The test-agent pilot has completed one-time enrollment and a live Gateway
baseline collection. The permanent credential is owned by
`endpoint-agent:endpoint-agent`; the finalized unit has no one-time claim
dependency, stays active with the TLS-only Gateway transport, and produced a
completed `baseline_v1` snapshot on the production controller. The inherited
Helpdesk WebSocket/API is no longer used by the ALT systemd runtime.

## Constraints

- web_ovpn and network_configuration remain read-only until a clean dedicated worktree exists.
- ALT Linux is first; no real device collection, deployment, or canary belongs to the foundation.
- Collectors are bounded/read-only; safe APIs never expose raw result payloads or credentials.
- The periodic allowlist is baseline (24h), health (5m) and network (15m).
  Diagnostic is manual-only. Scheduler and retention are local server work;
  their migration must not be run remotely in this foundation task.
- DNS for `endpoint.sosnadmin.local` is configured and the internal CA is
  available as deployment input outside Git. TLS verification remains mandatory.
- Disk resize is cancelled. Deployment uses the existing disk only after a
  capacity check confirms it is sufficient; no resize is a prerequisite.

## Next Steps

1. Implement and validate the Gateway-native ALT update and rollback runtime
   on `test-agent-lin` before any wider rollout.  The dedicated design and
   task plan are in `docs/superpowers/specs/2026-07-31-gateway-update-runtime-design.md`
   and `docs/superpowers/plans/2026-07-31-gateway-update-runtime.md`.
2. Validate Gateway reconnect and a repeated baseline collection after the
   update/rollback exercise.
3. Begin the separate Wave 1 `web_ovpn` integration only in its dedicated
   worktree after the production agent pilot is accepted.

## Verification

Foundation completion needs strict contracts, collector privacy/capability,
PostgreSQL lifecycle/idempotency, semantic hash/diff, scheduler/retention,
safe projection and generated-schema tests. Scheduler keeps one active request
per device/profile and expires bounded offline work; retention preserves the
current snapshot, its prior snapshot and explicit pins.

## Handoff

Production deployment passed its gate; the remaining agent pilot and the
`web_ovpn` service-token/client integration remain distinct deliverables.

