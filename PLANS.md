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

The production Endpoint Platform release is `9f8f5b49f578` on
`endpoint-platform-server`: PostgreSQL listens only on loopback, Nginx and the
API service are enabled, and the database is migrated through
`0010_session_last_seen_index`. The live `https://endpoint.sosnadmin.local`
health check passes strict CA and hostname verification.

The initial administrator `osn-admin` is active with the explicit
`updates:write` grant. Bootstrap was audited, and the strict-HTTPS login check
created then revoked its temporary verification session.

The test-agent pilot has completed one-time enrollment, Gateway delivery and a
live baseline collection. The permanent credential is owned by
`endpoint-agent:endpoint-agent`; the finalized unit has no one-time claim
dependency, stays active with the TLS-only Gateway transport, and produced a
completed `baseline_v1` snapshot on the production controller. The inherited
Helpdesk WebSocket/API is no longer used by the ALT systemd runtime.

The complete single-device update proof also passed on `test-agent-lin`: the
controller-delivered `3.1.84` canary reached `applied` after the post-restart
handshake, then an authenticated rollback selected the already immutable
`3.1.80` release and also reached `applied`. The root worker now resolves and
verifies the launcher in `current.json` rather than retaining stale updater
code. A deliberately malformed `3.1.83` archive was rejected without moving
the selector and recorded as a terminal failed canary; its immutable artifact
was not overwritten. The post-rollback `baseline_v1` request completed through
Gateway; its unchanged semantic hash reused the existing current snapshot.

Wave 1 is merged and deployed in `BorisDruzak/web_ovpn` at `f1108f4`. The
`openvpn-web` runtime has the matching typed Endpoint Platform SDK, a
root-managed least-privilege `web-ovpn-context` credential, and the configured
CA file. DNS resolution for `endpoint.sosnadmin.local` is pinned to the
internal resolver for the internal domain; live health and adapter calls pass
hostname and CA verification. The network-device list shows a session-only
Endpoint Agent state: it refreshes no more than once in five minutes, preserves
a stale safe cache on failure, and confirms a relationship only for a unique
normalized-MAC match. No MAC, IP, raw context, token, CA path or upstream error
is rendered or returned by the new status route. The status route is
session-protected; existing Bearer API authentication is unchanged.

The service credential was rotated through the controller lifecycle with no
scope change and no expiry policy. The replacement was staged and verified over
strict TLS before an atomic web-host switch; the old credential was revoked
with immutable created/revoked audit records, then its local backup was
securely removed. Production acceptance verified one active replacement
credential, the rejected old bearer, and a successful current identity-feed
call.

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

1. Treat the Gateway/update/rollback pilot as accepted only for the dedicated
   `test-agent-lin`; do not assign a production endpoint or run a bulk rollout
   without a separate change decision.
2. Keep the `web_ovpn` Endpoint Platform integration feature-gated. Any
   credential-expiry policy, production endpoint assignment, bulk rollout,
   IP-only correlation, or exposure of raw agent result payloads requires a
   separate approved change.

## Verification

Foundation completion needs strict contracts, collector privacy/capability,
PostgreSQL lifecycle/idempotency, semantic hash/diff, scheduler/retention,
safe projection and generated-schema tests. Scheduler keeps one active request
per device/profile and expires bounded offline work; retention preserves the
current snapshot, its prior snapshot and explicit pins.

## Handoff

Production deployment, the dedicated test-agent pilot, and the Wave 1 network
list presentation passed their gates. The deployed `web_ovpn` integration
remains a narrow service-to-service boundary; its page cache is MAC-free and
its only automatic association is the unique-MAC confirmation. Any production
endpoint assignment, bulk rollout, credential-expiry policy, or new data source
requires a separate decision.

