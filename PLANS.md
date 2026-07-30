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

1. At the production gate, re-check production capacity and verify the exact
   committed application release and its local test gate.
2. Install and configure PostgreSQL and Nginx on the Endpoint production host,
   transfer the verified wildcard certificate and key through a controlled
   deployment path without persisting them in Git or the workspace, then apply
   migrations only after the application deployment is verified.
3. Run the agent pilot only after the production API and TLS smoke checks pass.

## Verification

Foundation completion needs strict contracts, collector privacy/capability,
PostgreSQL lifecycle/idempotency, semantic hash/diff, scheduler/retention,
safe projection and generated-schema tests. Scheduler keeps one active request
per device/profile and expires bounded offline work; retention preserves the
current snapshot, its prior snapshot and explicit pins.

## Handoff

No remote migration, web_ovpn deployment or network change is authorized
before the production deployment gate passes. The `web_ovpn` service
token/client, netctl correlation and real pilot are distinct later
deliverables.

