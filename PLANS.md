# Endpoint Platform Plan

## Goal

Deliver Wave 1 Device Context, then expose normalized projections in web_ovpn without coupling that panel to raw agent results.

## Current State

6A enrollment and update control-plane work are merged locally. Device Context
foundation has passed independent review and local acceptance: strict profiles,
bounded ALT collectors, fixed Gateway capabilities, additive lifecycle/snapshot
storage, safe service routes, scheduler and retention. The typed safe SDK and
feature-gated `web_ovpn` adapter API are also implemented in clean local
worktrees. UI history/compare remediation and netctl correlation remain before
a test-agent pilot.

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

1. Finish baseline-history API review, then complete and review the
   `web_ovpn` history/compare UI remediation.
2. Implement explicit netctl correlation without IP-only matching.
3. Prepare ALT packaging/provisioning and validate it on the test agent.
4. At the production gate, check current disk capacity, install PostgreSQL and
   Nginx, transfer the CA through a controlled deployment path, and apply
   migrations only after a verified deploy.

## Verification

Foundation completion needs strict contracts, collector privacy/capability,
PostgreSQL lifecycle/idempotency, semantic hash/diff, scheduler/retention,
safe projection and generated-schema tests. Scheduler keeps one active request
per device/profile and expires bounded offline work; retention preserves the
current snapshot, its prior snapshot and explicit pins.

## Handoff

No remote migration, ALT install, web_ovpn deployment or network change is
authorized by this plan. The `web_ovpn` service token/client, netctl
correlation and real pilot are distinct later deliverables.

