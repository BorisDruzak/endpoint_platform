# Endpoint Platform Plan

## Goal

Deliver Wave 1 Device Context, then expose normalized projections in web_ovpn without coupling that panel to raw agent results.

## Current State

6A enrollment and update control-plane work are merged locally. Device Context
foundation is implemented in the local feature worktree: strict profiles,
bounded ALT collectors, fixed Gateway capabilities, additive lifecycle/snapshot
storage, safe service routes, scheduler and retention. Independent review and
full local acceptance remain the gate before any Wave 1 panel work.

## Constraints

- web_ovpn and network_configuration remain read-only until a clean dedicated worktree exists.
- ALT Linux is first; no real device collection, deployment, or canary belongs to the foundation.
- Collectors are bounded/read-only; safe APIs never expose raw result payloads or credentials.
- The periodic allowlist is baseline (24h), health (5m) and network (15m).
  Diagnostic is manual-only. Scheduler and retention are local server work;
  their migration must not be run remotely in this foundation task.

## Next Steps

1. Complete independent review and full local foundation acceptance, including
   generated contracts and local disposable-PostgreSQL migration evidence.
2. Make a separate web_ovpn SDK/adapter/UI plan in a clean worktree.
3. Obtain separate authorization for an ALT pilot only after both sides pass.

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

