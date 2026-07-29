# Endpoint Platform Plan

## Goal

Deliver Wave 1 Device Context, then expose normalized projections in web_ovpn without coupling that panel to raw agent results.

## Current State

6A enrollment and update control-plane work are merged locally. The next item is the Device Context foundation design in docs/superpowers/specs/2026-07-29-device-context-foundation-design.md.

## Constraints

- web_ovpn and network_configuration remain read-only until a clean dedicated worktree exists.
- ALT Linux is first; no real device collection, deployment, or canary belongs to the foundation.
- Collectors are bounded/read-only; safe APIs never expose raw result payloads or credentials.

## Next Steps

1. Implement contracts, collector profiles and Gateway allowlist.
2. Implement PostgreSQL lifecycle, canonical snapshots/diffs, scheduling and safe service API.
3. Verify locally; then make a separate web_ovpn SDK/adapter/UI plan.

## Verification

Foundation completion needs strict contracts, collector privacy/capability, PostgreSQL lifecycle/idempotency, semantic hash/diff, scheduler/retention, safe projection and generated-schema tests.

## Handoff

No remote migration, ALT install, web_ovpn deployment or network change is authorized by this plan.

