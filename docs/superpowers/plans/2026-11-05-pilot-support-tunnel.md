# Independent support tunnel implementation plan

Spec: `../specs/2026-11-05-pilot-support-tunnel.md`.
User chose the outbound gateway design. This plan is not an implementation or
rollout receipt. All steps below remain required before declaring access ready.

## Task1: Protocol, policy and broker

- [ ] Define bounded public-key registration and independent read-policy/status
  credentials, reusing existing device authentication/source/revocation checks.
  Keep registration independent of Core/WSS and claim retries idempotent.
- [ ] Add device/policy/lease records, admin role/CSRF/audit, key conflicts and
  retirement/expiry revocation. Use canonical migration/OpenAPI generation.
- [ ] Implement a narrowly scoped privileged broker reconciler: owned tunnel
  identity, loopback-only assigned port, no shell or unrelated forwarding;
  never mutate existing administrator SSH access. Validate daemon config before
  reload, preserve rollback, and keep active diagnostics bounded during API outage.
- [ ] Test real isolated PostgreSQL races, authorization/revocation, key rotation,
  expired leases and exact-device/port ownership. Review privilege boundaries.

## Task2: Independent Windows Foundation component

- [ ] Resolve and pin the supported Microsoft dependency for actual target OS;
  verify real bytes/signatures and dependency availability without reboot/GPO
  changes or overwriting existing SSH state.
- [ ] Build a separate signed service/supervisor with protected versioned storage,
  local keys, strict CA/host-key validation, bounded retries and owned child
  process cleanup. No Core/observer listener or arbitrary-source execution.
- [ ] Register public keys after standalone durable enrollment proof, before
  provisioner's final Core start; retry registration without replaying a claim.
  Already enrolled native upgrades use the same path.
- [ ] Integrate install/uninstall/upgrade and revocation into full Setup while
  preserving original identities, native receipts and unknown-outcome ownership.
- [ ] Test process independence, missing/broken Core, wrong policy/key, service
  restart, interruption, private ACLs and no secrets in logs/arguments/receipts.

## Task3: Console and live pilot

- [ ] Show policy, expiry, host-key identity, tunnel and actual access proof as
  separate states. Provide controlled connection information and audit.
- [ ] Qualify key-authenticated diagnosis on dedicated test Windows, with Core
  and observer stopped, then natural restart/reconnect and revocation/expiry.
- [ ] Publish a signed full Setup containing this separately versioned component;
  activate supported pilot devices through the same canary/qualification process
  and existing all-active policy with two concurrent installation chains.
- [ ] Update release/rules and report old-source/pre-enrollment limits honestly.
  No workstation command entry is an ordinary installation prerequisite.
