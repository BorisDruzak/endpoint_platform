# ALT headless WSS canary verification

**Status:** BLOCKED — NOT ACCEPTED

**Preflight date:** 2026-08-02

**Authorized pilot:** `test-agent-lin` only

This record is intentionally sanitized. It contains no credential, network
observation, trust-anchor location, artifact URL, raw context, authorization
header or journal body.

## Decision

No canary was assigned and neither remote host was changed. The controller did
not satisfy the mandatory WSS, migration, backup and rollback-artifact gates.
HTTP command pull and Helpdesk were not used as substitutes.

## Local preflight

- Starting checkout: `1e4878de36f75da75bb054f7f42c539ec77be24b`.
- The starting worktree was clean.
- The accepted Task 8 evidence digest was
  `c0cfbbd71b1b053599fba60fe26d18dca433b749da4aff4edfc1f2899becc6e1`;
  verified worker copies remain available.
- That digest identifies the pre-Task-9 archive and must not be published as
  the new canary. Task 9 adds the strict embedded ALT manifest, so a fresh
  SemVer, source revision and digest are required.
- Pre-change artifact check: `1 passed, 5 skipped`.
- Pre-change focused deployment/runtime check: `192 passed, 7 skipped`.
- Post-change focused verification: `246 passed, 12 skipped`.

## Controller preflight

| Gate | Sanitized result |
| --- | --- |
| Core services | active |
| Deployed release | `9f8f5b49f578` |
| Gateway WSS implementation | absent |
| Active proxy WebSocket upgrade route | absent |
| Database migration | `0010_session_last_seen_index` |
| Database read | passed |
| Pre-canary backup | absent |
| Rollback `3.1.80` metadata | present |
| Rollback `3.1.80` artifact | absent |

Required migration for this canary is `0011_gateway_wss` or its reviewed
successor. A build registration without its exact regular artifact is not
rollback availability.

## Pilot preflight

| Gate | Sanitized result |
| --- | --- |
| Agent service | active and enabled |
| Update path | active |
| Pending ALT update | absent |
| Strict selector | passed; selected `3.1.80` |
| Selected immutable release | exact files, hashes and modes passed |
| Fixed launcher | matched accepted selected launcher |
| Permanent credential | service-owned, mode `0600` |
| One-time claim source | absent |
| Legacy identity | service-owned, mode `0600` |
| Canonical headless enrollment identity | absent |
| Explicit `gateway_wss` service selection | absent |
| Explicit migration fallback-off | absent |

The token-bearing legacy identity must never be copied as the canonical
headless identity. Only its validated controller Device identifier may be
serialized into the credential-free strict identity record.

## Acceptance observations

These mandatory observations were not attempted because the preflight failed:

| Required observation | Result |
| --- | --- |
| Authenticated WSS session | not observed |
| Heartbeat after authentication | not observed |
| Baseline over WSS | not observed |
| Health over WSS | not observed |
| Network over WSS | not observed |
| Startup update outcome `applied` | not observed |
| Zero Helpdesk requests | not evaluated |
| Zero Gateway HTTP command-pull requests | not evaluated |
| Failed-next-release automatic rollback | not attempted |
| Rollback target is accepted headless release | not observed |
| Functional after fallback disabled | not observed |

## Re-open gate

Before another canary attempt:

1. deploy and verify the reviewed Gateway WSS server release and proxy route;
2. migrate through `0011_gateway_wss` and verify a fresh database backup;
3. restore and digest-check the accepted rollback artifact on the controller;
4. create and controller-match the strict credential-free pilot identity;
5. build the stable launcher and headless artifact from the reviewed commit;
6. use a fresh immutable SemVer above every registered build and require its
   runtime-reported version to match;
7. repeat every local, controller and pilot preflight item;
8. assign exactly one target, the authorized pilot, then execute the WSS-only
   success and failed-next-release rollback sequence from the ALT runbook.
