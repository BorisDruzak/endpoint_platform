# Endpoint Platform Plan

## Context and Evidence Retention v2 (2026-09-24)

The implementation plan is
`docs/superpowers/plans/2026-09-24-context-evidence-retention-v2.md`.
The architecture and production measurement procedure are in
`docs/architecture/context-evidence-retention-v2.md`. Work starts from main
`0aa22537d93e29e79eb43dce01e8e1e50ee23a6f` on
`codex/endpoint-retention-v2`, with Agent `3.2.65` unchanged. The new Alembic
head is `0027_context_observed_backfill` after a follow-up observation-freshness
repair. Production backup, migration and acceptance
evidence follows.

Production release `d626c1ed44b38637870e2968c599fc793142fa6e` was
deployed from `codex/endpoint-retention-v2` after `1849 passed, 40 skipped`,
21 Console unit tests, three browser E2E tests, contract generation check,
Alembic offline SQL, compileall and `git diff --check`. Previous release was
`0aa22537d93e29e79eb43dce01e8e1e50ee23a6f`; DB moved from
`0025_console_enrollment_queue` to `0026_context_evidence_v2` with migration
unit result `success`. The verified custom-format backup is
`/var/backups/endpoint-platform/pre-retention-v2-20260924T131917Z.dump`
(17,765,654 bytes, SHA-256
`0a3bcd6eb403067e069abc9d9f96af53b3388b747748b68a0ae0bc2705cee5a8`).
The release archive SHA-256 matched on both machines:
`e53b36362c8b28deac253855600d2e7a05ce106dee00edfb2581cedcdfb30d8d`.
API, worker, PostgreSQL and Nginx were active; strict hostname/CA HTTPS gave
`200` for health, Console login and its versioned JS asset. Unauthenticated
service API returned `401`. Existing completed Module detail projected one
successful step with its safe result. The live Agent `3.2.65` session remained
connected after the API restart. Initial due counts were 35,549 raw collection
payloads, 1,955 raw snapshot payloads and 92,150 scheduler bookkeeping rows;
later counts fell to 35,370, 1,766 and 91,984, respectively, as bounded
cleanup ran. At 13:29:25 UTC, Agent `3.2.65` completed fresh `health_v1` and
`session_v1` collections; both `ContextCurrent.last_observed_at` values advanced
after deployment. A bounded production snapshot-retention invocation removed
100 rows; all current pointers remained valid (`broken_current=0`) and six
current profiles for the `3.2.65` device remained. The read path for an older
successful diagnostic operation returned its lifecycle with
`result_available=false`, without a 503. PostgreSQL race tests were opt-in and
skipped locally because no disposable local PostgreSQL URL was configured. The
dedicated Linux test host was unreachable over SSH during this release.
Creation of a fresh production Module Operation and Evidence PIN through the
Console awaits an authenticated administrator session; the browser opened at
the login form during acceptance.

Post-deployment audit found that revision 0026 backfilled `last_observed_at`
only from the last changed snapshot. Existing completed deduplicated baseline
and inventory collections could be newer. Revision 0027 backfills those
observations from retained collection timestamps without changing snapshots;
the pre-migration query found 12 affected current rows (eight baseline and four
inventory). Follow-up release `db107f895bfc54cedef80a981eacb4f6794d79f1`
was published and deployed after `1850 passed, 41 skipped`, contract and
compile checks, offline Alembic SQL, and a successful full migration through
0027 on a disposable PostgreSQL database. Its test current pointer preserved
the original snapshot/`updated_at` and advanced `last_observed_at`; the
disposable database was removed. The second verified custom-format backup is
`/var/backups/endpoint-platform/pre-observation-backfill-20260924T134545Z.dump`
(17,451,925 bytes, SHA-256
`47c79fa17d8c4dbd98cedb0e98bba13ebc73ceb83b73a98e60c0f67de0ef3510`).
The follow-up release archive matched on both machines at SHA-256
`c434799debbdf317d063801a91cbc9f9cffd38a0714e222d1036d490ef70f86a`.
The migration unit returned `success`; production revision is
`0027_context_observed_backfill` with zero remaining current/collection
freshness mismatches. Agent `3.2.65` remained connected and completed fresh
health and session observations after the second API restart. API, worker,
PostgreSQL and Nginx remained active, strict HTTPS health returned `200`, and
post-release warning-or-higher service journal entries counted zero.
At 13:55 UTC, a separate disposable PostgreSQL 16 database on the production
host was migrated through revision 0027 and used for an actual concurrent
Evidence PIN versus expiry cleanup check. The uncommitted PIN held the row;
the cleanup transaction's `SKIP LOCKED` batch processed zero rows. After the
PIN committed, another cleanup processed zero rows, the safe payload remained,
`expires_at` was NULL, `pinned_at` was set, and one immutable PIN audit event
existed. The disposable database was dropped. This check used synthetic
records and did not change production application data.

## Current Console v1 work (2026-09-24)

The active implementation plan is
`docs/superpowers/plans/2026-09-24-endpoint-console-v1.md`, based on main
`2995b06d3b45a26d39b6acc4129e5892b6c7c942` and the user-supplied spec
in `docs/superpowers/specs/2026-09-24-endpoint-console-v1.md`.
The Module Platform capability constraint repair is revision
`0022_module_step_capabilities`; Windows Setup release metadata is revision
`0023_windows_setup_releases`; the credential-free Console module owner is
revision `0024_console_module_owner`, and enrollment queue pagination uses
revision `0025_console_enrollment_queue`. The Console foundation, fleet/context,
enrollment, updates, operations, Module Workbench, and audit were implemented
on `codex/endpoint-console-v1` and published to `main` at
`4801e21b20c342ba006b9bd9c40c42e6642ce27b`. The approved Windows Agent
3.2.63 runtime contract is unchanged. An isolated browser test covers the real
local API through manual enrollment approval, canary creation and rollback,
and module publication and device execution with simulated Agent results. The local run
also corrected module operation detail projection and the approved enrollment
queue/label, and aligned campaign display names with the Russian Console.
Device detail now projects the current user, OS and version from safe snapshots;
Context shows collection state and server-derived freshness. The browser flow
covers Setup download, campaign editing, and a Russian-label regression guard
across primary pages. Campaign editing now formats the existing expiration in
the browser's local time and preserves the original instant when only other
fields change; a browser regression runs in `Asia/Yekaterinburg`.
Completed rollout history now
uses its own filtered, paginated server query. The Module Capability Catalog
shows backend-provided Russian names, platforms, minimum Agent version, risk,
consent, and parameter rules.
Published modules on device detail and compatible devices in Module Lab now
use bounded, paginated API queries and visible page controls.
Windows campaigns and active Setup releases now also have bounded, paginated
Console queries. Campaign policy can select a signed release from later pages;
the Setup catalog publishes a typed page response. The legacy enrollment
campaign list contract remains unchanged. Module version history is bounded
and paginated. Device Context changes and update history have typed, paginated
responses and page controls; mixed baseline/inventory changes retain global
chronological order without exposing raw snapshots. Module validation and lab
histories also have bounded pages; the acceptance control uses a server-derived
summary of all passed platforms, including evidence beyond the current page.
All Console, operation journal, and audit JSON routes publish typed response
models; the Setup binary download remains a file response. The 2026-09-24
release `758043d02f3bce895e27cb3c9dd615f0692fa217` runs in production at
DB revision `0025_console_enrollment_queue`. The previous release
`a49cd5aa351a` is retained for rollback. The verified pre-release PostgreSQL
backup is
`/var/backups/endpoint-platform/pre-console-758043d-20260924T060319Z.dump`
(17,359,610 bytes; SHA-256
`eca3b674e313949f7e72e469840ade6c1aac99f34cb591e7d079d8a6c802dca8`).
The release archive SHA-256 is
`68ee7be926f36bb18af00ea35b0cd0687f34f09eebac464ef70146a107817d7b`.
The final code revision passed 1784 Python tests (39 skipped), contract
generation check, and compileall. The frontend passed 20 unit tests, three
Playwright E2E flows, and production build. Provider release-gate CI passed on
the deployed code revision.

The administrator credential was rotated as requested; previous sessions were
revoked and production browser login succeeded. Strict CA/hostname HTTPS
returned 200 for health, login, and the hashed Console asset. API, worker,
Nginx, and PostgreSQL are active. The local Windows Agent `3.2.63` completed
one real `adapter.list` Module Lab operation and one published device operation;
both reached `succeeded` with safe step results and audit events. Module
platform, execution, and read-only primitive flags are enabled; network
primitives remain disabled. The original mode-600 environment file is backed
up at
`/etc/endpoint-platform/endpoint-platform.env.pre-console-local-agent-20260924T054931Z`.
The workstation does have Endpoint Agent MSI `3.2.63` installed. The failed
preflight checked stale canary provenance for MSI `3.2.41`, whose ProductCode
was removed by later universal Setup major upgrades. Reinstalling the same
signed, SHA-256-verified `3.2.63` MSI through the canary wrapper refreshed the
protected provenance; the collector and validator then reported `READY`.
Universal Setup does not refresh that canary-only record, so another Setup
major upgrade can make this particular preflight stale again. Console rollout
and rollback use verified ZIP runtime builds and the Windows runtime selector,
not MSI. A live Console rollout/rollback cycle on this workstation remains
unverified; browser E2E covers those actions with simulated Agent outcomes.
PR #35 was merged by fast-forward into `main`. The historical Wave 1
plan below is retained as a record, not a current deployment gate.

## Goal

Deliver Wave 1 Device Context, then expose normalized projections in web_ovpn without coupling that panel to raw agent results.

## Current State

Headless Agent V2 architecture baseline is repository
`5b53f080d884193189b7458e27ab55a04cb6efe4`. Historical ALT pilot evidence
covered `3.1.84`; the pilot currently selects the intact immutable `3.1.80`
rollback release.

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

The production Endpoint Platform release is `9f8f5b49f578`: the API, database
and proxy are active, but this release does not contain Gateway WSS, the active
proxy does not expose the WebSocket upgrade route, and the database remains at
`0010_session_last_seen_index`. Task 9 live acceptance is blocked until the
reviewed WSS release/configuration and `0011_gateway_wss` migration are
deployed, a database backup is verified, and the rollback artifact is restored
on the controller.

The initial administrator `osn-admin` is active with the explicit
`updates:write` grant. Bootstrap was audited, and the strict-HTTPS login check
created then revoked its temporary verification session.

The test-agent pilot retains a secure permanent credential and token-bearing
legacy identity, and its finalized service has no one-time claim dependency.
The credential-free canonical headless enrollment identity is not present yet;
it must be created and matched to the controller Device before a WSS canary.

Historical single-device update proof on `test-agent-lin` recorded that the
controller-delivered `3.1.84` canary reached `applied` after the post-restart
handshake, then an authenticated rollback selected the already immutable
`3.1.80` release and also reached `applied`. That proof used the pre-WSS
runtime and does not satisfy the headless WSS gate. The Task 9 root worker uses
the separately reviewed stable root launcher; headless canary payloads do not
replace it. A deliberately malformed `3.1.83` archive was rejected without moving
the selector and recorded as a terminal failed canary; its immutable artifact
was not overwritten. The post-rollback `baseline_v1` request completed through
the former Gateway adapter. The controller metadata for rollback `3.1.80`
remains, but its artifact file is currently absent, so no new assignment is
allowed.

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

- Headless Agent V2 architecture work is documentation and local guardrail work
  only. It must not deploy to production, alter production configuration or
  data, restart services, or change the dedicated test-agent host.

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

1. Review and merge the local Endpoint Operations API v1 package described in
   `docs/superpowers/specs/2026-08-09-endpoint-operation-v1-design.md` and
   `docs/superpowers/plans/2026-08-09-endpoint-operation-v1.md`. The first
   typed operation, `context.diagnostic.collect`, is feature-gated and
   default-disabled; no production enablement, database migration, agent
   rollout, or Helpdesk integration is included in this package.
2. Treat the Gateway/update/rollback pilot as accepted only for the dedicated
   `test-agent-lin`; do not assign a production endpoint or run a bulk rollout
   without a separate change decision.
3. Keep the `web_ovpn` Endpoint Platform integration feature-gated. Any
   credential-expiry policy, production endpoint assignment, bulk rollout,
   IP-only correlation, or exposure of raw agent result payloads requires a
   separate approved change.

## Verification

Foundation completion needs strict contracts, collector privacy/capability,
PostgreSQL lifecycle/idempotency, semantic hash/diff, scheduler/retention,
safe projection and generated-schema tests. Scheduler keeps one active request
per device/profile and expires bounded offline work; retention preserves the
current snapshot, its prior snapshot and explicit pins.

Endpoint Operation v1 local acceptance on 2026-08-18 recorded 265 contract,
30 operation (4 PostgreSQL-dependent skips), 36 context (1 skip), 70
architecture and 55 transport tests passing. `tests/gateway` has 54 passing
tests but two pre-existing tests that monkeypatch the removed
`pc_agent.runtime.application._https_update_hook`; `tests/packaging` has 57
passing tests and one pre-existing stale hash for
`pc_agent/context_profiles/baseline.py` in `initial-runtime-3.2.13.json`.
The full suite stops at collection because two legacy agent tests import absent
`scripts.build_module_zip` and `scripts.register_support_modules`. These are
separate baseline repairs, not evidence to enable the feature.

## Handoff

Production deployment, the dedicated test-agent pilot, and the Wave 1 network
list presentation passed their gates. The deployed `web_ovpn` integration
remains a narrow service-to-service boundary; its page cache is MAC-free and
its only automatic association is the unique-MAC confirmation. Any production
endpoint assignment, bulk rollout, credential-expiry policy, or new data source
requires a separate decision.
