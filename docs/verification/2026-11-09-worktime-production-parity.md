# Worktime, employee portal and scoped Helpdesk production promotion

Follow-up: the initially disabled production Helpdesk AD entry described in this
16:49Z snapshot was corrected at16:59Z. See the [AD activation receipt](2026-11-09-helpdesk-production-ad-entry.md)
for current enabled settings, real browser redirect and remaining identity gate.

Observed 2026-11-09T16:49Z. The user authorized transfer of the remaining Worktime,
employee portal and Helpdesk-login changes and explicitly allowed only the
SSO/Worktime Helpdesk backport. Production services were actually deployed, not
merely prepared. No people, profile fields, account bindings or attendance were
invented to pass acceptance.

## Actual runtime identity

| Component | Production | Staging |
| --- | --- | --- |
| Endpoint API and worker | `818d2897b1d4b86bd0a90ed75729bdaa0d5f3170` | Same revision |
| Endpoint schema | `0051_staging_linux_worktime` | Same revision |
| Helpdesk | `1dc2be0d358dec13b12c4861d4f43419c70672d8` | `b9361e0f04c1738b09536dcf832e201a8f5cb04f` |
| Helpdesk schema | `153` | `158` |

Endpoint process cwd and RELEASE_COMMIT agree. Production API/worker PIDs
373261/373262 and staging224602/224603 were active with NRestarts0. Production
Helpdesk server/control373058/373062 and staging244227 were active with NRestarts0.
The default health payload version0.0.0 is not the runtime source identity.

Main Helpdesk staging advanced independently from65665e1c during qualification.
Its unrelated Studio/ticket/other changes were preserved. The authorized subset
was backported onto actual production6cca48e5; complete Helpdesk Git/schema parity
was intentionally not claimed. The main read-only Helpdesk checkout was unchanged.

## Changes and enabled production behavior

The common Endpoint merge retains Linux183, signed Windows177 and all historical
native recovery evidence while adding the employee portal, recorded Worktime,
Helpdesk handoff and deployment/contract tooling. Two reviewed regressions were
fixed with failing tests first: MFA step-up preserves the sealed Worktime authority
switch, and companion authority lookup supports Helpdesk-only people without an
AD GUID. The original43/44 migration ancestry and DDL hashes were retained.

The Helpdesk port includes source-session-bound one-use PKCE handoff, integration
identity/session contracts, fixed environment navigation, safe callback logging,
profile-error preservation, password-level AD/OIDC support and refresh nonce
handling. Original migrations151–153 were retained byte-for-byte. The unrelated
registration UI and other staging features were excluded.

Production Endpoint has SSO, Worktime and Helpdesk login enabled. Production
Helpdesk has Worktime handoff enabled to exactly
`https://endpoint.sosnadmin.local/employee`. Existing issuer/client secrets, trust
CA and service authority were checked privately; only the required configuration
keys were merged. No staging credentials or full environment file were copied.
Helpdesk AD login remains disabled until confirmed identity bindings exist;
ordinary password login and existing local Endpoint administrators remain usable.

The newly deployed production `/app/login` was observed in Codex with the updated
employee support UI. Verified HTTPS returned200 for that page, session capabilities,
the Endpoint employee login and healthz. Public capabilities correctly report
SSO disabled on Helpdesk. An authenticated request with a random unissued handoff
grant reached the actual provider and returned400 invalid_grant, establishing
paired service authority without creating a person/session.

## Qualification and data preservation

- Exact Helpdesk SHA full CI [42651948275](https://github.com/BorisDruzak/helpdesk/actions/runs/42651948275)
  passed all18 canonical layers, with full_merge_gate_satisfied true. This includes
  database/migration layers, no-DB/script suites, frontend/browser checks and audits.
- Separately invoked canonical database layers passed900 tests, zero failures,
  with cleanup auditing on owned PostgreSQL55619. Live production/staging5432
  databases were never used for fixture suites.
- Endpoint integration checks:1289 passed/19 skipped broad deployment/auth/contracts;
  205 passed/3 skipped enrollment/support/Linux/companion;16 real-PostgreSQL tests
  passed beside the database;122 frontend tests, typecheck and Vite build passed.
  Two real companion browser fixture checks passed at1440/390 widths.
- Contract acceptance passed4 tests against actual provider HTTP/gateway WSS.
  Its client was a protocol test client, not an installed physical agent.
  Provider OpenAPI digest is
  `1d2fce6b033fe8c46df9f65bb81eae9b285316abea065aa1bb8626fa1b991869`.
  Compared with the old canonical contract,19 routes were added and no existing
  paths/schemas removed or changed. Consumer lock validation passed.
- Actual isolated deployed Helpdesk1dc canary completed two closed requester/support
  ticket cycles, core and degraded, with zero duplicate events. Its built ticket
  UI opened one WSS connection and received3 frames per cycle, with no JavaScript
  errors or HTTP5xx. Wrong verifier, replay, forged fields, source logout/revocation,
  role isolation and CSRF checks passed using disposable fixture identities only.
- Degraded acceptance redirected only the owned canary to a closed Endpoint port:
  the BFF returned503 endpoint_unavailable while ticket lifecycle/UI remained usable.
  No real Endpoint service was stopped for that check.
- Endpoint production50→51 clone rehearsal preserved83 original tables/578950 rows
  and all original-column fingerprints; staging51→51 preserved85/189211. Repeated
  upgrades were inert. Actual production activation preserved36 protected tables,
  staging37. All owned clone databases were dropped.
- Helpdesk150→153 clone rehearsal preserved189 original tables/3236 rows and all
  original-column fingerprints; repeat upgrade was inert. Rehearsed92f9 runtime
  source/migrations/dependencies were unchanged through final1dc, whose subsequent
  commits changed test/CI harnesses only.
- The real production Helpdesk pre-migration backup899811 bytes, SHA
  `f9d5e2bb22548d27beda765aa7dc2935bd7ed813edcb94722f9e88af8c788623`,
  was restored by the canonical helper into an owned temporary DB after deployment.
  It verified original schema150, removed the temporary DB and left live153 intact.
  The source_release field identifies the candidate backup helper, not old runtime.
- Production Endpoint pre-activation backup51918544 bytes, SHA
  `ba6bf3844b922c5ffef6a57043853f2b95f23ea29262278310d567b8d3a857f4`,
  and all protected private evidence remain retained.

The canonical Helpdesk deployer validated exact-SHA full CI, risk/readiness records,
provider lock, schema, accepted frontend bytes, private config and backups before
activation. Production archive SHA is
`7d5f820e3febaf34be25a0ffcaf35b369940ac7afaf253e0fababefaccfd1abb`.
Accepted CI, final canary and production web content digest agree:
`71f6ccc735ca22769d7c2e58191021511ca2c9b738b6622c6442405a6e9eecc4`.
Endpoint archive SHA is
`c7dbb8119ade3f2d179e214f0ebea1608551bc689bb2ed7e9953c99b0f5dfe37`.

Before Endpoint source/config activation, native Setup, preparation, OTA, running
commands and active operations were all zero and rechecked after service stop.
Historical expired commands were preserved. Independent production gateway24963,
exporter334584 and SSH889 stayed active without restart. Final free space314552320
bytes was measured after actual publication/restore; no disk resize was performed.

## Agent and Worktime relationship

Eight bridge/companion/user-sensor/native-notification source paths in installed
Windows177/source25f2ad8a and Linux183/source21fc543a match the common runtime.
No new agent build, installation, reboot, GPO refresh or fleet policy change was
needed. Actual candidate typed TLS context reads of Windows120/Linux105/210 passed.

At16:47Z production accepted user-activity cursors advanced on Windows120/177 and
Linux105/210/183; staging VM107/183 advanced at16:48Z. These are genuine accepted
samples, beyond process/heartbeat/version evidence. Linux190 last accepted sample
was12:57Z; its stale observation does not establish shutdown or network failure.

Core retains its device credential. A closed typed per-user local bridge derives
the actual OS peer SID/UID and does not give the sensor Core secrets or arbitrary
identity/URL/command access. Native prompts use TaskDialog/notify-send, bounded
poll/backoff and lease/presentation/ACK fencing; notification failure does not stop
technical WSS. Companion bootstrap remains AD-only as specified by the existing
design. Browser authentication owns employee identity and source-session authority.

Production Worktime bindings, schedules, categories, confirmed identities and
employee sessions were still empty at16:48Z. Therefore genuine production employee
handoff and a native prompt for a real person are **not yet accepted**. The prior
helpdesk_admin session had an incomplete profile and must not gain Worktime access.
A fresh updated login page was left open for an existing complete employee; no
new profile/binding was manufactured. Technical ACTIVE does not mean working,
IDLE does not mean absent, and missing coverage remains unknown.

## Cleanup, retained failures and evidence

The disposable canary, fixture account/credentials/units/Nginx site and PostgreSQL
data were removed at16:48:37Z. Ports18443/18666/18667/55619 are closed. Its private
test-history archive was retained, SHA
`5b69770e57fcc7c1766794bc86f41a7a3e90cd1a6160e205b9d0e7d4a03ef325`.
An initial cleanup guard stopped before mutation because independently managed
Helpdesk staging had advanced. Cleanup then pinned and preserved its freshly
verified b9361e0f source/PID instead of restoring the historical65665e1c snapshot.
Real staging remained active and unchanged during cleanup.

Earlier failed CI runs remain recorded: unsupported Ubuntu26 browser dependencies,
two missing SSO cleanup profiles, ambient credential redaction test contamination,
and the old178-vs181 cleanup count. Fixes affected CI/tests and final full CI passed.
An invalid combined DB invocation caused fixture-order errors; canonical separate
layers passed. A local Windows Git-worktree exporter assumption failed, while the
normal-checkout full CI passed; unrelated exporter behavior was unchanged. Earlier
Windows-built canary frontend bytes and a TechPanel page without subscriptions
were iteration evidence only; final accepted CI bytes and real ticket WSS were used.
No TLS verification, identity, native recovery or production gate was bypassed.

GitNexus MCP was unavailable in the enabled catalog. Exact committed source,
runtime routes, tests and canonical OpenAPI were checked directly; no manual
central synchronization or manifest links were created. Context7 documentation
was checked for the pinned HTTPX/Authlib/Playwright APIs before dependent changes.

Private root receipts remain under `/var/lib/endpoint-worktime-parity-20261109`
on production and `/var/lib/helpdesk-worktime-parity-20261109` on staging.
Nonsecret operator evidence and the full73-file Helpdesk commit manifest are under
`C:/endpoint-platform-wix-build/worktime-parity-20261109/candidate-1dc2be0d358d`.
No passwords, bearer grants, environment secrets or private keys are committed.

## Published commits

Endpoint runtime: `818d2897b1d4b86bd0a90ed75729bdaa0d5f3170`
(`feat(worktime): integrate employee portal and Helpdesk login`).

Helpdesk branch `codex/worktime-production-sso`, all pushed:

- `b51830a8288c1a7ef0dfdd95d8aa9519ce4e6902` — feat(auth): backport SSO and WorkTime production contracts
- `92f9d2063950c9784e743d815bcebc23508c0599` — ci(readiness): pin the browser job to Ubuntu 24.04
- `f42eefb95f9874299a9c0745b0f331b071ac2748` — test(auth): declare SSO database cleanup profiles
- `35b6309671f3d13ae1dd3fd91523251192a3d0a0` — test(ci): isolate redaction fixtures from ambient credentials
- `1dc2be0d358dec13b12c4861d4f43419c70672d8` — test(auth): include WorkTime tables in cleanup scope guard

Final documentation commits do not change these deployed runtime identities.
