# Worktime production parity and agent integration acceptance

## Authorized objective and boundaries

The user requests review of remaining staging Worktime, employee portal and
Helpdesk-login changes, transfer to production, equal server versions, and a check
of existing agent/Worktime integration. Preserve production data, installed signed
Windows177/Linux183 media, device identities, fleet policy12, Support grants and
the employee/admin/DLP authorization boundaries. Helpdesk repository code is a
read-only contract source; do not edit or deploy Helpdesk code from this workspace.
No inferred HR attendance, fabricated administrator session or ambiguous person
mapping. Existing Activity telemetry remains separate from personnel records.

Current committed primary baseline9ff725ecf6e9eb533c72b2fd6615a6cf372774ec;
production providerfd196e78b2c5/schema50; staging0b8ea9138011/schema51. Existing
linked worktree/branch codex/pilot-support-channel is reused. GitNexus MCP is absent
from the enabled tool catalog; use exact Git/source/contracts/test evidence and
document dynamic cross-repository relationships. Do not reindex centrally.

## Task1 — read-only audit and concrete deployment requirements

- Record fresh revisions/schema/service health, capacity and relevant enabled
  feature/configuration names (never secret values) on both servers.
- Review the exact staged source delta, migrations0043_worktime_recorded,
 0044_worktime_helpdesk and0051 merge, Worktime contract, portal, handoff and CSRF/
  realm isolation. Trace agent Activity → explicit temporal person binding →
  technical coverage/pending explanations; identify companion delivery implemented
  versus planned. Inspect relevant approved read-only Helpdesk contract source.
- Record backend/frontend/agent findings, existing verification and remaining
  exact acceptance gates. Do not execute Keycloak recovery/diagnostic tools as a
  deployment substitute or copy staging credentials/configuration to production.

## Task2 — integrate a common source without regressing current agents

- Merge staged source into current primary in this existing worktree, inspect
  every conflict and retain latest canonical Linux183 runtime/tests/release history.
  Preserve genuine migration ancestry and staged Worktime history. Keep signed
  media unchanged. Bring required portal/auth/contract/deployment tooling together.
- Any confirmed defect gets a failing regression first, a narrow correction and
  focused regression checks. Consult exact dependency documentation before changing
  library-dependent behavior. Do not add unrelated new functionality.
- Run relevant Worktime/auth/enrollment/support/contract tests, frontend tests,
  typecheck/build and migration graph checks. Fresh-context final review covers
  cumulative integration, cross-repository contract and deployment risks.

## Task3 — isolated database and integration qualification

- Back up actual databases/configuration privately. Use owned same-host isolated
  database clones to rehearse production50 → common51 and staging51 → common51.
  Verify row counts/content fingerprints, personnel records/history and native
  identity/authority invariants. Use separate disposable PG for test fixtures,
  never run fixture tests against either live database.
- Test real shared Helpdesk exchange readiness, fixed origins/audiences, TLS,
  one-use state/PKCE, CSRF, logout/revocation and employee/admin/DLP separation.
  Use genuine authorized sessions for live acceptance; never invent principals,
  grants, personnel events or working time merely to make the UI pass.
- Build exact common server and Console artifact; verify archive permissions,
  requirements, source identity, Nginx query-safe logging and available capacity.

## Task4 — deploy the same reviewed revision to staging and production

- Deploy staging first with guarded rollback and preserve its existing data and
  environment-specific authority. Verify actual HTTPS/UI/API/agent flows.
- After checks, back up fresh production state, wait for native/update operations
  to be quiescent, apply additive migrations, atomically activate common source and
  approved production-specific configuration, and verify health. Preserve gateway/
  SSH and installed-agent state. Rollback restores source/configuration without
  destructive schema downgrade or history deletion.
- Confirm the same actual source revision/schema on both environments; keep their
  own databases, credentials, origins and device registrations separate.

## Task5 — live agent/Worktime acceptance and durable results

- Check existing Windows177/Linux183 fresh telemetry and Worktime bindings using
  the already selected devices; do not perform unrelated reinstall/reboot/GPO work.
  Verify employee UI and relevant companion behavior actually available in source.
- Record what is implemented, active, tested and still a separate future feature.
  Preserve unknown/ambiguous telemetry and history; no ACTIVE=work assertion.
- Stop/remove only owned temporary test resources, retain protected backups and
  recovery evidence, update release/deployment/runbook records, commit/push scoped
  changes and report exact common revision, tests, live results and limits.
