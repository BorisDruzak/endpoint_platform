# WorkTime without approval

The user's 2026-10-30 instruction supersedes the earlier approval workflow:
employees record explanations/corrections directly, without a second reviewer.

- [x] Backend: corrections without a historical decision apply immediately;
  report/history say `recorded`, not pending/approved. Preserve historic rejected
  decisions, raw events, explanations, audit, immutable saved timesheets and
  technical UNKNOWN data. Do not fabricate approval rows.
- [x] Disable new approval decisions/queue, including direct service writes.
  Remove approval barriers from monthly snapshot creation; preserve closed-month,
  actor authorization, person/department isolation, CSRF and idempotency.
- [x] Frontend: remove approval navigation/forms/fetches, save corrections directly,
  show recorded state and keep old decisions identifiable as archived history.
- [x] Focused backend/frontend regressions, real isolated PostgreSQL and rendered
  desktop/mobile checks; one bounded independent review of this change only.
- [ ] Prepare and deploy through the canonical staging release procedure with
  backups and source identity; verify existing owned correction is effective
  without approving/replaying it. Production promotion is a separate stage.

Ownership: stage_permissions owns backend/worktime tests/docs; Root owns UI,
browser tests, plans and release orchestration. Preserve existing SSO/Keycloak
dirty work; no unrelated commits/push or live role changes. The earlier request
for a second approver is obsolete; domain-session readiness is still needed for
native notification acceptance.

Verification: Root49 focused backend tests passed on Windows3.12 (3 PG opt-in
skips); all52 passed on isolated Linux/PostgreSQL with zero skips. Schema43
roundtrip and safe downgrade refusal preserve actual rows. Source manifest
ef96786a2fe197d3beb72d8d331bc8869d384bffd3380ad5e74cfb4356f804e2;
temporary cluster stopped with no owned processes/TCP/Unix listeners. First
packaging attempt lacked a fixture module, stopped safely before tests; preserved
as HOLD, then corrected snapshot supplied fixtures/new tests/aiosqlite test code.
Frontend69 unit tests, build and13 real Chromium scenarios passed. A targeted
desktop/mobile correction rerun also passed; Root inspected both screenshots,
no overflow. Playwright MCP transport closed after inventory; canonical project
Playwright CLI provided browser evidence. No actual SSO login is claimed here.
Independent delta review found a stale HR report/CSV after direct correction.
Root reproduced it with a failing real-browser test; report revision callback
fixed immediate totals/correction/CSV refresh. The regression and final delta
review passed; historical snapshot content remains immutable.
Release phase uses one task-only reviewed commit/clean managed checkout and
canonical archive builder, no push or unrelated source/role/Keycloak changes.
