# Opera readiness report — 2026-09-26

## Repository

Starting/ending code HEAD at the discovery stop: `552783744f3476e3f16a9d2d44abf20bc86a69f0`. Branch: `codex/browser-sensor-opera-addons-readiness`. Isolated managed worktree based on operator-approved Yandex/3.2.75 work; original checkout and commits preserved. Only discovery/preparation Markdown files added. No production operations. Documentation commit/push was subsequently authorized; Browser Sensor source remains unchanged.

Changed files in docs/browser-sensor:

- opera-runtime-architecture-decision.md
- opera-acceptance-risk.md
- permissions.md
- privacy.md
- opera-addons-submission.md
- opera-reviewer-notes.md
- opera-screenshots.md
- opera-readiness-report.md
- opera-pre-submission-questions.md

## Candidate

Source version remains 0.1.0. Intended next candidate: 0.2.0, not implemented. Artifact, candidate SHA-256 and candidate inventory: NOT PRODUCED due to explicit architecture STOP. Existing release package allow-list is manifest.json, background.js, content.js, protocol.js; this is not an Opera candidate inventory. No false compliant package or re-publication of 0.1.0.

Permission inventory: tabs, nativeMessaging, alarms; top-frame content scripts on http://*/* and https://*/*. Detailed rationale and unverified Opera warning behavior: permissions.md.

## Verification / runtime

`npm test --prefix browser_sensor` baseline: 12 passed, 0 failed. Source and four test files read completely. OPR/ UA normalization explicitly returns null, confirmed by direct Node assertion. Opera native connection cannot open with null family; sending opera would fail Python closed family contracts. This is source/unit evidence, not actual Opera runtime evidence.

Actual Opera version, Windows extension load, service worker errors, native handshake and unpacked ID: NOT TESTED. No working candidate exists at the architecture gate. Windows companion code exists but Opera success is unproved. Mac/Linux core companion functionality is not established; fail-gracefully acceptance remains untested.

## Acceptance / authorization

See opera-acceptance-risk.md for the criterion matrix. Automatic potentially private domain/origin/action metadata has no demonstrated user authorization. The extension has no cloud client, but the Agent forwards/persists telemetry; therefore local transport alone does not resolve the external-store rule. No consent/legal claims made.

## Store preparation

Name, summary, gated description, factual category (Productivity), license decision status and support-page content are in opera-addons-submission.md. Privacy, reviewer notes and screenshot plan are prepared as factual blocked drafts. Public URLs/contact, license, real icons/screenshots and portal package-format verification remain unresolved. The metadata must not be submitted as if planned popup/Opera support were implemented.

## Identity / production

Pinned ID: kkkoaifoohdbdaccmnnoagedifflbide. Unpacked ID: unobserved. Store ID: UNKNOWN UNTIL SUBMISSION. ID migration NOT performed. Production changes: none. No browser installation/profile hack, GPO, policy ownership, WSS, migration, release registration, fleet rollout, Nginx/DB change or store publication.

## Decision

NO-GO — genuine Opera telemetry requires a Foundation contract/status/database expansion; user authorization is unresolved; core functionality on Mac/Linux is unproved against Opera's all-platform testing requirement. Packaging, UI/icons and real runtime validation are intentionally not executed after the explicit STOP. This is the stop-gate deliverable, not completion of a working submission candidate.
