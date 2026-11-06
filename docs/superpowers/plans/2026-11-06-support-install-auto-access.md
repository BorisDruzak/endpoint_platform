# Automatic first-install support access implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development; review each task and preserve the current worktree.

**Goal:** Automatically authorize bounded reserve access after a successful installation and record how to use it during agent/updater failures.

**Architecture:** Provider-side one-time installer intent, consumed by the running independent Support1.0.1 status. Existing signed176 wire/media remain unchanged; explicit manual policies and source revocation retain precedence.

**Tech Stack:** Python3.12, SQLAlchemy2.1.1 (supported>=2.0), Alembic1.20.0, PostgreSQL16, existing FastAPI/Windows Support1.0.1.

**Spec:** ../specs/2026-11-06-support-install-auto-access.md

## Global constraints

- Exact176 C6/B6/media and Linux156 unchanged; no Windows native replay or identity/key resets.
- Initial access<=8hours, installer intent15minutes, no automatic renewal after consume/expire/manual action.
- Domain access requires actual installed running1.0.1; no fake capability at registration.
- Existing operator public key and verified SOSNADM\admin-2; no passwords/accounts guessed or created.
- Source authority/key-role/gateway/audit/locking and current campaign/fleet bounds remain intact.

## Review focus

- Old registration/heartbeat at deployment must not become an unsolicited access grant.
- Concurrent status/register/admin disable must preserve manual priority and consume once.
- Legacy/failing runtime, key conflicts, changed defaults or expired intent must fail closed.
- Default keys cannot be reused as host/tunnel/gateway keys.
- Diagnostic instructions must work with stopped Core/updater and strict UUID host pins.

## Task1: Backend automatic installation defaults

- [x] RED tests for config/one-time pending/actual runtime consumption/manual cancellation/replay/expiry/legacy/error/roles/default changes.
- [x] Minimal validated Settings, nullable0047 marker, registration/status integration and audit; no wire/client changes.
- [x] Targeted/server/config tests, isolated PostgreSQL real routes/races and migration checks.
- [x] Independent compliance/security review; fix confirmed issues; root commits exact files.

## Task2: Rules and connection procedure

- [x] Update AGENTS/runbook to use reserve access for unresolved authorized agent/updater diagnosis without redundant permission prompts.
- [x] Document installation auto-grant8h, manual renewal, actual Console controls, existing principals, strict authenticated host pins and SSH commands.
- [x] Check source/UI labels and commands; keep bounds/revocation/native ownership explicit.

## Task3: Deploy and verify

- [x] Fresh backup/capacity/config and six-device policy/identity baseline; exact provider commit and additive migration.
- [x] Atomic provider/config update; no gateway restart, no auto-grant to existing manual rows; preserve current valid leases.
- [x] Fresh provider/schema/defaults/source audit and actual reserve SSH on120; correlate existing policies/keys/current release unchanged.
- [x] Record tested scope and limits; clean isolated tests/task auth; final docs commit/push and report.

Implementation/deployed provider: `783cc21589e80115d395c4be8b89e710687804e6`. Final evidence: `docs/verification/2026-11-07-support-install-auto-access.md`. Windows176 and Linux156 unchanged.
