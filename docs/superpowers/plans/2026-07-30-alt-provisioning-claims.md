# ALT Provisioning Claims Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` task-by-task with an independent review after each task.

**Goal:** Provision an ALT Endpoint agent through a one-time, hardware-bound install claim without exposing a permanent device credential to `web_ovpn`, ISO media, logs, or deployment configuration.

**Architecture:** Endpoint Platform issues a show-once install claim to a dedicated provisioning service principal. `web_ovpn` stores it only in the root-only systemd credential source that the prepared ALT package exposes as a transient credentials-directory file. On first boot the unprivileged agent derives/validates its hardware fingerprint, exchanges the claim using the existing enrollment transport, atomically writes its service-user-owned permanent credential, proves persistence, and then removes the claim. A retryable outage leaves the claim in place until expiry; it never falls back to a campaign or generic administrator token.

**Tech Stack:** Endpoint Platform FastAPI/Pydantic/PostgreSQL enrollment, `pc_agent`, systemd credentials, `web_ovpn` FastAPI service client, pytest.

## Global Constraints

- Only a scoped provisioning service identity may request claims; it is not an admin browser credential.
- A claim is bound to a bounded install session ID and normalized hardware fingerprint, has short expiry, and is one-time.
- The provisioning controller never receives, persists, returns, or logs the permanent device token.
- No claim is committed, embedded in ISO/image/config, or placed in an environment variable/command line.
- First boot performs bounded retry for temporary Gateway outage; expired/replayed/mismatched claims fail closed.
- Claim file is root-owned mode 0600 and passed only by systemd `LoadCredential`; permanent credential is `endpoint-agent:endpoint-agent` mode 0600.
- No production or test-host installation occurs until package and all tasks pass independent review.

---

### Task 1: Scoped Endpoint Platform claim issuance

**Files:**
- Modify: `endpoint_server/auth/scopes.py`, enrollment routes/services and contracts as required
- Create: provisioning claim route/service tests

**Interface:** `POST /api/v1/provisioning/install-claims` accepts `{install_session_id, hardware_fingerprint, campaign_id}` from a dedicated service scope and returns `{claim, expires_at, install_session_id}` exactly once to that principal.

- [ ] Write failing tests for scope rejection, expiry, claim binding, audit redaction, and absence of permanent credential.
- [ ] Implement a fixed provisioning scope, claim issuance that delegates to existing one-time claim authority, and transactional redacted audit.
- [ ] Verify only the scoped service can receive a claim and it cannot receive a device token.
- [ ] Commit `feat: issue scoped provisioning claims`.

### Task 2: First-boot agent claim exchange

**Files:**
- Create/modify: `pc_agent` enrollment bootstrap module and service config integration
- Create: `pc_agent/tests/...` enrollment handoff tests

**Interface:** `bootstrap_enrollment(credentials_dir, config, probe) -> EnrollmentOutcome` reads only the systemd claim credential, calls existing enrollment transport with hardware proof, atomically writes permanent credential, proves it is mode 0600/service-user-owned, then removes the claim source through a root-mediated controlled action.

- [ ] Write failing tests for expired/replayed/mismatched claim, transient outage bounded retry, atomic credential persistence and no secret logging.
- [ ] Implement claim-only bootstrap and fixed retry budget; do not accept campaign/admin tokens.
- [ ] Verify success keeps identity across restart and failure leaves no partial permanent credential.
- [ ] Commit `feat: bootstrap agent from install claim`.

### Task 3: `web_ovpn` constrained provisioning client

**Files:**
- Create/modify: `web_ovpn` Endpoint Platform provisioning client/adapter and tests

**Interface:** an authenticated provisioning-controller path requests a claim for one install session and writes only the root-managed source file consumed by the ALT installer; response to UI/API contains session/expiry state but never the claim or permanent token.

- [ ] Write failing auth/CSRF/audit/redaction tests.
- [ ] Implement scoped service client with TLS verification, no claim response logging, bounded file write/mode check and degraded outage state.
- [ ] Verify replay/mismatch cannot return prior claim to another session.
- [ ] Commit `feat: provision ALT enrollment claims`.

### Task 4: Local integration acceptance

- [ ] Run contracts, server enrollment, agent bootstrap and panel provisioning tests.
- [ ] Verify no token/claim appears in logs, fixtures, artifacts, env examples, or `git diff`.
- [ ] Build the reviewed local ALT package only; do not install it yet.
- [ ] Commit runbook/acceptance evidence.

## Deployment Gate

Only after all tasks are accepted may the reviewed package be installed on `test-agent-lin`. Production remains outside this plan.
