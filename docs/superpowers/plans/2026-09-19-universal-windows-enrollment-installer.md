# Universal Windows Enrollment Installer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build one secret-free `EndpointAgentSetup.exe` that installs the current Windows MSI and supports server-selected AUTO and MANUAL campaign enrollment.

**Architecture:** A persisted request layer selects exactly one eligible Windows campaign and freezes that choice. The existing hardware-bound `ic_` claim and stdin provisioner remain authoritative; a Python Setup bootstrapper orchestrates MSI installation, request polling, provisioning, service startup, and server-side WSS/context completion checks.

**Tech Stack:** Python 3, FastAPI, Pydantic v2, SQLAlchemy/Alembic/PostgreSQL, Jinja/admin HTTP patterns, PyInstaller, WiX 4, PowerShell 5.1.

**Spec:** `docs/superpowers/specs/2026-09-19-universal-windows-enrollment-installer-design.md`

## Global Constraints

- Do not modify `web_ovpn` or Helpdesk.
- Campaign policy is the sole AUTO/MANUAL and installer-release authority; client campaign IDs are forbidden.
- Do not create a global enrollment-mode environment variable.
- No artifact, MSI property, file, registry value, argv, log, or environment may contain a campaign bearer, `ic_` claim, device token, request capability, password, or provisioning service credential.
- Preserve `/agent/v1/enroll`, `collect_device_fingerprint()`, `WindowsProvisioner.provision_from_stdin()`, and the existing agent MSI/service paths.
- Claims are one-time, 15 minutes or less, hardware-bound, installation-bound, and bound to the frozen selected campaign.
- Request TTL is 24 hours; Setup polling is five seconds for at most 30 minutes.
- All admin mutations require existing administrator authentication, CSRF validation, transactional audit, and redacted details.
- One universal artifact is valid for both interactive and `/quiet` installation; no fleet production rollout.

## Review Focus

- A spoofed `X-Forwarded-For` must not enter an allowed campaign CIDR; trusted proxy address handling owns a route test.
- An ambiguous campaign set must persist review without choosing a newer or higher-use campaign; selection service owns a deterministic-order test.
- A campaign invalidated after selection must deny/expire instead of reselecting; approval service owns this test.
- A dropped response after claim issuance must be retriable without plaintext claim persistence or a second device; delivery service owns this test.
- A valid existing Device UUID must be preserved when Setup reruns or repairs a service; installer-state classifier owns this test.

---

### Task 1: Strict campaign policy and public contracts

**Files:**
- Modify: `endpoint_contracts/enrollment.py`
- Modify: `endpoint_contracts/__init__.py`
- Modify: `endpoint_server/enrollment/campaigns.py`
- Test: `tests/contracts/test_enrollment_request_contracts.py`
- Test: `tests/server/test_enrollment_campaigns.py`

**Interfaces:**
- Produces: `WindowsEnrollmentPolicyV1`, `PreEnrollmentRequestCreateV1`, `PreEnrollmentRequestStatusV1`, and `parse_windows_enrollment_policy(policy) -> WindowsEnrollmentPolicyV1 | None`.
- Consumes: existing normalized campaign CIDR/platform/quota rules.

- [ ] Write contract tests accepting `{"policy_id":"windows-office-v1","enrollment_mode":"auto","allowed_installer_releases":["1.0.0"]}` and rejecting missing mode, duplicate release, non-Windows release policy, oversized inventory evidence, and a client `campaign_id` field.
- [ ] Run `pytest tests/contracts/test_enrollment_request_contracts.py -v`; expect collection failure because public request models do not exist.
- [ ] Add strict Pydantic models: fixed schema versions, `windows` platform only, 43-character opaque capability, bounded inventory fields, and status-only response with no claim field by default. Add the policy parser and call it during campaign creation/update validation.
- [ ] Run the focused contracts and campaign tests; expect green.
- [ ] Commit `feat(enrollment): define Windows request policy contracts`.

### Task 2: Request persistence and migration

**Files:**
- Modify: `endpoint_server/db/models/enrollment.py`
- Modify: `endpoint_server/db/models/__init__.py`
- Create: `endpoint_server/db/migrations/versions/0020_enrollment_requests.py`
- Test: `tests/server/test_enrollment_request_models.py`

**Interfaces:**
- Consumes: Task 1 contracts and existing `EnrollmentCampaign`, `EnrollmentClaim`, `Device` ownership tables.
- Produces: `EnrollmentRequest` with digest-only bindings and `EnrollmentClaim.enrollment_request_id` unique relation.

- [ ] Write tests proving the model persists selected campaign, HMAC digests rather than raw capability/fingerprint/installation ID, status/reason/decision fields, indexes for active expiry and unique request-to-claim linkage.
- [ ] Run `pytest tests/server/test_enrollment_request_models.py -v`; expect import/model failure.
- [ ] Add the model and an Alembic revision that creates `enrollment_requests`, foreign keys, bounded textual columns, status/check indexes, and nullable unique claim linkage without rewriting existing credentials.
- [ ] Run focused tests plus `pytest tests/server/test_migrations.py -v`; expect green.
- [ ] Commit `feat(enrollment): persist pre-enrollment requests`.

### Task 3: Selection, transition, conflict, and audit service

**Files:**
- Create: `endpoint_server/enrollment/requests.py`
- Modify: `endpoint_server/enrollment/campaigns.py`
- Test: `tests/server/test_enrollment_request_service.py`
- Test: `tests/server/test_enrollment_postgresql.py`

**Interfaces:**
- Consumes: Task 1 policy parser, Task 2 persistence, `campaign_request_matches`, `issue_install_claim`, and `append_audit_event`.
- Produces: `create_or_resume_request`, `approve_request`, `deny_request`, `issue_request_claim`, and `mark_request_device_registered`.

- [ ] Write failing service tests for zero/one/multiple matching campaigns, AUTO, MANUAL, duplicate active fingerprint, invalidation after selection, request TTL, quota race, and audit evidence redaction.
- [ ] Run `pytest tests/server/test_enrollment_request_service.py -v`; expect missing service failure.
- [ ] Implement transactional `SELECT FOR UPDATE` selection and explicit transition table. Persist `selected_campaign_id` only for one candidate; enforce review reasons and revalidate that one campaign before approval/claim issuance.
- [ ] Add PostgreSQL concurrent tests proving one active request/claim can win and no second Device is created.
- [ ] Run focused service/PostgreSQL tests; expect green.
- [ ] Commit `feat(enrollment): add request selection state machine`.

### Task 4: Capability-protected public routes and claim delivery

**Files:**
- Create: `endpoint_server/enrollment/request_routes.py`
- Modify: `endpoint_server/main.py`
- Modify: `endpoint_server/enrollment/agent_routes.py`
- Modify: `endpoint_server/enrollment/delivery.py`
- Test: `tests/server/test_enrollment_request_api.py`
- Test: `tests/server/test_agent_enrollment_api.py`

**Interfaces:**
- Consumes: Task 3 services and existing encrypted enrollment delivery envelope.
- Produces: `POST /api/v1/enrollment/requests`, capability-protected status/claim handoff, and request lifecycle updates from the existing agent enrollment route.

- [ ] Write API tests for untrusted source rejection, capability mismatch, bounded polling, AUTO claim handoff, MANUAL approval completion, denial, retry after a dropped handoff, replayed claim denial, and no secret in response error/audit representation.
- [ ] Run `pytest tests/server/test_enrollment_request_api.py -v`; expect router missing.
- [ ] Implement routes with source address from the trusted application request context, per-source/installation/fingerprint rate limits, HMAC capability comparison, encrypted claim-delivery retry envelope, and transaction-safe request updates.
- [ ] Update `/agent/v1/enroll` to link consumed request claims to `DEVICE_REGISTERED` without changing its credential ownership or direct campaign compatibility.
- [ ] Run focused API/agent tests; expect green.
- [ ] Commit `feat(enrollment): expose approved request handoff`.

### Task 5: Administrator campaign and review controls

**Files:**
- Modify: `endpoint_server/enrollment/admin_routes.py`
- Create: `endpoint_server/enrollment/admin_request_routes.py`
- Modify: `endpoint_server/main.py`
- Modify: existing admin templates/static route files discovered in this task
- Test: `tests/server/test_enrollment_admin_api.py`
- Create: `tests/server/test_enrollment_request_admin_api.py`

**Interfaces:**
- Consumes: Task 1 campaign policy and Task 3 approve/deny services.
- Produces: campaign policy editing/projection plus administrator queue list, approve, and deny operations.

- [ ] Write tests for admin-only policy editing, CSRF rejection, mode/release validation, queue field redaction, approve from manual/review only, deny idempotence, and audits naming the administrator.
- [ ] Run `pytest tests/server/test_enrollment_request_admin_api.py -v`; expect missing routes.
- [ ] Add admin endpoints/forms following existing session/CSRF patterns, campaign summary, queue view, and POST actions; never include raw claim or credential data in view models.
- [ ] Run both enrollment admin suites; expect green.
- [ ] Commit `feat(enrollment): add campaign approval controls`.

### Task 6: Completion observation API

**Files:**
- Create: `endpoint_server/enrollment/verification_routes.py`
- Modify: `endpoint_server/main.py`
- Modify: `endpoint_server/enrollment/requests.py`
- Test: `tests/server/test_enrollment_verification_api.py`

**Interfaces:**
- Consumes: Task 3 request/device link and existing device presence/context projections.
- Produces: capability-protected bounded completion status reporting WSS and baseline/inventory readiness.

- [ ] Write tests that distinguish service/start failure from missing fresh WSS presence, baseline timeout, optional inventory absence, and verify that a completed request emits one redacted audit event.
- [ ] Run `pytest tests/server/test_enrollment_verification_api.py -v`; expect missing route.
- [ ] Implement read-only Device UUID completion checks and `WAITING_WSS -> COMPLETED` transition with a transaction-safe `installer_wss_verified` audit.
- [ ] Run focused verification and gateway presence tests; expect green.
- [ ] Commit `feat(enrollment): verify installer completion server-side`.

### Task 7: Testable universal Setup core

**Files:**
- Create: `pc_agent/platform/windows/setup_core.py`
- Create: `pc_agent/platform/windows/setup_entry.py`
- Test: `pc_agent/tests/windows/test_setup_core.py`
- Modify: `pc_agent/platform/windows/provision_entry.py` only if an existing public stdin helper must be exposed

**Interfaces:**
- Consumes: canonical `collect_device_fingerprint()`, existing provisioner stdin entry, MSI/service paths, and Task 4/6 APIs.
- Produces: `SetupExit`, `InstallationState`, `EnrollmentApi`, `UniversalSetup.run(quiet: bool) -> SetupExit`.

- [ ] Write failing tests for clean install AUTO, manual timeout, review/denied mapping, valid rerun preserving Device UUID, repairable missing service, conflicted credential state, claim passed solely to a subprocess stdin stream, and log redaction.
- [ ] Run `pytest pc_agent/tests/windows/test_setup_core.py -v`; expect missing module.
- [ ] Implement dependency-injected orchestration: local state classification, MSI install invocation, in-memory request capability, five-second bounded polling, direct claim stdin piping, service start, and server completion verification. Log only permitted fields.
- [ ] Run focused setup tests; expect green.
- [ ] Commit `feat(windows): add universal setup orchestrator`.

### Task 8: Bootstrapper build, release metadata, signing hook, and static scan

**Files:**
- Create: `pc_agent/pyinstaller_endpoint_setup.spec`
- Create: `packaging/windows/build-setup.ps1`
- Create: `packaging/windows/verify_setup_artifact.py`
- Modify: `packaging/windows/README.md`
- Test: `tests/packaging/test_windows_setup_contract.py`

**Interfaces:**
- Consumes: Task 7 entry executable and existing `build-msi.ps1` output/release manifest.
- Produces: `EndpointAgentSetup.exe`, `EndpointAgentSetup-<version>.release.json`, optional Authenticode signing invocation, and secret scan result.

- [ ] Write packaging tests proving one x64 Setup artifact, MSI handoff, `/quiet` contract, manifest fields, prohibited secret marker rejection, and unsigned/signing-status reporting without a certificate.
- [ ] Run `pytest tests/packaging/test_windows_setup_contract.py -v`; expect missing builder/validator.
- [ ] Add PyInstaller bootstrap spec, PowerShell 5.1-compatible builder that invokes the existing MSI builder, writes SHA-256/source/version/agent/signature metadata, and runs static scanning. Do not accept any credential parameter.
- [ ] Run focused packaging tests; expect green.
- [ ] Commit `build(windows): package universal enrollment setup`.

### Task 9: Runbook, full verification, and test artifact

**Files:**
- Create: `docs/runbooks/WINDOWS_UNIVERSAL_ENROLLMENT.md`
- Modify: `docs/agent/WINDOWS_RUNTIME_DESIGN.md`
- Test: relevant docs/packaging contract tests

**Interfaces:**
- Consumes: Tasks 1-8.
- Produces: production-safe AUTO/MANUAL runbook and a locally generated test-only artifact with release metadata.

- [ ] Write documentation tests or assertions for AUTO/MANUAL instructions, `/quiet`, exit codes, no-session/no-secret boundary, and explicit production prerequisites/no-fleet-rollout statement.
- [ ] Run the documentation/packaging contract target; expect missing documentation assertions where applicable.
- [ ] Document campaign setup, pending approval, denial/retry behavior, artifact verification, VM acceptance matrix, rollback boundaries, and signing prerequisite. Build the artifact only after all source/contract tests are green.
- [ ] Run `pytest -q`, `python tools/contracts/generate_contract_artifacts.py --check` (or repository equivalent), `git diff --check`, and the Windows setup builder/secret scan; record actual outcomes.
- [ ] Commit `docs(enrollment): document universal Windows setup`.

## Self-review

Coverage: Tasks 1-6 implement policy, persistence, server APIs, audit, UI, and completion; Tasks 7-8 implement and package the single installer; Task 9 covers runbook and end-to-end build verification. The acceptance-only Windows VM, signing certificate, trusted-proxy deployment, and fleet rollout are explicit external prerequisites, not claims made by unit tests. No plan task selects a campaign client-side, persists local secrets, or modifies excluded repositories. Interface names are defined by the producing task before use. No placeholders or deferred implementation markers remain.
