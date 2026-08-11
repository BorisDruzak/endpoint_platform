# Ansible ALT Agent Rollout Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enable an external Ansible controller to create a narrow Gateway campaign, issue host claims, install the ALT RPM, and revoke the campaign without an admin session.

**Architecture:** Gateway gets service-authenticated campaign create/revoke routes and stores the owning service client. The portable Ansible role calls only those HTTPS APIs, creates one single-use campaign per target, uses `no_log` for claims, and supplies the existing RPM first-boot contract. An administrator creates the limited token once and places it in the external controller's Vault.

**Tech Stack:** FastAPI, Pydantic, SQLAlchemy/Alembic/PostgreSQL, Ansible core, ALT Linux RPM/systemd.

## Global Constraints

- The deployment token has exactly `provisioning.campaigns.create`, `provisioning.campaigns.revoke`, and `provisioning.install-claims.issue`.
- Never log or persist a raw service token, campaign bearer, or install claim outside the Ansible Vault input and protected target file.
- Use `https://endpoint.sosnadmin.local` with certificate validation; never substitute an IP address or disable TLS verification.
- A service may revoke only campaigns it owns. A service-owned campaign may issue claims only to that same service client. Legacy/admin campaigns remain ownerless and retain the existing claim-issuance compatibility.
- Do not apply production migrations until deployed code and the current Alembic revision are verified on the server.

---

### Task 1: Persist service campaign ownership

**Files:**
- Modify: `endpoint_server/db/models/enrollment.py`
- Create: `endpoint_server/db/migrations/versions/0011_service_campaign_ownership.py`
- Test: `tests/server/test_enrollment_postgresql.py`

**Interfaces:** `EnrollmentCampaign.owner_service_client_id: UUID | None`; migration adds a nullable `service_clients.id` foreign key with `ON DELETE SET NULL` and an index.

- [ ] **Step 1: Write the failing test**

```python
def test_enrollment_campaign_tracks_nullable_service_owner() -> None:
    campaign = EnrollmentCampaign(owner_service_client_id=uuid4(), ...)
    assert campaign.owner_service_client_id is not None
```

The test catches missing ownership state, which would permit cross-service cleanup.

- [ ] **Step 2: Verify RED**

Run: `python -m pytest tests/server/test_enrollment_postgresql.py -k service_owner -v`

Expected: FAIL because the mapped field is absent.

- [ ] **Step 3: Implement the model and migration**

```python
owner_service_client_id: Mapped[UUID | None] = mapped_column(
    ForeignKey("service_clients.id", ondelete="SET NULL"), nullable=True, index=True
)
```

Use `op.add_column`, `op.create_foreign_key`, and `op.create_index`; downgrade drops them.

- [ ] **Step 4: Verify GREEN and commit**

Run: `python -m pytest tests/server/test_enrollment_postgresql.py -k service_owner -v`

Expected: PASS. Commit the model, migration, and test with `feat: track service campaign ownership`.

### Task 2: Add the scoped campaign API

**Files:**
- Modify: `endpoint_server/auth/scopes.py`
- Modify: `endpoint_server/enrollment/provisioning_routes.py`
- Modify: `endpoint_server/enrollment/campaigns.py`
- Test: `tests/server/test_provisioning_api.py`

**Interfaces:** Add `PROVISIONING_CAMPAIGNS_CREATE_SCOPE` and `PROVISIONING_CAMPAIGNS_REVOKE_SCOPE`. `POST /api/v1/provisioning/campaigns` returns UUID and non-secret metadata; `POST /api/v1/provisioning/campaigns/{campaign_id}/revoke` returns 204 only for the owner and otherwise the existing non-oracular 404.

- [ ] **Step 1: Write failing route tests**

```python
async def test_service_creates_owned_campaign_without_bearer() -> None:
    response = await client.post("/api/v1/provisioning/campaigns", json=payload)
    assert response.status_code == 201
    assert "token" not in response.json()
    assert campaign.owner_service_client_id == principal.client.id

async def test_other_service_cannot_revoke_owned_campaign() -> None:
    response = await client.post(f"/api/v1/provisioning/campaigns/{campaign.id}/revoke")
    assert response.status_code == 404
```

The tests catch bearer disclosure and cross-client revocation.

- [ ] **Step 2: Verify RED**

Run: `python -m pytest tests/server/test_provisioning_api.py -k service_campaign -v`

Expected: FAIL because the routes/scopes do not exist.

- [ ] **Step 3: Implement strict service handlers**

Use `ConfigDict(extra="forbid")`, `require_service_scope`, `issue_campaign`, and `append_audit_event`. Set owner only in this service route, preserve ownerless admin behavior, and never return `IssuedCampaign.token`. In the existing claim route, deny a claim when a non-null campaign owner differs from the authenticated service client.

- [ ] **Step 4: Verify GREEN and commit**

Run: `python -m pytest tests/server/test_provisioning_api.py -k service_campaign -v`

Expected: PASS. Commit with `feat: add scoped provisioning campaigns`.

### Task 3: Package a portable Ansible role

**Files:**
- Create: `deploy/ansible/roles/endpoint_agent_alt/defaults/main.yml`
- Create: `deploy/ansible/roles/endpoint_agent_alt/tasks/main.yml`
- Create: `deploy/ansible/roles/endpoint_agent_alt/README.md`
- Create: `deploy/ansible/playbooks/endpoint_agent_alt_pilot.yml`
- Create: `deploy/ansible/group_vars/endpoint_agent_alt_pilot.example.yml`
- Test: `tests/deploy/test_ansible_alt_agent_rollout.py`

**Interfaces:** Controller input is `vault_endpoint_provisioning_token`; host inputs are RPM and CA sources. Campaign variables include CIDRs and lifetime. The role creates one `max_uses: 1` campaign per target, uses controller-delegated HTTPS calls, exact root-only modes, enrollment wait, and an `always` revoke block.

- [ ] **Step 1: Write failing role tests**

```python
def test_secret_bearing_tasks_are_no_log() -> None:
    assert every_secret_bearing_task_has_no_log(load_tasks())

def test_campaign_revoke_is_in_an_always_block() -> None:
    assert role_has_always_revoke_block(load_tasks())
```

The tests catch token/claim leakage and cleanup omission after a failed install.

- [ ] **Step 2: Verify RED**

Run: `python -m pytest tests/deploy/test_ansible_alt_agent_rollout.py -v`

Expected: FAIL because the role files are missing.

- [ ] **Step 3: Implement role and pilot playbook**

Add DNS preflight, controller-side campaign creation, host fingerprint acquisition, claim issuance, secure CA/RPM/bootstrap transfer, RPM installation, enrollment wait, and `always` revocation. Keep `validate_certs: true` and forbid endpoint IP configuration.

- [ ] **Step 4: Verify GREEN and commit**

Run: `python -m pytest tests/deploy/test_ansible_alt_agent_rollout.py -v`

Expected: PASS. Commit with `feat: add Ansible ALT agent rollout role`.

### Task 4: Document and validate the handoff

**Files:**
- Modify: `docs/runbooks/ALT_AGENT_INSTALL.md`
- Modify: `deploy/agent/alt/rpm/README.md`
- Test: `tests/server/test_provisioning_api.py`
- Test: `tests/deploy/test_ansible_alt_agent_rollout.py`

**Interfaces:** Documentation names the single Vault variable, campaign constraints, external-controller invocation, and migration deployment gate.

- [ ] **Step 1: Write the failing Vault documentation test**

```python
def test_role_documents_the_only_vault_variable_without_claim_storage() -> None:
    assert "vault_endpoint_provisioning_token" in role_readme
    assert "endpoint_install_claim:" not in example_vars
```

This catches instructions that persist a one-time claim.

- [ ] **Step 2: Verify RED**

Run: `python -m pytest tests/deploy/test_ansible_alt_agent_rollout.py -k vault -v`

Expected: FAIL before the role documentation exists.

- [ ] **Step 3: Implement docs and run verification**

Run: `python -m pytest tests/server/test_provisioning_api.py tests/server/test_enrollment_campaigns.py tests/deploy/test_ansible_alt_agent_rollout.py tests/deploy/test_alt_agent_rpm.py -v --tb=short`

Expected: PASS. Commit with `docs: describe Ansible ALT rollout`.

### Task 5: Deployment gate and clean-host verification

**Files:** No repository changes after Tasks 1-4.

**Interfaces:** Production must be at Alembic revision `0011_service_campaign_ownership` before the external controller is used. The only raw token destination is that controller's Vault.

- [ ] **Step 1: Deploy reviewed code and inspect current production revision**

Run on `endpoint-platform-server` after deployment: `cd /opt/endpoint-platform/current && sudo -n bash -c 'set -a; . /etc/endpoint-platform/endpoint-platform.env; set +a; venv/bin/python -m alembic current'`.

Expected: existing revision is shown; do not upgrade before code deployment.

- [ ] **Step 2: Apply the reviewed migration and verify revision**

Use the established server-side migration procedure and repeat `alembic current`.

Expected: `0011_service_campaign_ownership` is current.

- [ ] **Step 3: Bootstrap the external deployment credential**

Create `ansible-alt-deployer` with exactly the three global scopes and place only its raw token in the external Ansible Vault. Record only its public credential identifier.

- [ ] **Step 4: Clean and run the external role on `192.168.101.56`**

Remove only the endpoint-agent RPM, its units, and `/opt/endpoint-agent`, `/etc/endpoint-agent`, `/var/lib/endpoint-agent`, `/var/log/endpoint-agent`; preserve host networking and DNS.

- [ ] **Step 5: Verify end-to-end state**

Require active agent/update/finalizer units, durable credential, removed handoff, Gateway-ready mode, consumed claim linked to device, enrollment audit event, and a revoked rollout campaign.
