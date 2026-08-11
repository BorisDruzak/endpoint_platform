# ALT Ansible RPM 3.2.14 Rollout Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the obsolete ALT Endpoint Ansible role with a two-phase RPM 3.2.14 first-install and Gateway enrollment workflow.

**Architecture:** Pre-stage the reviewed RPM while its service remains inactive, use the RPM-shipped frozen-core fingerprint helper, then create a single-use campaign and claim immediately before first service start.  The role uses a single `block`/`always` transaction for secret-safe claim delivery and campaign revocation.

**Tech Stack:** Ansible built-in modules, RPM/systemd on ALT Linux, Gateway HTTPS API, PyYAML/pytest contract tests.

## Global Constraints

- Gateway URL is exactly `https://endpoint.sosnadmin.local`; certificate verification remains enabled and no proxy, IP URL, HTTP fallback, or TLS bypass is allowed.
- Accept only `vault_endpoint_provisioning_token`; never create a service credential or store claims, campaign bearer material, or device credentials in Vault, inventory, Git, or logs.
- Each target gets one campaign with `max_uses: 1`; always revoke it when it was created.
- Put the claim only at `/etc/credstore/endpoint-enrollment-claim` as `root:root` `0600`.
- Treat a partial or already-enrolled host as a failure, not a re-enrollment.
- Do not contact production Gateway or target hosts while implementing tests.

---

### Task 1: Define the two-phase role contract in tests

**Files:**
- Modify: `tests/deploy/test_ansible_alt_agent_rollout.py`
- Modify: `deploy/ansible/roles/endpoint_agent_alt/tasks/main.yml`

**Interfaces:**
- Consumes: role YAML loaded through `_tasks()` and flattened through `_walk_tasks()`.
- Produces: contract tests requiring a pre-stage RPM task, the official helper task, root-only credstore claim, no `endpoint-agent-finalize` dependency, and secret `always` cleanup.

- [ ] **Step 1: Write the failing test**

```python
def test_role_pre_stages_rpm_before_issuing_claim_and_uses_official_helper() -> None:
    rendered = TASKS_PATH.read_text(encoding="utf-8")
    assert rendered.index("Install reviewed Endpoint Agent RPM before enrollment") < rendered.index("Create per-host rollout campaign")
    assert "/usr/lib/endpoint-agent/endpoint-agent-fingerprint" in rendered
    assert "/etc/credstore/endpoint-enrollment-claim" in rendered
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/deploy/test_ansible_alt_agent_rollout.py -q`

Expected: FAIL because the old role extracts the obsolete release bundle and writes `/etc/endpoint-agent/bootstrap/provisioning-claim`.

- [ ] **Step 3: Write minimal implementation**

Replace the role task file with the two-phase task order.  Use the package helper as `endpoint-agent`, create a single-use campaign after fingerprint collection, write the fixed source claim path, and remove the old finalizer condition.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/deploy/test_ansible_alt_agent_rollout.py -q`

Expected: PASS.

- [ ] **Step 5: Commit**

Do not commit in this task: the user requested local-only changes.

### Task 2: Add non-secret configuration and role defaults

**Files:**
- Modify: `deploy/ansible/roles/endpoint_agent_alt/defaults/main.yml`
- Create: `deploy/ansible/roles/endpoint_agent_alt/templates/config.yaml.j2`
- Modify: `deploy/ansible/group_vars/endpoint_agent_alt_pilot.example.yml`
- Test: `tests/deploy/test_ansible_alt_agent_rollout.py`

**Interfaces:**
- Consumes: `endpoint_agent_rpm_source`, `endpoint_agent_rpm_sha256`, external CA paths, CIDRs, and `vault_endpoint_provisioning_token`.
- Produces: `endpoint_agent_installation_id`, campaign policy metadata, and an exact `config.yaml` matching the canonical RPM runtime paths.

- [ ] **Step 1: Write the failing test**

```python
def test_role_renders_fixed_https_configuration_without_a_claim() -> None:
    template = (ROLE_ROOT / "templates" / "config.yaml.j2").read_text(encoding="utf-8")
    assert "https://endpoint.sosnadmin.local" in template
    assert "/etc/endpoint-agent/ca.crt" in template
    assert "/var/lib/endpoint-agent/device-credential" in template
    assert "claim" not in template.lower()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/deploy/test_ansible_alt_agent_rollout.py -q`

Expected: FAIL because the canonical config template does not exist.

- [ ] **Step 3: Write minimal implementation**

Add only non-secret defaults, require the RPM SHA-256, and render the fixed HTTPS Gateway configuration with no credential or claim value.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/deploy/test_ansible_alt_agent_rollout.py -q`

Expected: PASS.

- [ ] **Step 5: Commit**

Do not commit in this task: the user requested local-only changes.

### Task 3: Document use from an external controller

**Files:**
- Modify: `deploy/ansible/roles/endpoint_agent_alt/README.md`
- Modify: `docs/superpowers/specs/2026-08-11-alt-ansible-rpm-3.2.14-design.md`
- Test: `tests/deploy/test_ansible_alt_agent_rollout.py`

**Interfaces:**
- Consumes: final role variables and fixed bootstrap paths.
- Produces: a controller runbook that documents pre-stage RPM, official fingerprint helper, Vault-only service token, and no live credentials in examples.

- [ ] **Step 1: Write the failing test**

```python
def test_readme_documents_pre_stage_before_claim() -> None:
    readme = README_PATH.read_text(encoding="utf-8")
    assert "before its first service start" in readme
    assert "endpoint-agent-fingerprint" in readme
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/deploy/test_ansible_alt_agent_rollout.py -q`

Expected: FAIL because the old README says a claim is obtained immediately before RPM installation.

- [ ] **Step 3: Write minimal implementation**

Replace the old order with the two-phase contract, list the exact source claim path and external controller inputs, and retain the Vault-only token warning.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/deploy/test_ansible_alt_agent_rollout.py -q`

Expected: PASS.

- [ ] **Step 5: Commit**

Do not commit in this task: the user requested local-only changes.

### Task 4: Verify the complete local change

**Files:**
- Verify: `tests/deploy/test_ansible_alt_agent_rollout.py`
- Verify: `tests/packaging/test_alt_rpm_contract.py`
- Verify: `pc_agent/tests/runtime/test_headless_lifecycle.py`

- [ ] **Step 1: Run focused role tests**

Run: `python -m pytest tests/deploy/test_ansible_alt_agent_rollout.py -q`

Expected: PASS with all role contract tests green.

- [ ] **Step 2: Run package and runtime regression tests**

Run: `python -m pytest tests/packaging/test_alt_rpm_contract.py pc_agent/tests/runtime/test_headless_lifecycle.py -q`

Expected: PASS with the existing expected skip only.

- [ ] **Step 3: Check local diff**

Run: `git diff --check && git status --short`

Expected: no whitespace errors; only the role, test, and documentation files listed above are modified or added.
